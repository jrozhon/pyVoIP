import audioop
import io
import random
import time
import uuid
import warnings
from enum import Enum
from threading import Lock, Timer
from typing import Any, Callable, Optional

from icecream import ic
from rich import print

import pyvoip
from pyvoip.lib.credentials import Credentials
from pyvoip.proto import RTP, SIP
from pyvoip.sock.transport import TransportMode

__all__ = [
    "CallState",
    "InvalidRangeError",
    "InvalidStateError",
    "NoPortsAvailableError",
    "VoIPCall",
    "VoIPPhone",
]

debug = pyvoip.debug
TRACE = pyvoip.TRACE


class InvalidRangeError(Exception):
    pass


class InvalidStateError(Exception):
    pass


class NoPortsAvailableError(Exception):
    pass


class CallState(str, Enum):
    DIALING = "DIALING"
    RINGING = "RINGING"
    ANSWERED = "ANSWERED"
    ENDED = "ENDED"


class PhoneStatus(str, Enum):
    INACTIVE = "INACTIVE"  # Phone was instantiated but not started, or was stopped.
    CONNECTING = "CONNECTING"  # Phone tries to bind to the network.
    CONNECTED = "CONNECTED"  # Phone is bound to the network.
    REGISTERING = "REGISTERING"  # Phone is trying to register with the SIP server.
    REGISTERED = "REGISTERED"  # Phone is registered with the SIP server.
    DEREGISTERING = (
        "DEREGISTERING"  # Phone is trying to deregister with the SIP server.
    )
    FAILED = (
        "FAILED"  # Phone failed to bind to the network or register with the SIP server.
    )


class VoIPCall:
    def __init__(
        self,
        phone: "VoIPPhone",
        callstate: CallState,
        request: SIP.SIPMessage,
        session_id: int,
        bind_ip: str,
        ms: Optional[dict[int, RTP.PayloadType]] = None,
        sendmode="sendonly",
    ):
        if TRACE:
            ic()
        self._state = None
        self.state = callstate
        self.phone = phone
        self.sip = self.phone.sip
        self.request = request
        self.call_id = request.headers["Call-ID"]
        self.session_id = str(session_id)
        self.bind_ip = bind_ip
        self.rtp_port_high = self.phone.rtp_port_high
        self.rtp_port_low = self.phone.rtp_port_low
        self.sendmode = sendmode

        self.dtmfLock = Lock()
        self.dtmf = io.StringIO()

        self.RTPClients: list[RTP.RTPClient] = []

        self.connections = 0
        self.audioPorts = 0
        self.videoPorts = 0

        # Type checker being weird with this variable.
        # Appears to be because this variable is used differently depending
        # on whether we received or originated the call.
        # Will need to refactor the code later to properly type this.
        self.assignedPorts: Any = {}

        if callstate == CallState.RINGING:
            audio = []
            video = []
            for x in self.request.body["c"]:
                self.connections += x["address_count"]
            for x in self.request.body["m"]:
                if x["type"] == "audio":
                    self.audioPorts += x["port_count"]
                    audio.append(x)
                elif x["type"] == "video":
                    self.videoPorts += x["port_count"]
                    video.append(x)
                else:
                    warnings.warn(
                        f"Unknown media description: {x['type']}", stacklevel=2
                    )

            # Ports Adjusted is used in case of multiple m tags.
            if len(audio) > 0:
                audioPortsAdj = self.audioPorts / len(audio)
            else:
                audioPortsAdj = 0
            if len(video) > 0:
                videoPortsAdj = self.videoPorts / len(video)
            else:
                videoPortsAdj = 0

            if not (
                (audioPortsAdj == self.connections or self.audioPorts == 0)
                and (videoPortsAdj == self.connections or self.videoPorts == 0)
            ):
                # TODO: Throw error to PBX in this case
                warnings.warn("Unable to assign ports for RTP.", stacklevel=2)
                return

            for i in request.body["m"]:
                assoc = {}
                e = False
                for x in i["methods"]:
                    try:
                        p = RTP.PayloadType(int(x))
                        assoc[int(x)] = p
                    except ValueError:
                        try:
                            p = RTP.PayloadType(i["attributes"][x]["rtpmap"]["name"])
                            assoc[int(x)] = p
                        except ValueError:
                            # Sometimes rtpmap raise a KeyError because fmtp
                            # is set instate
                            pt = i["attributes"][x]["rtpmap"]["name"]
                            warnings.warn(
                                f"RTP Payload type {pt} not found.",
                                stacklevel=20,
                            )
                            # Resets the warning filter so this warning will
                            # come up again if it happens.  However, this
                            # also resets all other warnings.
                            warnings.simplefilter("default")
                            p = RTP.PayloadType("UNKNOWN")
                            assoc[int(x)] = p
                        except KeyError:
                            # fix issue 42
                            # When rtpmap is not found, also set the found
                            # element to UNKNOWN
                            warnings.warn(f"RTP KeyError {x} not found.", stacklevel=20)
                            p = RTP.PayloadType("UNKNOWN")
                            assoc[int(x)] = p

                if e:
                    raise RTP.RTPParseError(f"RTP Payload type {pt} not found.")

                # Make sure codecs are compatible.
                codecs = {}
                for m in assoc:
                    if assoc[m] in pyvoip.RTPCompatibleCodecs:
                        codecs[m] = assoc[m]
                # TODO: If no codecs are compatible then send error to PBX.

                port = self.phone.request_port()
                self.create_rtp_clients(codecs, self.bind_ip, port, request, i["port"])
        elif callstate == CallState.DIALING:
            if ms is None:
                raise RuntimeError(
                    "Media assignments are required when " + "initiating a call"
                )
            self.ms = ms
            for m in self.ms:
                self.port = m
                self.assignedPorts[m] = self.ms[m]

    @property
    def state(self) -> CallState:
        return self._state

    @state.setter
    def state(self, value: CallState) -> None:
        if TRACE:
            ic()
        self._state = value
        if TRACE:
            print(
                f"[bright_black]Call state changed to: [/bright_black][red]{value}[/red]"
            )

    def create_rtp_clients(
        self,
        codecs: dict[int, RTP.PayloadType],
        ip: str,
        port: int,
        request: SIP.SIPMessage,
        baseport: int,
    ) -> None:
        if TRACE:
            ic()
        for ii in range(len(request.body["c"])):
            # TODO: Check IPv4/IPv6
            c = RTP.RTPClient(
                codecs,
                ip,
                port,
                request.body["c"][ii]["address"],
                baseport + ii,
                self.sendmode,
                dtmf=self.dtmf_callback,
            )
            self.RTPClients.append(c)

    def __del__(self):
        if hasattr(self, "phone"):
            self.phone.release_ports(call=self)

    def dtmf_callback(self, code: str) -> None:
        if TRACE:
            ic()
        self.dtmfLock.acquire()
        bufferloc = self.dtmf.tell()
        self.dtmf.seek(0, 2)
        self.dtmf.write(code)
        self.dtmf.seek(bufferloc, 0)
        self.dtmfLock.release()

    def get_dtmf(self, length=1) -> str:
        if TRACE:
            ic()
        self.dtmfLock.acquire()
        packet = self.dtmf.read(length)
        self.dtmfLock.release()
        return packet

    def send_dtmf(self, code: str) -> None:
        if TRACE:
            ic()
        for x in self.RTPClients:
            # DTMF is actually a hexademical number
            x.outgoing_dtmf.append(code)

    def gen_ms(self) -> dict[int, dict[int, RTP.PayloadType]]:
        """
        Generate m SDP attribute for answering originally and
        for re-negotiations.
        """
        if TRACE:
            ic()
        # TODO: this seems "dangerous" if for some reason sip server handles 2
        # and more bindings it will cause duplicate RTP-Clients to spawn.
        m = {}
        for x in self.RTPClients:
            x.start()
            m[x.in_port] = x.assoc

        return m

    def renegotiate(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        m = self.gen_ms()
        message = self.sip.gen_answer(request, self.session_id, m, self.sendmode)
        self.sip.send_b(
            message,
            self.request.headers["Via"][0]["address"],
            self.request.headers["Via"][0]["port"],
        )
        for i in request.body["m"]:
            for ii, client in zip(range(len(request.body["c"])), self.RTPClients):
                client.out_ip = request.body["c"][ii]["address"]
                client.out_port = i["port"] + ii  # TODO: Check IPv4/IPv6

    def answer(self) -> None:
        if TRACE:
            ic()
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        m = self.gen_ms()
        message = self.sip.gen_answer(self.request, self.session_id, m, self.sendmode)
        self.sip.send_b(
            message,
            self.request.headers["Via"][0]["address"],
            self.request.headers["Via"][0]["port"],
        )
        self.state = CallState.ANSWERED

    def answered(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        if self.state != CallState.DIALING:
            return

        for i in request.body["m"]:
            assoc = {}
            e = False
            for x in i["methods"]:
                try:
                    p = RTP.PayloadType(int(x))
                    assoc[int(x)] = p
                except ValueError:
                    try:
                        p = RTP.PayloadType(i["attributes"][x]["rtpmap"]["name"])
                        assoc[int(x)] = p
                    except ValueError:
                        e = True

            if e:
                raise RTP.RTPParseError(f"RTP Payload type {p} not found.")

            self.create_rtp_clients(assoc, self.bind_ip, self.port, request, i["port"])

        for x in self.RTPClients:
            x.start()
        self.request.headers["Contact"] = request.headers["Contact"]
        self.request.headers["To"]["tag"] = request.headers["To"]["tag"]
        self.state = CallState.ANSWERED

    def not_found(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        if self.state != CallState.DIALING:
            debug(
                "TODO: 500 Error, received a not found response for a "
                + f"call not in the dailing state.  Call: {self.call_id}, "
                + f"Call State: {self.state}"
            )
            return

        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers["Call-ID"]]
        debug("Call not found and terminated")
        warnings.warn(
            f"The number '{request.headers['To']['number']}' "
            + "was not found.  Did you call the wrong number?  "
            + "CallState set to CallState.ENDED.",
            stacklevel=20,
        )
        # Resets the warning filter so this warning will
        # come up again if it happens.  However, this
        # also resets all other warnings.
        warnings.simplefilter("default")

    def unavailable(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        if self.state != CallState.DIALING:
            debug(
                "TODO: 500 Error, received an unavailable response for a "
                + f"call not in the dailing state.  Call: {self.call_id}, "
                + f"Call State: {self.state}"
            )
            return

        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers["Call-ID"]]
        debug("Call unavailable and terminated")
        warnings.warn(
            f"The number '{request.headers['To']['number']}' "
            + "was unavailable.  CallState set to CallState.ENDED.",
            stacklevel=20,
        )
        # Resets the warning filter so this warning will
        # come up again if it happens.  However, this
        # also resets all other warnings.
        warnings.simplefilter("default")

    def deny(self) -> None:
        if TRACE:
            ic()
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        message = self.sip.gen_response(
            self.request, status_code=486, status_message="Busy Here"
        )
        self.sip.send_b(
            message,
            self.request.headers["Via"][0]["address"],
            self.request.headers["Via"][0]["port"],
        )
        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers["Call-ID"]]

    def hangup(self) -> None:
        if TRACE:
            ic()
        if self.state != CallState.ANSWERED:
            raise InvalidStateError("Call is not answered")
        for x in self.RTPClients:
            x.stop()
        self.sip.bye(self.request)
        self.state = CallState.ENDED
        if self.request.headers["Call-ID"] in self.phone.calls:
            del self.phone.calls[self.request.headers["Call-ID"]]

    def on_bye(self) -> None:
        """
        Closes the RTP ports and sets the call state to CallState.ENDED.
        It is meant to be used by the UAS when it receives a BYE request.
        The response is then handled further in the flow of SIP client.
        Should not be called byt the user.

        Returns
        -------
        None
        """
        if TRACE:
            ic()
        if self.state == CallState.ANSWERED:
            for x in self.RTPClients:
                x.stop()
            self.state = CallState.ENDED
        if self.request.headers["Call-ID"] in self.phone.calls:
            del self.phone.calls[self.request.headers["Call-ID"]]

    def write_audio(self, data: bytes) -> None:
        """
        This method is used to write audio to the RTP clients.
        Audio must be in the format of a bytes object.
        Linear PCM 16-bit, 8kHz, mono is the required format.

        There is an addition to allow for sending DTMF codes,
        but it is a rather naive approach and should be handled
        separately.

        In case of DTMF, there are 4 key events with first
        having the Marker set to True (1) and the rest set to False (0).
        Timestamp is not incremented, but the sequence number is. Event
        duration is updated as well.

        Then, there are 3 key events with end of event set to True (1).
        First one, updates the timestamp and the Event duration. The
        remaining two are just repetitions.


        Parameters
        ----------
        data
            Bytes object of audio data

        dtmf
            Bytes object of DTMF codes. Actually just one key and the
            RTP client will handle the rest.

        Returns
        -------
        None
        """
        if TRACE:
            ic()
        for x in self.RTPClients:
            x.write(data)

    def read_audio(self, length=160, blocking=True) -> bytes:
        if TRACE:
            ic()
        if len(self.RTPClients) == 1:
            return self.RTPClients[0].read(length, blocking)
        data = []
        for x in self.RTPClients:
            data.append(x.read(length))
        # Mix audio from different sources before returning
        nd = audioop.add(data.pop(0), data.pop(0), 1)
        for d in data:
            nd = audioop.add(nd, d, 1)
        return nd


class VoIPPhone:
    def __init__(
        self,
        server: str,
        port: int,
        user: str,
        password: str,
        auth_user: str | None = None,
        realm: str | None = None,
        bind_ip="0.0.0.0",
        bind_port=5060,
        transport_mode=TransportMode.UDP,
        call_callback: Optional[Callable[["VoIPCall"], None]] = None,
        rtp_port_low=10000,
        rtp_port_high=20000,
    ):
        if TRACE:
            ic()
        if rtp_port_low > rtp_port_high:
            raise InvalidRangeError("'rtp_port_high' must be >= 'rtp_port_low'")

        self.uuid = uuid.uuid4()  # used to reference the phone in external systems
        self.rtp_port_low = rtp_port_low
        self.rtp_port_high = rtp_port_high
        # a flag telling that the phone is registered or not
        # unsure why this is needed, but it is in the original code
        self.NSD = False

        self.portsLock = Lock()
        self.assignedPorts: list[int] = []
        self.session_ids: list[int] = []

        self.server = server
        self.port = port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.user = user
        self.credentials = Credentials(
            user=user,
            auth_user=auth_user or user,
            password=password,
            realm=realm,
            server=server,
        )
        self.call_callback = call_callback
        self._status = None
        self.status = PhoneStatus.INACTIVE
        self.transport_mode = transport_mode

        # "recvonly", "sendrecv", "sendonly", "inactive"
        self.sendmode = "sendrecv"
        self.recvmode = "sendrecv"

        self.calls: dict[str, VoIPCall] = {}
        self.threads: list[Timer] = []
        # Allows you to find call ID based off thread.
        self.threadLookup: dict[Timer, str] = {}
        self.sip = SIP.SIPClient(
            server,
            port,
            user,
            self.credentials,
            bind_ip=self.bind_ip,
            bind_port=bind_port,
            call_callback=self.callback,  # this is just a reference to the callback method
            transport_mode=self.transport_mode,
        )

    @property
    def status(self) -> PhoneStatus:
        """
        Get phone status. A replacement for the original get_status method.

        Parameters
        ----------
        self : VoIPPhone

        Returns
        -------
        PhoneStatus
        """
        if TRACE:
            ic()
        return self._status

    @status.setter
    def status(self, value: PhoneStatus) -> None:
        """
        Set phone status. Allows for hooks that can be used for asynchronous monitoring
        of the phone's status.

        Parameters
        ----------
        self : VoIPPhone
        value
            The new status of the phone.

        Returns
        -------
        None
        """
        if TRACE:
            ic()
        self._status = value
        if TRACE:
            print(
                f"[bright_black]Phone status changed to: [/bright_black][red]{value}[/red]"
            )

    def to_dict(self) -> dict[str, Any]:
        if TRACE:
            ic()
        """
        A simple method to print user-friendly information about the phone.

        Returns
        -------
        dict[str, Any]
            A dictionary containing the phone's information.
        """
        return {
            "uuid": self.uuid,
            "pbx_ip": self.server,
            "pbx_port": self.port,
            "user": self.user,
            "auth_user": self.credentials.auth_user,
            "password": self.credentials.password,
            "bind_ip": self.bind_ip,
            "bind_port": self.bind_port,
            "transport_mode": self.transport_mode,
            "rtp_port_low": self.rtp_port_low,
            "rtp_port_high": self.rtp_port_high,
            "status": self.status,
            "calls": len(self.calls),
        }

    def callback(self, request: SIP.SIPMessage) -> Optional[str]:
        if TRACE:
            ic()
        """
        A mysterious method that returns or not

        [TODO:description]

        Parameters
        ----------
        request
            [TODO:description]

        Returns
        -------
        Optional[str]
            [TODO:description]
        """

        # debug("Callback: "+request.summary())
        if request.type == pyvoip.proto.SIP.SIPMessageType.REQUEST:
            # debug("This is a message")
            if request.method == "INVITE":
                self._callback_MSG_Invite(request)
            elif request.method == "BYE":
                self._callback_MSG_Bye(request)
            elif request.method == "OPTIONS":
                return self._callback_MSG_Options(request)
        else:
            if request.status == SIP.SIPStatus.OK:
                self._callback_RESP_OK(request)
            elif request.status == SIP.SIPStatus.NOT_FOUND:
                self._callback_RESP_NotFound(request)
            elif request.status == SIP.SIPStatus.SERVICE_UNAVAILABLE:
                self._callback_RESP_Unavailable(request)
        return None  # mypy needs this for some reason.

    def _callback_MSG_Invite(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        call_id = request.headers["Call-ID"]
        if call_id in self.calls:
            debug("Re-negotiation detected!")
            # TODO: this seems "dangerous" if for some reason sip server
            # handles 2 and more bindings it will cause duplicate RTP-Clients
            # to spawn.

            # CallState.Ringing seems important here to prevent multiple
            # answering and RTP-Client spawning. Find out when renegotiation
            # is relevant.
            if self.calls[call_id].state != CallState.RINGING:
                self.calls[call_id].renegotiate(request)
            return  # Raise Error
        if self.call_callback is None:
            message = self.sip.gen_response(
                request, status_code=486, status_message="Busy Here"
            )
            self.sip.send_b(
                message,
                request.headers["Via"][0]["address"],
                request.headers["Via"][0]["port"],
            )
        else:
            debug("New call!")
            sess_id = None
            while sess_id is None:
                proposed = random.randint(1, 100000)
                if proposed not in self.session_ids:
                    self.session_ids.append(proposed)
                    sess_id = proposed
            message = self.sip.gen_response(
                request, status_code=180, status_message="Ringing"
            )
            self.sip.send_b(
                message,
                request.headers["Via"][0]["address"],
                request.headers["Via"][0]["port"],
            )
            self._create_Call(request, sess_id)
            try:
                t = Timer(1, self.call_callback, [self.calls[call_id]])
                t.name = f"Phone Call: {call_id}"
                t.start()
                self.threads.append(t)
                self.threadLookup[t] = call_id
            except Exception:
                message = self.sip.gen_response(
                    request, status_code=486, status_message="Busy Here"
                )
                self.sip.send_b(
                    message,
                    request.headers["Via"][0]["address"],
                    request.headers["Via"][0]["port"],
                )
                raise

    def _callback_MSG_Bye(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        debug("BYE received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            return
        self.calls[call_id].on_bye()

    def _callback_MSG_Options(self, request: SIP.SIPMessage) -> str:
        if TRACE:
            ic()
        debug("Options recieved")
        if self.call_callback:
            response = self.sip.gen_response(
                request, status_code=200, status_message="OK"
            )
        else:
            response = self.sip.gen_response(
                request, status_code=486, status_message="Busy Here"
            )
            # TODO: Remove warning, implement RFC 3264
        return response

    def _callback_RESP_OK(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        debug("OK recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        # TODO: Somehow never is reached. Find out if you have a network
        # issue here or your invite is wrong.
        self.calls[call_id].answered(request)
        debug("Answered")
        # here we ack the call generated by the invite method of SIPClient
        ack = self.sip.gen_ack(request)
        self.sip.send_b(
            ack, request.headers["Contact"]["host"], request.headers["Contact"]["port"]
        )

    def _callback_RESP_NotFound(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        debug("Not Found recieved, invalid number called?")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            debug("TODO: Add 481 here as server is probably waiting for " + "an ACK")
        self.calls[call_id].not_found(request)
        debug("Terminating Call")
        ack = self.sip.gen_ack(request)
        self.sip.send_b(ack)

    def _callback_RESP_Unavailable(self, request: SIP.SIPMessage) -> None:
        if TRACE:
            ic()
        debug("Service Unavailable recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unkown call")
            debug("TODO: Add 481 here as server is probably waiting for " + "an ACK")
        self.calls[call_id].unavailable(request)
        debug("Terminating Call")
        ack = self.sip.gen_ack(request)
        self.sip.send_b(ack)

    def _create_Call(self, request: SIP.SIPMessage, sess_id: int) -> None:
        """
        Create a new VoIPCall object for the incoming call. Acting as UAS.

        Parameters
        ----------
        request: SIP.SIPMessage
            Request that originated the call.
        sess_id: int
            Internal session id.

        Returns
        -------
        None
        """
        if TRACE:
            ic()
        call_id = request.headers["Call-ID"]
        self.calls[call_id] = VoIPCall(
            self,
            CallState.RINGING,
            request,
            sess_id,
            self.bind_ip,
            sendmode=self.recvmode,
        )

    def start(self) -> None:
        if TRACE:
            ic()
        self.status = PhoneStatus.CONNECTING
        # self._status = PhoneStatus.REGISTERING
        try:
            self.sip.start()
            self.status = PhoneStatus.CONNECTED
            self.NSD = True
        except Exception:
            self.status = PhoneStatus.FAILED
            self.sip.stop()
            self.NSD = False
            raise

    def register(self) -> None:
        """
        Perform the registration process on user demand and not automatically.
        This can be used when registration is not needed.

        Returns
        -------
        None

        Raises
        ------
        Exception
            [TODO:description]
        """
        if TRACE:
            ic()
        self.status = PhoneStatus.REGISTERING
        try:
            self.sip.register()
            self.status = PhoneStatus.REGISTERED
        except Exception:
            self.status = PhoneStatus.FAILED
            self.sip.stop()
            self.NSD = False
            raise

    def stop(self) -> None:
        if TRACE:
            ic()
        self.status = PhoneStatus.DEREGISTERING
        for x in self.calls.copy():
            try:
                self.calls[x].hangup()
            except InvalidStateError:
                pass
        self.sip.stop()
        self.status = PhoneStatus.INACTIVE

    def call(
        self,
        number: str,
        payload_types: Optional[list[RTP.PayloadType]] = None,
    ) -> VoIPCall:
        """
        Call a number/name. This will create a new VoIPCall object. Acting as UAC.

        Parameters
        ----------
        number: str
            Number or name to call.
        payload_types: Optional[list[RTP.PayloadType]], optional
            Payload types to use, by default None.

        Returns
        -------
        VoIPCall
            VoIPCall object.

        Raises
        ------
        RuntimeError:
            [TODO:description]
        """
        if TRACE:
            ic()
        port = self.request_port()
        medias = {}
        if not payload_types:
            payload_types = [
                RTP.PayloadType.PCMA,
                RTP.PayloadType.PCMU,
                RTP.PayloadType.EVENT,
            ]
        medias[port] = {}
        dynamic_int = 101
        for pt in payload_types:
            if pt not in pyvoip.RTPCompatibleCodecs:
                raise RuntimeError(
                    "Unable to make call!\n\n"
                    + f"{pt} is not supported by pyvoip {pyvoip.__version__}"
                )
            try:
                medias[port][int(pt)] = pt
            except RTP.DynamicPayloadType:
                medias[port][dynamic_int] = pt
                dynamic_int += 1
        debug(f"Making call with {medias=}")
        request, call_id, sess_id = self.sip.invite(
            number, medias, RTP.TransmitType.SENDRECV
        )
        self.calls[call_id] = VoIPCall(
            self,
            CallState.DIALING,
            request,
            sess_id,
            self.bind_ip,
            ms=medias,
            sendmode=self.sendmode,
        )

        return self.calls[call_id]

    def request_port(self, blocking=True) -> int:
        if TRACE:
            ic()
        ports_available = [
            port
            for port in range(self.rtp_port_low, self.rtp_port_high + 1)
            if port not in self.assignedPorts
        ]
        if len(ports_available) == 0:
            # If no ports are available attempt to cleanup any missed calls.
            self.release_ports()
            ports_available = [
                port
                for port in range(self.rtp_port_low, self.rtp_port_high + 1)
                if (port not in self.assignedPorts)
            ]

        while self.NSD and blocking and len(ports_available) == 0:
            ports_available = [
                port
                for port in range(self.rtp_port_low, self.rtp_port_high + 1)
                if (port not in self.assignedPorts)
            ]
            time.sleep(0.5)
            self.release_ports()

            if len(ports_available) == 0:
                raise NoPortsAvailableError("No ports were available to be assigned")

        selection = random.choice(ports_available)
        self.assignedPorts.append(selection)

        return selection

    def release_ports(self, call: Optional[VoIPCall] = None) -> None:
        if TRACE:
            ic()
        self.portsLock.acquire()
        self._cleanup_dead_calls()
        try:
            if isinstance(call, VoIPCall):
                ports = list(call.assignedPorts.keys())
            else:
                dnr_ports = []
                for call_id in self.calls:
                    dnr_ports += list(self.calls[call_id].assignedPorts.keys())
                ports = []
                for port in self.assignedPorts:
                    if port not in dnr_ports:
                        ports.append(port)

            for port in ports:
                self.assignedPorts.remove(port)
        finally:
            self.portsLock.release()

    def _cleanup_dead_calls(self) -> None:
        if TRACE:
            ic()
        to_delete = []
        for thread in self.threads:
            if not thread.is_alive():
                call_id = self.threadLookup[thread]
                try:
                    del self.calls[call_id]
                except KeyError:
                    debug("Unable to delete from calls dictionary!")
                    debug(f"call_id={call_id} calls={self.calls}")
                try:
                    del self.threadLookup[thread]
                except KeyError:
                    debug("Unable to delete from threadLookup dictionary!")
                    debug(f"thread={thread} threadLookup={self.threadLookup}")
                to_delete.append(thread)
        for thread in to_delete:
            self.threads.remove(thread)
