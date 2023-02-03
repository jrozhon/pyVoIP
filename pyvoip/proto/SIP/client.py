import hashlib
import random
import select
import socket
import ssl
import time
import uuid
from base64 import b16encode, b64encode
from threading import Lock, Timer
from typing import TYPE_CHECKING, Any, Callable, Optional

import jinja2
from rich import print

import pyvoip
from pyvoip.lib.credentials import Credentials
from pyvoip.lib.helpers import Counter
from pyvoip.proto.SIP.error import InvalidAccountInfoError, SIPParseError
from pyvoip.proto.SIP.message import SIPMessage, SIPMessageType, SIPStatus
from pyvoip.sock.transport import TransportMode
from pyvoip.templates.body import SIPBodyTemplate
from pyvoip.templates.sip import SIPHeaderTemplate

if TYPE_CHECKING:
    from pyvoip.proto import RTP

from icecream import ic

debug = pyvoip.debug
TRACE = pyvoip.TRACE


def fmt(
    template: SIPHeaderTemplate | SIPBodyTemplate,
    vars: dict[str, Any],
    fix_newlines: bool = True,
) -> str:
    """
    A temporary function to allow migration to templates.

    Parameters
    ----------
    teplate:
        A template to be used.
    vars
        A dictionary of variables to be used in the template.
    fix_newlines:
        Whether to fix newlines in the template.

    Returns
    -------
    str
        The rendered template.
    """
    if TRACE:
        ic()

    e = jinja2.Environment()
    t = e.from_string(template.value)
    msg = t.render(**vars).lstrip()
    if fix_newlines:
        msg = msg.replace("\n", "\r\n")
    # print("Call of fmt function. Rendered msg:")
    # print(msg)
    return msg


class SIPClient:
    def __init__(
        self,
        server: str,
        port: int,
        user: str,
        credentials: Credentials,
        bind_ip: str = "0.0.0.0",
        bind_port: int = 5060,
        call_callback: Optional[Callable[[SIPMessage], Optional[str]]] = None,
        transport_mode: TransportMode = TransportMode.UDP,
    ):
        if TRACE:
            ic()
        self.uuid = uuid.uuid4()
        self.NSD = False
        self.server = server
        self.port = port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.user = user
        self.credentials = credentials
        self.transport_mode = transport_mode

        self.call_callback = call_callback

        self.tags: list[str] = []
        self.tagLibrary = {"register": self.gen_tag()}

        self.default_expires = 120
        self.register_timeout = 30

        self.invite_counter = Counter()
        self.register_counter = Counter()
        self.subscribe_counter = Counter()
        self.byeCounter = Counter()
        self.callID = Counter()
        self.sessID = Counter()

        self.urnUUID = self.gen_urn_uuid()
        self.nc: dict[str, Counter] = {}

        self.registerThread: Optional[Timer] = None
        self.recvLock = Lock()

    def send_b(
        self, message: str, dst: str | None = None, dst_port: int | None = None
    ) -> None:
        """
        Send a message to the server. This is the replacement for recurrent
        self.out.sendto calls to allow to check on messages being sent out.
        """
        if TRACE:
            ic()

        dst = dst or self.server
        dst_port = dst_port or self.port

        print(f"----> {dst}:{dst_port}")
        print(message, end="\n")
        # print(message.encode("utf8"), end="\n")

        try:
            self.out.sendto(message.encode("utf8"), (dst, dst_port))
        except socket.timeout:
            print("Socket timeout on send_b")
        except socket.gaierror:
            print("Error while Getting Address Info on send_b")

    def recv_b(self, buffsize: int = 8192) -> bytes:
        """
        Receive a message from the server. This is the replacement for recurrent
        self.s.recv calls to allow to check on messages being received.

        Don't trace here as it will generate a lot of output.
        """

        raw, (addr, port) = self.s.recvfrom(buffsize)
        try:
            print(f"<---- {addr}:{port}")
            print(raw.decode("utf8"), end="\n")
        except Exception as ex:
            pass
        return raw

    def recv(self) -> None:
        if TRACE:
            ic()
        while self.NSD:
            self.recvLock.acquire()
            self.s.setblocking(False)
            try:
                raw = self.recv_b()
                if raw != b"\x00\x00\x00\x00":
                    try:
                        message = SIPMessage(raw)
                        debug(message.summary())
                        self.parse_message(message)
                    except Exception as ex:
                        debug(f"Error on header parsing: {ex}")
            except BlockingIOError:
                self.s.setblocking(True)
                self.recvLock.release()
                time.sleep(0.01)
                continue
            except SIPParseError as e:
                if "SIP Version" in str(e):
                    request = self.gen_sip_version_not_supported(message)
                    self.send_b(request)
                else:
                    debug(f"SIPParseError in SIP.recv: {type(e)}, {e}")
            except Exception as e:
                debug(f"SIP.recv error: {type(e)}, {e}\n\n{str(raw, 'utf8')}")
                if pyvoip.DEBUG:
                    self.s.setblocking(True)
                    self.recvLock.release()
                    raise
            self.s.setblocking(True)
            self.recvLock.release()

    def parse_message(self, message: SIPMessage) -> None:
        if TRACE:
            ic()
        if message.type != SIPMessageType.REQUEST:
            if message.status == SIPStatus.OK:
                if self.call_callback is not None:
                    self.call_callback(message)
            elif message.status == SIPStatus.NOT_FOUND:
                if self.call_callback is not None:
                    self.call_callback(message)
            elif message.status == SIPStatus.SERVICE_UNAVAILABLE:
                if self.call_callback is not None:
                    self.call_callback(message)
            elif (
                message.status == SIPStatus.TRYING
                or message.status == SIPStatus.RINGING
            ):
                pass
            else:
                debug(
                    "TODO: Add 500 Error on Receiving SIP Response:\r\n"
                    + message.summary(),
                    "TODO: Add 500 Error on Receiving SIP Response",
                )
            self.s.setblocking(True)
            return
        elif message.method == "INVITE":
            if self.call_callback is None:
                request = self.gen_busy(message)
                # TODO what about port?
                self.send_b(
                    request,
                    message.headers["Via"][0]["address"],
                    message.headers["Via"][0]["port"],
                )
            else:
                self.call_callback(message)
        elif message.method == "BYE":
            # TODO: If callCallback is None, the call doesn't exist, 481
            # this is not actual call_callback but the callback assigned
            # to bye by voip.py
            if self.call_callback:
                self.call_callback(message)

            # this actually hangs up the incoming call
            response = self.gen_ok(message)
            try:
                # BYE comes from client cause server only acts as mediator
                _sender_address = message.headers["Via"][0]["address"]
                _sender_port = message.headers["Via"][0]["port"]
                self.send_b(response, _sender_address, _sender_port)
            except Exception as e:
                debug("BYE Answer failed falling back to server as target", e)
                self.send_b(
                    response,
                    message.headers["Via"][0]["address"],
                    message.headers["Via"][0]["port"],
                )
        elif message.method == "ACK":
            return
        elif message.method == "CANCEL":
            # TODO: If callCallback is None, the call doesn't exist, 481
            self.call_callback(message)  # type: ignore
            response = self.gen_ok(message)
            self.send_b(
                response,
                message.headers["Via"][0]["address"],
                message.headers["Via"][0]["port"],
            )
        elif message.method == "OPTIONS":
            if self.call_callback:
                response = str(self.call_callback(message))
            else:
                response = self._gen_options_response(message)
            self.send_b(
                response,
                message.headers["Via"][0]["address"],
                message.headers["Via"][0]["port"],
            )
        else:
            debug("TODO: Add 400 Error on non processable request")

    def start(self) -> None:
        if TRACE:
            ic()
        if self.NSD:
            raise RuntimeError("Attempted to start already started SIPClient")
        self.NSD = True
        self.s = socket.socket(socket.AF_INET, self.transport_mode.socket_type)
        """
        self.out = socket.socket(
            socket.AF_INET, self.transport_mode.socket_type
        )
        """

        if self.transport_mode.tls_mode:
            ctx = ssl.SSLContext(protocol=self.transport_mode.tls_mode)
            self.s = ctx.wrap_socket(self.s)
            # self.out = ctx.wrap_socket(self.out)
        self.s.bind((self.bind_ip, self.bind_port))
        self.out = self.s
        self.register()
        t = Timer(1, self.recv)
        t.name = "SIP Receive"
        t.start()

    def stop(self) -> None:
        if TRACE:
            ic()
        self.NSD = False
        if self.registerThread:
            # Only run if registerThread exists
            self.registerThread.cancel()
            self.deregister()
        self._close_sockets()

    def _close_sockets(self) -> None:
        if TRACE:
            ic()
        if hasattr(self, "s"):
            if self.s:
                self.s.close()
        if hasattr(self, "out"):
            if self.out:
                self.out.close()

    def gen_call_id(self) -> str:
        if TRACE:
            ic()
        hash = hashlib.sha256(str(self.callID.next()).encode("utf8"))
        hhash = hash.hexdigest()
        return f"{hhash[0:32]}@{self.bind_ip}:{self.bind_port}"

    def gen_last_call_id(self) -> str:
        if TRACE:
            ic()
        hash = hashlib.sha256(str(self.callID.current() - 1).encode("utf8"))
        hhash = hash.hexdigest()
        return f"{hhash[0:32]}@{self.bind_ip}:{self.bind_port}"

    def gen_tag(self) -> str:
        if TRACE:
            ic()
        # Keep as True instead of NSD so it can generate a tag on deregister.
        while True:
            rand = str(random.randint(1, 4294967296)).encode("utf8")
            tag = hashlib.md5(rand).hexdigest()[0:8]
            if tag not in self.tags:
                self.tags.append(tag)
                return tag
        return ""

    def gen_sip_version_not_supported(self, request: SIPMessage) -> str:
        if TRACE:
            ic()
        # TODO: Add Supported
        response = "SIP/2.0 505 SIP Version Not Supported\r\n"
        response += "\r\n".join(self._gen_response_via_header(request)) + "\r\n"
        response += f"From: {request.headers['From']['raw']}\r\n"
        to = request.headers["To"]
        display_name = f'"{to["display-name"]}" ' if to["display-name"] else ""
        response += f'To: {display_name}<{to["uri"]}>;tag=' + f"{self.gen_tag()}\r\n"
        response += f"Call-ID: {request.headers['Call-ID']}\r\n"
        response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        response += f"Contact: {request.headers['Contact']['raw']}\r\n"
        response += f"User-Agent: pyvoip {pyvoip.__version__}\r\n"
        response += 'Warning: 399 GS "Unable to accept call"\r\n'
        response += f"Allow: {(', '.join(pyvoip.SIPCompatibleMethods))}\r\n"
        response += "Content-Length: 0\r\n\r\n"

        return response

    def _hash_md5(self, data: bytes) -> str:
        if TRACE:
            ic()
        """
        MD5 Hash function.
        """
        return hashlib.md5(data).hexdigest()

    def _hash_sha256(self, data: bytes) -> str:
        if TRACE:
            ic()
        """
        SHA-256 Hash function.
        """
        sha256 = hashlib.new("sha256")
        sha256.update(data)
        return sha256.hexdigest()

    def _hash_sha512_256(self, data: bytes) -> str:
        if TRACE:
            ic()
        """
        SHA-512-256 Hash function.
        """
        sha512 = hashlib.new("sha512")
        sha512.update(data)
        return sha512.hexdigest()[:64]

    def gen_digest(self, request: SIPMessage, body: str = "") -> dict[str, str]:
        if TRACE:
            ic()
        server = request.headers["From"]["host"]
        realm = request.authentication["realm"]
        user = request.headers["From"]["user"]
        username = self.credentials.auth_user
        password = self.credentials.password
        nonce = request.authentication["nonce"]
        method = request.headers["CSeq"]["method"]
        uri = f"sip:{self.server}"  # ;transport={self.transport_mode}"
        algo = request.authentication.get("algorithm", "md5").lower()
        if algo in ["sha512-256", "sha512-256-sess"]:
            hash_func = self._hash_sha512_256
        elif algo in ["sha256", "sha256-sess"]:
            hash_func = self._hash_sha256
        else:
            hash_func = self._hash_md5
        # Get new method values
        qop = request.authentication.get("qop", None).pop(0)
        opaque = request.authentication.get("opaque", None)
        userhash = request.authentication.get("userhash", False)

        if qop:
            # Use new hash method
            cnonce = uuid.uuid4().hex
            if nonce not in self.nc:
                self.nc[nonce] = Counter()
            nc = str(b16encode(self.nc[nonce].next().to_bytes(4, "big")), "utf8")
            HA1 = f"{username}:{realm}:{password}"
            HA1 = hash_func(HA1.encode("utf8"))
            if "-sess" in algo:
                HA1 += f":{nonce}:{cnonce}"
            HA2 = f"{method}:{uri}"
            if "auth-int" in qop:
                HAB = hash_func(body.encode("utf8"))
                HA2 += f":{HAB}"
            HA2 = hash_func(HA2.encode("utf8"))
            HA3 = f"{HA1}:{nonce}:{nc}:{cnonce}:{qop}:{HA2}"
            if userhash:
                username = hash_func(f"{username}:{realm}")
            response = {
                "realm": realm,
                "nonce": nonce,
                "algorithm": algo,
                "digest": hash_func(HA3.encode("utf8")),
                "uri": uri,
                "username": username,
                "opaque": opaque,
                "qop": qop,
                "cnonce": cnonce,
                "nc": nc,
                "userhash": userhash,
            }
        else:
            # Use old hash method
            HA1 = f"{username}:{realm}:{password}"
            HA1 = hash_func(HA1.encode("utf8"))
            HA2 = f"{method}:{uri}"
            HA2 = hash_func(HA2.encode("utf8"))
            HA3 = f"{HA1}:{nonce}:{HA2}"
            response = {
                "realm": realm,
                "nonce": nonce,
                "algorithm": algo,
                "digest": hash_func(HA3.encode("utf8")),
                "username": username,
                "opaque": opaque,
            }

        return response

    def gen_authorization(self, request: SIPMessage, body: str = "") -> str:
        if TRACE:
            ic()
        if request.authentication["method"].lower() == "digest":
            digest = self.gen_digest(request)
            response = (
                f'Authorization: Digest username="{digest["username"]}",'
                + f'realm="{digest["realm"]}",nonce="{digest["nonce"]}",'
                + f'uri="{digest["uri"]}",response="{digest["digest"]}",'
                + f'algorithm={digest["algorithm"]}'
            )
            if "qop" in digest:
                response += (
                    f',qop={digest["qop"]},'
                    + f'cnonce="{digest["cnonce"]}",nc={digest["nc"]},'
                    + f'userhash={str(digest["userhash"]).lower()}'
                )
            if "opaque" in digest:
                if digest["opaque"]:
                    response += f',opaque="{digest["opaque"]}"'
            response += "\r\n"
        elif request.authentication["method"].lower() == "basic":
            if not pyvoip.ALLOW_BASIC_AUTH:
                raise RuntimeError(
                    "Basic authentication is not allowed. "
                    + "Please use pyvoip.ALLOW_BASIC_AUTH = True to allow it, "
                    + "but this is not recommended."
                )
            server = request.headers["From"]["host"]
            realm = request.authentication.get("realm", None)
            username = self.credentials.auth_user
            password = self.credentials.password
            userid_pass = f"{username}:{password}".encode("utf8")
            encoded = str(b64encode(userid_pass), "utf8")
            response = f"Authorization: Basic {encoded}\r\n"
        return response

    def gen_branch(self, length=32) -> str:
        """
        Generate unique branch id according to
        https://datatracker.ietf.org/doc/html/rfc3261#section-8.1.1.7
        """
        if TRACE:
            ic()
        branchid = uuid.uuid4().hex[: length - 7]
        return f"z9hG4bK{branchid}"

    def gen_urn_uuid(self) -> str:
        """
        Generate client instance specific urn:uuid
        """
        if TRACE:
            ic()
        return str(uuid.uuid4()).upper()

    def gen_register(
        self, response: SIPMessage | None = None, deregister: bool = False
    ) -> str:
        """
        Generates REGISTER request (initial and subsequent) to register with SIP Server

        Parameters
        ----------
        response : SIPMessage
            The response to the previous REGISTER request. If this is the first
            REGISTER request, this should be None.
        deregister : bool
            A flag telling the SIP client whether we want to register or unregister

        Returns
        -------
        str
            Right now, it returns a string containing the SIP message. In the future,
            it will return a SIPMessage object.
        """
        if TRACE:
            ic()
        vars = dict(
            method="REGISTER",
            r_user=None,
            r_domain=self.server,
            v_proto=self.transport_mode,
            v_addr=self.bind_ip,
            v_port=self.bind_port,
            rport=";rport",
            branch=self.gen_branch(),
            f_name=self.user,
            f_user=self.user,
            f_domain=self.server,
            f_tag=self.tagLibrary["register"],
            t_name=self.user,
            t_user=self.user,
            t_domain=self.server,
            t_tag=None,
            call_id=self.gen_call_id(),
            cseq_num=self.register_counter.next(),
            c_user=self.user,
            c_domain=self.bind_ip,
            c_port=self.bind_port,
            c_transport=self.transport_mode,
            c_params=f'+sip.instance="<urn:uuid:{self.urnUUID}>"',
            allow=",".join(pyvoip.SIPCompatibleMethods),
            expires=self.default_expires if not deregister else 0,
            user_agent=f"pyvoip {pyvoip.__version__}",
            max_forwards=70,
            content_type=None,
            content_length=None,
            authorization=None
            if response is None
            else self.gen_authorization(response)[
                15:
            ],  # strip Authorization:_ not to break compatibility
            body=None,
        )
        register_request = fmt(template=SIPHeaderTemplate.REQUEST, vars=vars)

        return register_request

    def gen_invite(
        self,
        number: str,
        sess_id: str,
        ms: dict[int, dict[int, "RTP.PayloadType"]],
        sendtype: "RTP.TransmitType",
        call_id: str,
        response: SIPMessage | None = None,
    ) -> str:
        """
        Same as gen_register, this method generates INVITE based on the values given
        in vars. Ideally, these methods should converge to a single method gen_request.
        It is not clear at this point if this generalization would be flexible enough
        to manage all possible scenarios.

        Parameters
        ----------
        number : str
            Number to call. Not ideal, as it is a string. Should be renamed as there can be names as well.
        sess_id : str
            Session ID.
        ms : dict
            Dictionary of available audio media types.
        sendtype: RTP.TransmitType
            Type of transmission (sendrecv, sendonly, recvonly, inactive).
        call_id : str
            Call ID.
        response : SIPMessage
            The response to the previous INVITE request. If this is the first
            INVITE request, this should be None.

        Returns
        -------
        str
            Formatted INVITE request.
        """
        if TRACE:
            ic()
        tag = self.gen_tag()
        self.tagLibrary[call_id] = tag

        # Generate body first for content length
        body_vars = dict(
            sdp_user="pyvoip",
            sdp_sess_id=sess_id,
            sdp_sess_version=int(sess_id) + 2,
            sdp_af="IP4",
            local_ip=self.bind_ip,
            sdp_ms=ms,
            sdp_direction=sendtype,
        )

        body = fmt(template=SIPBodyTemplate.SDP, vars=body_vars, fix_newlines=False)

        vars = dict(
            method="INVITE",
            r_user=number,
            r_domain=self.server,
            v_proto=self.transport_mode,
            v_addr=self.bind_ip,
            v_port=self.bind_port,
            rport=";rport",
            branch=self.gen_branch(),
            f_name=self.user,
            f_user=self.user,
            f_domain=self.server,
            f_tag=self.tagLibrary[call_id],
            t_name=None,
            t_user=number,
            t_domain=self.server,
            # unless we are re-inviting, no to_tag is known
            t_tag=None,
            call_id=call_id,
            cseq_num=self.invite_counter.next(),
            c_user=self.user,
            c_domain=self.bind_ip,
            c_port=self.bind_port,
            c_transport=self.transport_mode,
            c_params=None,  # f'+sip.instance="<urn:uuid:{self.urnUUID}>"',
            allow=",".join(pyvoip.SIPCompatibleMethods),
            expires=None,  # self.default_expires if not deregister else 0,
            user_agent=f"pyvoip {pyvoip.__version__}",
            max_forwards=70,
            content_type="application/sdp",
            content_length=len(body),
            authorization=None
            if response is None
            else self.gen_authorization(response)[
                15:
            ],  # strip Authorization:_ not to break compatibility
            body=body,
        )

        invite_request = fmt(template=SIPHeaderTemplate.REQUEST, vars=vars)

        return invite_request

    def gen_ack(self, response: SIPMessage) -> str:
        """
        Format ACK request based on the response to the INVITE request.

        Parameters
        ----------
        response : SIPMessage
            SIP response to INVITE request.

        Returns
        -------
        str
            Formatted ACK request.
        """
        if TRACE:
            ic()
        vars = dict(
            method="ACK",
            r_user=response.headers["To"]["user"],
            r_domain=response.headers["To"]["host"],
            v_proto=self.transport_mode,
            v_addr=self.bind_ip,
            v_port=self.bind_port,
            rport=";rport",
            # branch should be regenerated if 200 OK message arrives
            # otherwise it should be the same as in the INVITE request
            branch=response.headers["Via"][0]["branch"]
            if response.status != SIPStatus(200)
            else self.gen_branch(),
            f_name=self.user,
            f_user=self.user,
            f_domain=self.server,
            f_tag=self.tagLibrary[response.headers["Call-ID"]],
            t_name=response.headers["To"]["display-name"],
            t_user=response.headers["To"]["user"],
            t_domain=response.headers["To"]["host"],
            t_tag=response.headers["To"]["tag"],
            call_id=response.headers["Call-ID"],
            # cseq is not incremented in either case
            cseq_num=response.headers["CSeq"]["check"],
            # no need for contact in ACK
            c_user=None,
            c_domain=None,
            c_port=None,
            c_transport=None,
            c_params=None,
            # allow is not needed in ACK
            allow=None,
            # expires is not needed in ACK
            expires=None,
            user_agent=f"pyvoip {pyvoip.__version__}",
            max_forwards=70,
            # Content type/length should be used in late media
            # No support as of yet, though
            content_type=None,
            content_length=0,
            # Usually ACK is not authenticated
            authorization=None
            # if response is None
            # else self.gen_authorization(response)[
            #     15:
            # ],  # strip Authorization:_ not to break compatibility
            # body=None,
        )
        ack_request = fmt(template=SIPHeaderTemplate.REQUEST, vars=vars)

        return ack_request

    def gen_bye(self, request: SIPMessage) -> str:
        """
        Format BYE request based on the request to the INVITE request.
        INVITE is actually a second one and so the request.headers
        contain all the necessary information.


        Parameters
        ----------
        request : SIPMessage
            SIP INVITE request that originated the call.

        Returns
        -------
        str
            Formatted BYE request.
        """
        if TRACE:
            ic()

        # bye can go from the same side as the invite
        # or from the other side. this affects the tags

        # locally stored tag
        tag = self.tagLibrary[request.headers["Call-ID"]]
        # if local tag is the same as the tag from the From header,
        # we initiated the call, so we need to use the tag from the To header
        # otherwise we need to use the tag from the From header.

        if request.headers["From"]["tag"] == tag:
            f_tag = tag
            t_tag = request.headers["To"]["tag"]
            f_user = self.user
            f_name = self.user
            f_domain = self.server
            t_name = request.headers["To"]["display-name"]
            t_user = request.headers["To"]["user"]
            t_domain = request.headers["To"]["host"]

        else:
            f_tag = request.headers["To"]["tag"]
            t_tag = tag
            t_user = self.user
            t_name = self.user
            t_domain = self.server
            f_name = request.headers["To"]["display-name"]
            f_user = request.headers["To"]["user"]
            f_domain = request.headers["To"]["host"]

        vars = dict(
            method="BYE",
            r_user=request.headers["Contact"]["user"],
            r_domain=request.headers["Contact"]["host"],
            r_port=request.headers["Contact"]["port"],
            v_proto=self.transport_mode,
            v_addr=self.bind_ip,
            v_port=self.bind_port,
            rport=";rport",
            # branch should be regenerated if 200 OK message arrives
            # otherwise it should be the same as in the INVITE request
            branch=self.gen_branch(),
            f_name=f_name,
            f_user=f_user,
            f_domain=f_domain,
            f_tag=f_tag,
            t_name=t_name,
            t_user=t_user,
            t_domain=t_domain,
            t_tag=t_tag,
            call_id=request.headers["Call-ID"],
            # cseq is not incremented in either case
            cseq_num=int(request.headers["CSeq"]["check"]) + 1,
            # no need for contact in ACK
            c_user=self.user,
            c_domain=self.bind_ip,
            c_port=self.bind_port,
            c_transport=self.transport_mode,
            c_params=None,
            # allow is not needed in ACK
            allow=", ".join(pyvoip.SIPCompatibleMethods),
            # expires is not needed in ACK
            expires=None,
            user_agent=f"pyvoip {pyvoip.__version__}",
            max_forwards=70,
            # Content type/length should be used in late media
            # No support as of yet, though
            content_type=None,
            content_length=0,
            # Usually ACK is not authenticated
            authorization=None
            # if request is None
            # else self.gen_authorization(request)[
            #     15:
            # ],  # strip Authorization:_ not to break compatibility
            # body=None,
        )
        bye_request = fmt(template=SIPHeaderTemplate.REQUEST, vars=vars)

        return bye_request

    def gen_ok(self, request: SIPMessage) -> str:
        if TRACE:
            ic()
        okResponse = "SIP/2.0 200 OK\r\n"
        okResponse += "\r\n".join(self._gen_response_via_header(request)) + "\r\n"
        okResponse += f"From: {request.headers['From']['raw']}\r\n"
        to = request.headers["To"]
        display_name = f'"{to["display-name"]}" ' if to["display-name"] else ""
        okResponse += f'To: {display_name}<{to["uri"]}>;tag=' + f"{self.gen_tag()}\r\n"
        okResponse += f"Call-ID: {request.headers['Call-ID']}\r\n"
        okResponse += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        okResponse += f"User-Agent: pyvoip {pyvoip.__version__}\r\n"
        okResponse += f"Allow: {(', '.join(pyvoip.SIPCompatibleMethods))}\r\n"
        okResponse += "Content-Length: 0\r\n\r\n"

        vars = dict(
            status_code=200,
            status_message="OK",
            method=request.headers["CSeq"]["method"],
            # r_user=request.headers["Contact"]["user"],
            # r_domain=request.headers["Contact"]["host"],
            # r_port=request.headers["Contact"]["port"],
            # for responses Via should remain the same as in the request
            # as it is used to forward the response back to the
            # transaction origin
            vias=self._gen_response_via_header(request),
            # branch should be regenerated if 200 OK message arrives
            # otherwise it should be the same as in the INVITE request
            # as this is response, we can leave From header as is
            f_raw=request.headers["From"]["raw"],
            # f_name=request.headers["From"]["display-name"],
            # f_user=request.headers["From"]["user"],
            # f_domain=request.headers["From"]["host"],
            # f_tag=request.headers["From"]["tag"],
            # if there is a tag in to stored already,
            # it means that we are further in dialog
            # so no need to manipulate it
            t_raw=request.headers["To"]["raw"]
            if request.headers["To"]["tag"]
            else None,
            # this wont be used if t_raw is set
            t_name=request.headers["To"]["display-name"],
            t_user=request.headers["To"]["user"],
            t_domain=request.headers["To"]["host"],
            t_tag=request.headers["To"]["tag"]
            if request.headers["To"]["tag"]
            else self.gen_tag(),
            call_id=request.headers["Call-ID"],
            # cseq is not incremented in either case
            cseq_num=int(request.headers["CSeq"]["check"]),
            # no need for contact in ACK
            c_user=self.user,
            c_domain=self.bind_ip,
            c_port=self.bind_port,
            c_transport=self.transport_mode,
            c_params=None,
            # allow is not needed in ACK
            allow=", ".join(pyvoip.SIPCompatibleMethods),
            # expires is not needed in ACK
            expires=None,
            user_agent=f"pyvoip {pyvoip.__version__}",
            max_forwards=70,
            # Content type/length should be used in late media
            # No support as of yet, though
            content_type=None,
            content_length=0,
            # Usually ACK is not authenticated
            authorization=None
            # if request is None
            # else self.gen_authorization(request)[
            #     15:
            # ],  # strip Authorization:_ not to break compatibility
            # body=None,
        )
        ok_response = fmt(template=SIPHeaderTemplate.RESPONSE, vars=vars)

        return ok_response
        # return okResponse

    # def gen_subscribe(self, response: SIPMessage) -> str:
    #     subRequest = f"SUBSCRIBE sip:{self.user}@{self.server} SIP/2.0\r\n"
    #     subRequest += (
    #         "Via: SIP/2.0/"
    #         + str(self.transport_mode)
    #         + f" {self.bind_ip}:{self.bind_port};"
    #         + f"branch={self.gen_branch()};rport\r\n"
    #     )
    #     subRequest += (
    #         f'From: "{self.user}" '
    #         + f"<sip:{self.user}@{self.server}>;tag="
    #         + f"{self.gen_tag()}\r\n"
    #     )
    #     subRequest += f"To: <sip:{self.user}@{self.server}>\r\n"
    #     subRequest += f'Call-ID: {response.headers["Call-ID"]}\r\n'
    #     subRequest += f"CSeq: {self.subscribe_counter.next()} SUBSCRIBE\r\n"
    #     # TODO: check if transport is needed
    #     subRequest += (
    #         "Contact: "
    #         + f"<sip:{self.user}@{self.bind_ip}:{self.bind_port};"
    #         + "transport="
    #         + str(self.transport_mode)
    #         + ">;+sip.instance="
    #         + f'"<urn:uuid:{self.urnUUID}>"\r\n'
    #     )
    #     subRequest += "Max-Forwards: 70\r\n"
    #     subRequest += f"User-Agent: pyvoip {pyvoip.__version__}\r\n"
    #     subRequest += f"Expires: {self.default_expires * 2}\r\n"
    #     subRequest += "Event: message-summary\r\n"
    #     subRequest += "Accept: application/simple-message-summary"
    #     subRequest += "Content-Length: 0"
    #     subRequest += "\r\n\r\n"
    #
    #     return subRequest

    def gen_busy(self, request: SIPMessage) -> str:
        if TRACE:
            ic()
        response = "SIP/2.0 486 Busy Here\r\n"
        response += "\r\n".join(self._gen_response_via_header(request)) + "\r\n"
        response += f"From: {request.headers['From']['raw']}\r\n"
        to = request.headers["To"]
        display_name = f'"{to["display-name"]}" ' if to["display-name"] else ""
        response += f'To: {display_name}<{to["uri"]}>;tag=' + f"{self.gen_tag()}\r\n"
        response += f"Call-ID: {request.headers['Call-ID']}\r\n"
        response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        response += f"Contact: {request.headers['Contact']['raw']}\r\n"
        # TODO: Add Supported
        response += f"User-Agent: pyvoip {pyvoip.__version__}\r\n"
        response += 'Warning: 399 GS "Unable to accept call"\r\n'
        response += f"Allow: {(', '.join(pyvoip.SIPCompatibleMethods))}\r\n"
        response += "Content-Length: 0\r\n\r\n"

        return response

    def gen_ringing(self, request: SIPMessage) -> str:
        if TRACE:
            ic()
        tag = self.gen_tag()
        regRequest = "SIP/2.0 180 Ringing\r\n"
        regRequest += "\r\n".join(self._gen_response_via_header(request)) + "\r\n"
        regRequest += f"From: {request.headers['From']['raw']}\r\n"
        to = request.headers["To"]
        display_name = f'"{to["display-name"]}" ' if to["display-name"] else ""
        regRequest += f'To: {display_name}<{to["uri"]}>;tag={tag}\r\n'
        regRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        regRequest += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        regRequest += f"Contact: {request.headers['Contact']['raw']}\r\n"
        # TODO: Add Supported
        regRequest += f"User-Agent: pyvoip {pyvoip.__version__}\r\n"
        regRequest += f"Allow: {(', '.join(pyvoip.SIPCompatibleMethods))}\r\n"
        regRequest += "Content-Length: 0\r\n\r\n"

        self.tagLibrary[request.headers["Call-ID"]] = tag

        return regRequest

    def gen_answer(
        self,
        request: SIPMessage,
        sess_id: str,
        ms: dict[int, dict[int, "RTP.PayloadType"]],
        sendtype: "RTP.TransmitType",
    ) -> str:
        if TRACE:
            ic()
        # Generate body first for content length
        body = "v=0\r\n"
        # TODO: Check IPv4/IPv6
        body += f"o=pyvoip {sess_id} {int(sess_id)+2} IN IP4 {self.bind_ip}\r\n"
        body += f"s=pyvoip {pyvoip.__version__}\r\n"
        # TODO: Check IPv4/IPv6
        body += f"c=IN IP4 {self.bind_ip}\r\n"
        body += "t=0 0\r\n"
        for x in ms:
            # TODO: Check AVP mode from request
            body += f"m=audio {x} RTP/AVP"
            for m in ms[x]:
                body += f" {m}"
        body += "\r\n"  # m=audio <port> RTP/AVP <codecs>\r\n
        for x in ms:
            for m in ms[x]:
                body += f"a=rtpmap:{m} {ms[x][m]}/{ms[x][m].rate}\r\n"
                if str(ms[x][m]) == "telephone-event":
                    body += f"a=fmtp:{m} 0-15\r\n"
        body += "a=ptime:20\r\n"
        body += "a=maxptime:150\r\n"
        body += f"a={sendtype}\r\n"

        tag = self.tagLibrary[request.headers["Call-ID"]]

        regRequest = "SIP/2.0 200 OK\r\n"
        regRequest += "\r\n".join(self._gen_response_via_header(request)) + "\r\n"
        regRequest += f"From: {request.headers['From']['raw']}\r\n"
        to = request.headers["To"]
        display_name = f'"{to["display-name"]}" ' if to["display-name"] else ""
        regRequest += f'To: {display_name}<{to["uri"]}>;tag={tag}\r\n'
        regRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        regRequest += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        regRequest += (
            "Contact: " + f"<sip:{self.user}@{self.bind_ip}:{self.bind_port}>\r\n"
        )
        # TODO: Add Supported
        regRequest += f"User-Agent: pyvoip {pyvoip.__version__}\r\n"
        regRequest += f"Allow: {(', '.join(pyvoip.SIPCompatibleMethods))}\r\n"
        regRequest += "Content-Type: application/sdp\r\n"
        regRequest += f"Content-Length: {len(body)}\r\n\r\n"
        regRequest += body

        return regRequest

    def _gen_options_response(self, request: SIPMessage) -> str:
        if TRACE:
            ic()
        return self.gen_busy(request)

    # def _gen_response_via_header(self, request: SIPMessage) -> str:
    #     via = ""
    #     for h_via in request.headers["Via"]:
    #         v_line = (
    #             "Via: SIP/2.0/"
    #             + str(self.transport_mode)
    #             + " "
    #             + f'{h_via["address"][0]}:{h_via["address"][1]}'
    #         )
    #         if "branch" in h_via.keys():
    #             v_line += f';branch={h_via["branch"]}'
    #         if "rport" in h_via.keys():
    #             if h_via["rport"] is not None:
    #                 v_line += f';rport={h_via["rport"]}'
    #             else:
    #                 v_line += ";rport"
    #         if "received" in h_via.keys():
    #             v_line += f';received={h_via["received"]}'
    #         v_line += "\r\n"
    #         via += v_line
    #     return via
    def _gen_response_via_header(self, request: SIPMessage) -> list[str]:
        if TRACE:
            ic()
        vias = []
        for via in request.headers["Via"]:
            vias.append(
                fmt(
                    template=SIPHeaderTemplate.RESPONSE_VIA,
                    vars=dict(
                        v_proto=via["proto"],
                        v_addr=via["address"],
                        v_port=via["port"],
                        rport=via["rport"],
                        branch=via["branch"],
                    ),
                    fix_newlines=False,
                )
            )
        return vias

    def invite(
        self,
        number: str,
        ms: dict[int, dict[int, "RTP.PayloadType"]],
        sendtype: "RTP.TransmitType",
    ) -> tuple[SIPMessage, str, int]:
        if TRACE:
            ic()
        call_id = self.gen_call_id()
        sess_id = self.sessID.next()
        invite = self.gen_invite(number, str(sess_id), ms, sendtype, call_id)
        self.recvLock.acquire()
        self.send_b(invite)
        debug("Invited")
        # here, the message.headers are first filled with content
        response = SIPMessage(self.recv_b())

        while (
            response.status != SIPStatus(401)
            and response.status != SIPStatus(100)
            and response.status != SIPStatus(180)
        ) or response.headers["Call-ID"] != call_id:
            if not self.NSD:
                break
            self.parse_message(response)
            response = SIPMessage(self.recv_b())

        if response.status == SIPStatus(100) or response.status == SIPStatus(180):
            self.recvLock.release()
            return SIPMessage(invite.encode("utf8")), call_id, sess_id
        debug(f"Received Response: {response.summary()}")

        self.ack(response)
        debug("Acknowledged")

        invite = self.gen_invite(
            number, str(sess_id), ms, sendtype, call_id, response=response
        )

        self.send_b(invite)

        self.recvLock.release()

        return SIPMessage(invite.encode("utf8")), call_id, sess_id

    def ack(self, response: SIPMessage) -> None:
        """
        Manage ACK for outgoing INVITES. In SIP this message can be routed
        based on the Record-Route header and Contact header. This function
        will handle that routing.

        Parameters
        ----------
        response : SIPMessage
            Received SIP Response. Usually 200 OK.

        Returns
        -------
        None
        """
        if TRACE:
            ic()
        ack = self.gen_ack(response)
        # handle negative responses first
        # these are negotiated with server
        if response.status != SIPStatus(200):
            self.send_b(ack)
        # then move on to positive responses
        # right now, only 200 OK will be handled
        else:
            if "Record-Route" in response.headers.keys():
                self.send_b(
                    ack,
                    response.headers["Record-Route"][0]["address"],
                    response.headers["Record-Route"][0]["port"],
                )
            else:
                self.send_b(
                    ack,
                    response.headers["Contact"]["host"],
                    response.headers["Contact"]["port"],
                )

    def bye(self, request: SIPMessage) -> None:
        if TRACE:
            ic()
        message = self.gen_bye(request)
        # TODO: Handle bye to server vs. bye to connected client
        self.recvLock.acquire()
        self.send_b(
            message,
            request.headers["Contact"]["host"],
            request.headers["Contact"]["port"],
        )
        response = SIPMessage(self.recv_b())
        if response.status == SIPStatus(401):
            #  Requires password
            auth = self.gen_authorization(response)
            message = message.replace("\r\nContent-Length", f"\r\n{auth}Content-Length")
            # TODO: Handle bye to server vs. bye to connected client
            self.send_b(
                message,
                request.headers["Contact"]["host"],
                request.headers["Contact"]["port"],
            )
        else:
            debug("Received not a 401 on bye:")
            debug(response.summary())
        self.recvLock.release()

    def deregister(self) -> bool:
        if TRACE:
            ic()
        self.recvLock.acquire()
        first_register_request = self.gen_register(deregister=True)
        self.send_b(first_register_request)

        self.out.setblocking(False)

        ready = select.select([self.out], [], [], self.register_timeout)
        if ready[0]:
            resp = self.recv_b()
        else:
            raise TimeoutError("Deregistering on SIP Server timed out")

        response = SIPMessage(resp)
        response = self.trying_timeout_check(response)

        if response.status == SIPStatus(401):
            # Unauthorized, likely due to being password protected.
            register_request = self.gen_register(response, deregister=True)
            self.send_b(register_request)
            ready = select.select([self.s], [], [], self.register_timeout)
            if ready[0]:
                resp = self.recv_b()
                response = SIPMessage(resp)
                if response.status == SIPStatus(401):
                    # At this point, it's reasonable to assume that
                    # this is caused by invalid credentials.
                    debug("Unauthorized")
                    raise InvalidAccountInfoError(
                        "Invalid Username or "
                        + "Password for SIP server "
                        + f"{self.server}:"
                        + f"{self.bind_port}"
                    )
                elif response.status == SIPStatus(400):
                    # Bad Request
                    # TODO: implement
                    # TODO: check if broken connection can be brought back
                    # with new urn:uuid or reply with expire 0
                    self._handle_bad_request()
            else:
                raise TimeoutError("Deregistering on SIP Server timed out")

        if response.status == SIPStatus(500):
            self.recvLock.release()
            time.sleep(5)
            return self.deregister()

        if response.status == SIPStatus.OK:
            self.recvLock.release()
            return True
        self.recvLock.release()
        return False

    def register(self) -> bool:
        if TRACE:
            ic()
        self.recvLock.acquire()
        first_register_request = self.gen_register()
        self.send_b(first_register_request)

        self.out.setblocking(False)

        ready = select.select([self.out], [], [], self.register_timeout)
        if ready[0]:
            resp = self.recv_b()
        else:
            raise TimeoutError("Registering on SIP Server timed out")

        response = SIPMessage(resp)
        response = self.trying_timeout_check(response)
        first_response = response

        if response.status == SIPStatus(400):
            # Bad Request
            # TODO: implement
            # TODO: check if broken connection can be brought back
            # with new urn:uuid or reply with expire 0
            self._handle_bad_request()

        if response.status == SIPStatus(401):
            # Unauthorized, likely due to being password protected.
            regRequest = self.gen_register(response)
            self.send_b(regRequest)
            ready = select.select([self.s], [], [], self.register_timeout)
            if ready[0]:
                resp = self.recv_b()
                response = SIPMessage(resp)
                response = self.trying_timeout_check(response)
                if response.status == SIPStatus(401):
                    # At this point, it's reasonable to assume that
                    # this is caused by invalid credentials.
                    debug("=" * 50)
                    debug("Unauthorized, SIP Message Log:\n")
                    debug("SENT")
                    debug(firstRequest)
                    debug("\nRECEIVED")
                    debug(first_response.summary())
                    debug("\nSENT (DO NOT SHARE THIS PACKET)")
                    debug(regRequest)
                    debug("\nRECEIVED")
                    debug(response.summary())
                    debug("=" * 50)
                    raise InvalidAccountInfoError(
                        "Invalid Username or "
                        + "Password for SIP server "
                        + f"{self.server}:"
                        + f"{self.bind_port}"
                    )
                elif response.status == SIPStatus(400):
                    # Bad Request
                    # TODO: implement
                    # TODO: check if broken connection can be brought back
                    # with new urn:uuid or reply with expire 0
                    self._handle_bad_request()
            else:
                raise TimeoutError("Registering on SIP Server timed out")

        if response.status == SIPStatus(407):
            # Proxy Authentication Required
            # TODO: implement
            debug("Proxy auth required")

        # TODO: This must be done more reliable
        if response.status not in [
            SIPStatus(400),
            SIPStatus(401),
            SIPStatus(407),
        ]:
            # Unauthorized
            if response.status == SIPStatus(500):
                self.recvLock.release()
                time.sleep(5)
                return self.register()
            else:
                # TODO: determine if needed here
                self.parse_message(response)

        debug(response.summary())
        debug(response.raw)

        self.recvLock.release()
        if response.status == SIPStatus.OK:
            if self.NSD:
                # self.subscribe(response)
                self.registerThread = Timer(self.default_expires - 5, self.register)
                self.registerThread.name = (
                    "SIP Register CSeq: " + f"{self.register_counter.x}"
                )
                self.registerThread.start()
            return True
        else:
            raise InvalidAccountInfoError(
                "Invalid Username or Password for "
                + f"SIP server {self.server}:"
                + f"{self.bind_port}"
            )

    def _handle_bad_request(self) -> None:
        if TRACE:
            ic()
        # Bad Request
        # TODO: implement
        # TODO: check if broken connection can be brought back
        # with new urn:uuid or reply with expire 0
        debug("Bad Request")

    # def subscribe(self, lastresponse: SIPMessage) -> None:
    #     # TODO: check if needed and maybe implement fully
    #     self.recvLock.acquire()
    #
    #     subRequest = self.gen_subscribe(lastresponse)
    #     self.send_b(subRequest)
    #
    #     response = SIPMessage(self.recv_b())
    #
    #     debug(f'Got response to subscribe: {str(response.heading, "utf8")}')
    #
    #     self.recvLock.release()

    def trying_timeout_check(self, response: SIPMessage) -> SIPMessage:
        """
        Some servers need time to process the response.
        When this happens, the first response you get from the server is
        SIPStatus.TRYING. This while loop tries checks every second for an
        updated response. It times out after 30 seconds.
        """
        if TRACE:
            ic()
        start_time = time.monotonic()
        while response.status == SIPStatus.TRYING:
            if (time.monotonic() - start_time) >= self.register_timeout:
                raise TimeoutError(
                    f"Waited {self.register_timeout} seconds but server is "
                    + "still TRYING"
                )

            ready = select.select([self.s], [], [], self.register_timeout)
            if ready[0]:
                resp = self.recv_b()
            response = SIPMessage(resp)
        return response
