import audioop
import io
import random
import socket
import threading
import time
import warnings
from enum import Enum
from threading import Timer
from typing import Callable, Optional

from icecream import ic
from pydantic import BaseModel
from rich import print

import pyvoip

__all__ = [
    "add_bytes",
    "byte_to_bits",
    "DynamicPayloadType",
    "PayloadType",
    "RTPParseError",
    "RTPProtocol",
    "RTPPacketManager",
    "RTPClient",
    "TransmitType",
]


debug = pyvoip.debug
TRACE = pyvoip.TRACE


def byte_to_bits(byte: bytes) -> str:
    nbyte = bin(ord(byte)).lstrip("-0b")
    nbyte = ("0" * (8 - len(nbyte))) + nbyte
    return nbyte


def add_bytes(byte_string: bytes) -> int:
    binary = ""
    for byte in byte_string:
        nbyte = bin(byte).lstrip("-0b")
        nbyte = ("0" * (8 - len(nbyte))) + nbyte
        binary += nbyte
    return int(binary, 2)


class DynamicPayloadType(Exception):
    pass


class RTPParseError(Exception):
    pass


class DTMFEventPayload(BaseModel):
    payload: bytes = b""
    marker: bool = False
    update_sequence: bool = True
    update_timestamp: bool = True


class DTMFEvent(BaseModel):
    event: list[DTMFEventPayload] = []

    def add_payload(self, payload: DTMFEventPayload) -> None:
        self.event.append(payload)


class RTPProtocol(str, Enum):
    UDP = "udp"
    AVP = "RTP/AVP"
    SAVP = "RTP/SAVP"


class TransmitType(str, Enum):
    RECVONLY = "recvonly"
    SENDRECV = "sendrecv"
    SENDONLY = "sendonly"
    INACTIVE = "inactive"

    def __str__(self):
        return self.value


class PayloadType(Enum):
    def __new__(
        cls,
        value: int | str,
        clock: int = 0,
        channel: int = 0,
        description: str = "",
    ):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.rate = clock
        obj.channel = channel
        obj.description = description
        return obj

    @property
    def rate(self) -> int:
        return self._rate

    @rate.setter
    def rate(self, value: int) -> None:
        self._rate = value

    @property
    def channel(self) -> int:
        return self._channel

    @channel.setter
    def channel(self, value: int) -> None:
        self._channel = value

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str) -> None:
        self._description = value

    def __int__(self) -> int:
        try:
            return int(self.value)
        except ValueError:
            pass
        raise DynamicPayloadType(
            self.description + " is a dynamically assigned payload"
        )

    def __str__(self) -> str:
        if isinstance(self.value, int):
            return self.description
        return str(self.value)

    # Audio
    PCMU = 0, 8000, 1, "PCMU"
    GSM = 3, 8000, 1, "GSM"
    G723 = 4, 8000, 1, "G723"
    DVI4_8000 = 5, 8000, 1, "DVI4"
    DVI4_16000 = 6, 16000, 1, "DVI4"
    LPC = 7, 8000, 1, "LPC"
    PCMA = 8, 8000, 1, "PCMA"
    G722 = 9, 8000, 1, "G722"
    L16_2 = 10, 44100, 2, "L16"
    L16 = 11, 44100, 1, "L16"
    QCELP = 12, 8000, 1, "QCELP"
    CN = 13, 8000, 1, "CN"
    # MPA channel varries, should be defined in the RTP packet.
    MPA = 14, 90000, 0, "MPA"
    G728 = 15, 8000, 1, "G728"
    DVI4_11025 = 16, 11025, 1, "DVI4"
    DVI4_22050 = 17, 22050, 1, "DVI4"
    G729 = 18, 8000, 1, "G729"

    # Video
    CELB = 25, 90000, 0, "CelB"
    JPEG = 26, 90000, 0, "JPEG"
    NV = 28, 90000, 0, "nv"
    H261 = 31, 90000, 0, "H261"
    MPV = 32, 90000, 0, "MPV"
    # MP2T is both audio and video per RFC 3551 July 2003 5.7
    MP2T = 33, 90000, 1, "MP2T"
    H263 = 34, 90000, 0, "H263"

    # Non-codec
    EVENT = 101, 8000, 0, "telephone-event"
    # EVENT = "telephone-event", 8000, 0, "telephone-event"
    UNKNOWN = "UNKNOWN", 0, 0, "UNKNOWN CODEC"


class RTPPacketManager:
    """
    This class is responsible for managing the RTP packets.
    There is one instance for sending and one for receiving.
    Buffer actually works as a FIFO queue or stack.
    """

    def __init__(self):
        if TRACE:
            ic()
        self.offset = 4294967296
        """
        The largest number storable in 4 bytes + 1. This will ensure the
        offset adjustment in self.write(offset, data) works.
        """
        self.buffer = io.BytesIO()
        self.bufferLock = threading.Lock()
        self.log = {}
        self.rebuilding = False

    def read(self, length: int = 160) -> bytes:
        # This acts functionally as a lock while the buffer is being rebuilt.
        while self.rebuilding:
            time.sleep(0.01)
        self.bufferLock.acquire()
        packet = self.buffer.read(length)

        # If the packet is too small, pad it with 0x80
        if len(packet) < length:
            packet = packet + (b"\x80" * (length - len(packet)))
        # else:
        #     raise RTPParseError("Packet is too large")
        self.bufferLock.release()
        return packet

    def rebuild(self, reset: bool, offset: int = 0, data: bytes = b"") -> None:
        self.rebuilding = True
        if reset:
            self.log = {}
            self.log[offset] = data
            self.buffer = io.BytesIO(data)
        else:
            bufferloc = self.buffer.tell()
            self.buffer = io.BytesIO()
            for pkt in self.log:
                self.write(pkt, self.log[pkt])
            self.buffer.seek(bufferloc, 0)
        self.rebuilding = False

    def write(self, offset: int, data: bytes) -> None:
        if TRACE:
            ic()
        self.bufferLock.acquire()
        self.log[offset] = data
        bufferloc = self.buffer.tell()
        if offset < self.offset:
            """
            If the new timestamp is over 100,000 bytes before the
            earliest, erase the buffer.  This will stop memory errors.
            """
            reset = abs(offset - self.offset) >= 100000
            self.offset = offset
            self.bufferLock.release()
            """
            Rebuilds the buffer if something before the earliest
            timestamp comes in, this will stop overwritting.
            """
            self.rebuild(reset, offset, data)
            return
        offset = offset - self.offset
        self.buffer.seek(offset, 0)
        self.buffer.write(data)
        self.buffer.seek(bufferloc, 0)
        self.bufferLock.release()


class RTPMessage:
    def __init__(self, data: bytes, assoc: dict[int, PayloadType]):
        if TRACE:
            ic()
        self.RTPCompatibleVersions = pyvoip.RTPCompatibleVersions
        self.assoc = assoc
        # Setting defaults to stop mypy from complaining
        self.version = 0
        self.padding = False
        self.extension = False
        self.CC = 0
        self.marker = False
        self.payload_type = PayloadType.UNKNOWN
        self.sequence = 0
        self.timestamp = 0
        self.SSRC = 0

        self.parse(data)

    def summary(self) -> str:
        if TRACE:
            ic()
        data = ""
        data += f"Version: {self.version}\n"
        data += f"Padding: {self.padding}\n"
        data += f"Extension: {self.extension}\n"
        data += f"CC: {self.CC}\n"
        data += f"Marker: {self.marker}\n"
        data += f"Payload Type: {self.payload_type} " + f"({self.payload_type.value})\n"
        data += f"Sequence Number: {self.sequence}\n"
        data += f"Timestamp: {self.timestamp}\n"
        data += f"SSRC: {self.SSRC}\n"
        return data

    def parse(self, packet: bytes) -> None:
        if TRACE:
            ic()
        byte = byte_to_bits(packet[0:1])
        self.version = int(byte[0:2], 2)
        if self.version not in self.RTPCompatibleVersions:
            raise RTPParseError(f"RTP Version {self.version} not compatible.")
        if self.version == 0:
            # this is STUN protocol MUXED with RTP so just ignore it
            return
        self.padding = bool(int(byte[2], 2))
        self.extension = bool(int(byte[3], 2))
        self.CC = int(byte[4:], 2)

        byte = byte_to_bits(packet[1:2])
        self.marker = bool(int(byte[0], 2))

        pt = int(byte[1:], 2)
        if pt in self.assoc:
            self.payload_type = self.assoc[pt]
        else:
            try:
                self.payload_type = PayloadType(pt)
                e = False
            except ValueError:
                e = True
            if e:
                raise RTPParseError(f"RTP Payload type {pt} not found.")

        self.sequence = add_bytes(packet[2:4])
        self.timestamp = add_bytes(packet[4:8])
        self.SSRC = add_bytes(packet[8:12])

        self.CSRC = []

        i = 12
        for x in range(self.CC):
            self.CSRC.append(packet[i : i + 4])
            i += 4

        if self.extension:
            pass

        self.payload = packet[i:]


class RTPClient:
    def __init__(
        self,
        assoc: dict[int, PayloadType],
        in_ip: str,
        in_port: int,
        out_ip: str,
        out_port: int,
        sendrecv: TransmitType,
        dtmf: Optional[Callable[[str], None]] = None,
    ):
        if TRACE:
            ic()
        self.NSD = True
        # Example: {0: PayloadType.PCMU, 101: PayloadType.EVENT}
        self.assoc = assoc
        debug("Selecting audio codec for transmission")
        for m in assoc:
            try:
                if int(assoc[m]) is not None:
                    debug(f"Selected {assoc[m]}")
                    """
                    Select the first available actual codec to encode with.
                    TODO: will need to change if video codecs
                    are ever implemented.
                    """
                    self.preference = assoc[m]
                    break
            except Exception:
                debug(f"{assoc[m]} cannot be selected as an audio codec")

        self.in_ip = in_ip
        self.in_port = in_port
        self.out_ip = out_ip
        self.out_port = out_port

        self.dtmf = dtmf

        self.pmout = RTPPacketManager()  # To Send
        self.pmin = RTPPacketManager()  # Received
        self.outOffset = random.randint(1, 5000)

        self.outSequence = random.randint(1, 100)
        self.outTimestamp = random.randint(1, 10000)
        self.outSSRC = random.randint(1000, 65530)
        self._outgoing_dtmf: list[str] = []  # A container for DTMF events
        self._preference = PayloadType.UNKNOWN  # Initial value of _preference

    @property
    def outgoing_dtmf(self) -> list[str]:
        if TRACE:
            ic()
        return self._outgoing_dtmf

    @outgoing_dtmf.setter
    def outgoing_dtmf(self, value: list[str]) -> None:
        if TRACE:
            ic()
        self._outgoing_dtmf = value

    def start(self) -> None:
        if TRACE:
            ic()
        self.sin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sout = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sin.bind((self.in_ip, self.in_port))
        self.sin.setblocking(False)

        r = Timer(0, self.recv)
        r.name = "RTP Receiver"
        r.start()
        t = Timer(0, self.transmit_audio)
        t.name = "RTP Transmitter"
        t.start()

    def stop(self) -> None:
        if TRACE:
            ic()
        self.NSD = False
        self.sin.close()
        self.sout.close()

    def read(self, length: int = 160, blocking: bool = True) -> bytes:
        if not blocking:
            return self.pmin.read(length)
        packet = self.pmin.read(length)
        while packet == (b"\x80" * length) and self.NSD:
            time.sleep(0.01)
            packet = self.pmin.read(length)
        return packet

    def write(self, data: bytes) -> None:
        self.pmout.write(self.outOffset, data)
        self.outOffset += len(data)

    def recv(self) -> None:
        while self.NSD:
            try:
                packet = self.sin.recv(8192)
                self.parse_packet(packet)
            except BlockingIOError:
                time.sleep(0.01)
            except RTPParseError as e:
                debug(str(e))
            except OSError:
                pass

    def transmit_audio(self) -> None:
        """
        This method constructs RTP packets from encoded audio data and
        transmits them to the remote host.
        When there is content in self.outgoing_dtmf list, it pauses
        and jumps to separate self.transmit_dtmf method to handle
        the event. When the event is finished, it resumes transmitting
        audio.


        Returns
        -------
        None
        """
        while self.NSD:
            if self.outgoing_dtmf:
                self.transmit_dtmf()
            last_sent = time.monotonic_ns()
            payload = self.pmout.read()
            payload = self.encode_packet(payload)
            packet = b"\x80"  # RFC 1889 V2 No Padding Extension or CC.
            packet += chr(int(self.preference)).encode("utf8")
            try:
                packet += self.outSequence.to_bytes(2, byteorder="big")
            except OverflowError:
                self.outSequence = 0
            try:
                packet += self.outTimestamp.to_bytes(4, byteorder="big")
            except OverflowError:
                self.outTimestamp = 0
            packet += self.outSSRC.to_bytes(4, byteorder="big")
            packet += payload

            # debug(payload)

            try:
                self.sout.sendto(packet, (self.out_ip, self.out_port))
            except OSError:
                warnings.warn(
                    "RTP Packet failed to send!",
                    RuntimeWarning,
                    stacklevel=2,
                )

            self.outSequence += 1
            self.outTimestamp += len(payload)
            # Calculate how long it took to generate this packet.
            # Then how long we should wait to send the next, then devide by 2.
            delay = (1 / self.preference.rate) * 160
            sleep_time = max(
                0, delay - ((time.monotonic_ns() - last_sent) / 1000000000)
            )
            time.sleep(sleep_time / self.trans_delay_reduction)

    def transmit_dtmf(self) -> None:
        """
        This method handles sending the DTMF events to the remote host.
        It works the same as transmit_audio, but it uses the DTMF
        generator to construct the RTP packets.


        Returns
        -------
        None
        """
        if TRACE:
            ic()
        # take the first recorded event
        event = self.outgoing_dtmf.pop(0)
        # generate payloads for the event
        dtmf_event = self.gen_telephone_event(event)

        # store the original preference
        self._preference = self.preference
        self.preference = PayloadType.EVENT

        # take the global timestamp and use it locally
        # as no DTMF packet increases it,
        # but the following audio packets  take the
        # gap into account
        timestamp = self.outTimestamp

        # iterate over individual payloads/packets
        for dtmf_event_payload in dtmf_event.event:
            last_sent = time.monotonic_ns()

            print(
                f"[bright_black]Sending DTMF: [/bright_black][red]{event}[/red]. "
                f"[bright_black]Payload: [/bright_black][green]{dtmf_event_payload}[/green]"
            )
            packet = b"\x80"  # RFC 1889 V2 No Padding Extension or CC.

            # add 128 which equals to 1000 0000 in binary
            # as a marker for the firts packet of the DTMF event
            if dtmf_event_payload.marker:
                packet += (int(self.preference) + 128).to_bytes(1, byteorder="big")
            else:
                packet += int(self.preference).to_bytes(1, byteorder="big")

            # sequence number
            try:
                packet += self.outSequence.to_bytes(2, byteorder="big")
            except OverflowError:
                self.outSequence = 0
            try:
                packet += self.outTimestamp.to_bytes(4, byteorder="big")
            except OverflowError:
                self.outTimestamp = 0
            packet += self.outSSRC.to_bytes(4, byteorder="big")
            packet += dtmf_event_payload.payload

            # debug(payload)

            try:
                self.sout.sendto(packet, (self.out_ip, self.out_port))
            except OSError:
                warnings.warn(
                    "RTP Packet failed to send!",
                    RuntimeWarning,
                    stacklevel=2,
                )

            # if there is a mark to update the sequence in the payload
            # then update it.
            # End of event packets do not update sequence.
            if dtmf_event_payload.update_sequence:
                self.outSequence += 1

            # if there is a mark to update the timestamp in the payload
            # then update it. Only the first packet of the event does it.

            if dtmf_event_payload.update_timestamp:
                timestamp += 160  # this is default timestamp clock of PCMA/PCMU, should be parameterized
            # Calculate how long it took to generate this packet.
            # Then how long we should wait to send the next, then devide by 2.
            delay = (1 / self.preference.rate) * 160
            sleep_time = max(
                0, delay - ((time.monotonic_ns() - last_sent) / 1000000000)
            )
            time.sleep(sleep_time / self.trans_delay_reduction)

        # set the preference back to the original one
        self.preference = self._preference
        self.outTimestamp = timestamp
        return

    @property
    def trans_delay_reduction(self) -> float:
        reduction = pyvoip.TRANSMIT_DELAY_REDUCTION + 1
        return reduction if reduction else 1.0

    def parse_packet(self, packet: bytes) -> None:
        msg = RTPMessage(packet, self.assoc)
        if msg.payload_type == PayloadType.PCMU:
            self.parse_pcmu(msg)
        elif msg.payload_type == PayloadType.PCMA:
            self.parse_pcma(msg)
        elif msg.payload_type == PayloadType.EVENT:
            self.parse_telephone_event(msg)
        else:
            raise RTPParseError("Unsupported codec (parse): " + str(msg.payload_type))

    def encode_packet(self, payload: bytes) -> bytes:
        if self.preference == PayloadType.PCMU:
            return self.encode_pcmu(payload)
        elif self.preference == PayloadType.PCMA:
            return self.encode_pcma(payload)
        else:
            raise RTPParseError("Unsupported codec (encode): " + str(self.preference))

    def parse_pcmu(self, packet: RTPMessage) -> None:
        data = audioop.ulaw2lin(packet.payload, 1)
        data = audioop.bias(data, 1, 128)
        self.pmin.write(packet.timestamp, data)

    def encode_pcmu(self, packet: bytes) -> bytes:
        packet = audioop.bias(packet, 1, -128)
        packet = audioop.lin2ulaw(packet, 1)
        return packet

    def parse_pcma(self, packet: RTPMessage) -> None:
        data = audioop.alaw2lin(packet.payload, 1)
        data = audioop.bias(data, 1, 128)
        self.pmin.write(packet.timestamp, data)

    def encode_pcma(self, packet: bytes) -> bytes:
        packet = audioop.bias(packet, 1, -128)
        packet = audioop.lin2alaw(packet, 1)
        return packet

    def parse_telephone_event(self, packet: RTPMessage) -> None:
        key = [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "*",
            "#",
            "A",
            "B",
            "C",
            "D",
        ]

        payload = packet.payload
        event = key[payload[0]]
        """
        Commented out the following due to F841 (Unused variable).
        Might use at some point though, so I'm saving the logic.

        byte = byte_to_bits(payload[1:2])
        end = (byte[0] == '1')
        volume = int(byte[2:], 2)
        """

        if packet.marker:
            if self.dtmf is not None:
                self.dtmf(event)

    def gen_telephone_event(
        self,
        event: str,
        event_repetition: int = 4,
        end_of_event_retransmission: int = 3,
        timestamp_len: int = 160,
        volume: int = 10,
    ) -> DTMFEvent:
        """
        Generate sequence of payloads together with mark that are used by the RTP.
        Payloads are compliant to RFC 4733 specification for DTMF events.


        Parameters
        ----------
        event: str
            String representation of DTMF code.
        event_repetition: int
            How many times should the event be repeated. This means how many
            RTP packets will be generated without the end of event mark.
        end_of_event_retransmission: int
            How many times should the end of event be repeated. This means how many
            RTP packets will be generated with the end of event mark.
        timestamp_len: int
            The duration of Timestamp unit. For PCM, it is usually 160 (with packetization of 20ms).
            For other codecs, it might be different.
        volume
            Volume of the event. It is a 6-bit unsigned integer. The value 0 is
            silent, and the value 63 is the loudest. The default value is 10.

        Returns
        -------
        DTMFEvent
            Basically a list of payloads and marks.

        Raises
        ------
        ValueError:
            If the event is not between 0 and 15. Meaning, it is not a standard DTMF code.
        """
        if TRACE:
            ic()

        RESERVED = 0

        event_codes = {
            "0": 0,
            "1": 1,
            "2": 2,
            "3": 3,
            "4": 4,
            "5": 5,
            "6": 6,
            "7": 7,
            "8": 8,
            "9": 9,
            "*": 10,
            "#": 11,
            "A": 12,
            "B": 13,
            "C": 14,
            "D": 15,
        }

        if event not in event_codes.keys():
            raise ValueError(
                f"DTMF event must be between 0 and 15. Got {event} instead."
            )

        dtmf_event = DTMFEvent()

        # First generate the event payloads
        end_of_event = 0
        for idx, event_repetition in enumerate(range(event_repetition)):
            duration = (event_repetition + 1) * timestamp_len
            dtmf_event_payload = DTMFEventPayload(
                payload=int(
                    f"{event_codes[event]}{end_of_event:1b}{RESERVED:1b}{volume:>06b}{duration:>016b}",
                    2,
                ).to_bytes(4, "big"),
                marker=True if idx == 0 else False,
                update_sequence=True,
                update_timestamp=True,
            )
            dtmf_event.add_payload(dtmf_event_payload)

        # Now generate End of event and repeat it
        end_of_event = 1
        for idx, event_repetition in enumerate(range(end_of_event_retransmission)):
            if idx == 0:
                # use previously generated duration
                # and add one more length of timestamp
                # the rest of the packets are just
                # repetitions
                duration = duration + timestamp_len
            dtmf_event_payload = DTMFEventPayload(
                payload=int(
                    f"{event_codes[event]}{end_of_event:1b}{RESERVED:1b}{volume:>06b}{duration:>016b}",
                    2,
                ).to_bytes(4, "big"),
                marker=False,
                update_sequence=True if idx == 0 else False,
                update_timestamp=False,
            )
            dtmf_event.add_payload(dtmf_event_payload)

        return dtmf_event
