import socket
import ssl
from typing import Callable, Optional

SOCKETS = socket.socket | ssl.SSLSocket


KEY_PASSWORD = Optional[
    bytes
    | bytearray
    | str
    | Callable[[], bytes]
    | Callable[[], bytearray]
    | Callable[[], str]
]
