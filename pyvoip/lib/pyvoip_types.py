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


CREDENTIALS_DICT = dict[
    Optional[str],  # Server or None if default
    dict[
        Optional[str],  # Realm or None if default
        dict[
            Optional[str],  # To or None if default
            dict[str, str],  # Actual credentials
        ],
    ],
]
