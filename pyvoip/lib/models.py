import uuid
from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class PhoneEvent(str, Enum):
    STATE_CHANGED = "STATE_CHANGED"


class CallState(str, Enum):
    DIALING = "DIALING"
    RINGING = "RINGING"
    ANSWERED = "ANSWERED"
    ENDED = "ENDED"


class PhoneStatus(str, Enum):
    OFFLINE = "OFFLINE"  # Phone was not instantiated.
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


class PhoneEventState(BaseModel):
    event: PhoneEvent
    states: dict[Literal["original", "new"], PhoneStatus]


class Message(BaseModel):
    """
    A simple message class to be used for sending messages to the
    controlling application.
    """

    id: uuid.UUID = uuid.uuid4()
    timestamp: datetime = Field(default_factory=datetime.now)
    scope: Literal["VoIPPhone", "VoIPCall"]
    event: PhoneEventState

    def __str__(self) -> str:
        return dict(self)


class Credentials(BaseModel):
    user: str
    auth_user: Optional[str] = None
    password: str
    server: str
    realm: Optional[str] = None
