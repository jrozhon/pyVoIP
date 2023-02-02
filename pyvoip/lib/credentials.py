from typing import Optional

from pydantic import BaseModel


class Credentials(BaseModel):
    user: str
    auth_user: Optional[str] = None
    password: str
    server: str
    realm: Optional[str] = None
