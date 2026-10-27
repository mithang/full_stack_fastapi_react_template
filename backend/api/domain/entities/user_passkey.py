
from typing import Literal, Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

from pymongo import ASCENDING, IndexModel

from api.common.utils import get_utc_now
from api.domain.entities.api_base_model import ApiBaseModel
from webauthn.helpers.structs import (
    AuthenticatorTransport
)
class Credential(BaseModel):
    credential_id: str
    public_key: str
    sigin_count: int
    transports: list[AuthenticatorTransport] = []
    created_at: datetime
    last_used_at: Optional[datetime] = None
    

class UserPasskey(ApiBaseModel):
    user_email: EmailStr
    credentials: list[Credential] = []
    class Settings:
        name = "user_passkeys"


class Challenges(ApiBaseModel):
    email: EmailStr
    type: Literal["registration", "authentication"] = "registration"
    challenge: str
    # default_factory, not a plain default: get_utc_now() as a plain default
    # is evaluated once at class definition, so every challenge constructed
    # without expires_at (the only construction site, save_challenge in the
    # passkey repository) shared the server-start time. The TTL index expires
    # documents 300s after expires_at, so once the server had been up more
    # than 5 minutes, every new challenge was immediately TTL-eligible and
    # could vanish before it was used, surfacing as "challenge expired".
    expires_at: datetime = Field(default_factory=get_utc_now)

    class Settings:
        name = "user_passkey_challenges"
        indexes = [
            IndexModel(
                [("expires_at", ASCENDING)],
                expireAfterSeconds=300  # Document expires 5 minutes after 'expired_at'
            )
        ]
    