from datetime import datetime
from beanie import PydanticObjectId
from pydantic import Field
from api.common.utils import get_utc_now
from api.domain.entities.api_base_model import ApiBaseModel
from pymongo import ASCENDING, IndexModel


class UserMagicLink(ApiBaseModel):
    user_id: PydanticObjectId
    token: str
    # default_factory, not a plain default: get_utc_now() as a plain default
    # is evaluated once at class definition, so every link constructed
    # without expires_at (the only construction site, the magic-link
    # repository) shared the server-start time. The TTL index expires
    # documents 900s after expires_at, so once the server had been up
    # more than 15 minutes, every new magic link was immediately
    # TTL-eligible and could vanish before it was used. Validation
    # relies on the TTL alone (no in-code expiry check), so this
    # default is the validity window.
    expires_at: datetime = Field(default_factory=get_utc_now)

    class Settings:
        name = "user_magic_links"

        indexes = [
            IndexModel(
                [("expires_at", ASCENDING)],
                expireAfterSeconds=900 # 15 minutes
            )
        ]