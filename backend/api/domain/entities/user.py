from datetime import datetime
from typing import Optional
from beanie import Indexed, PydanticObjectId
from pydantic import EmailStr
from api.common.enums.gender import Gender
from api.domain.entities.api_base_model import ApiBaseModel


class User(ApiBaseModel):
    first_name: str
    last_name: str
    email: EmailStr = Indexed(EmailStr, unique=True)
    gender: Gender = Indexed(str)
    role_id: Optional[PydanticObjectId] = None
    is_active: bool
    activated_at: Optional[datetime] = None
    # Last time a (re)send of the account activation email went out for
    # this user. send_activation_email() throttles repeats within the
    # cooldown window; None means no resend has been recorded (existing
    # documents predate the field and proceed as before).
    activation_email_sent_at: Optional[datetime] = None
    # Last time a change-email confirmation email went out for this
    # user. change_email_request() throttles repeats within the
    # cooldown window; None means no request has been recorded
    # (existing documents predate the field and proceed as before).
    change_email_sent_at: Optional[datetime] = None
    image_url: Optional[str] = None
    password: str  # hashed password
    sso_provider_id: Optional[str] = None

    async def to_serializable_dict(self):
        base_doc = await super().to_serializable_dict()
        return {
            **base_doc,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "gender": str(self.gender.value),
            "role_id": str(self.role_id) if self.role_id else None,
            "is_active": self.is_active,
            "activated_at": str(self.activated_at) if self.activated_at else None,
            "activation_email_sent_at": str(self.activation_email_sent_at) if self.activation_email_sent_at else None,
            "change_email_sent_at": str(self.change_email_sent_at) if self.change_email_sent_at else None,
            "image_url": str(self.image_url) if self.image_url else None,
            "sso_provider_id": self.sso_provider_id if self.sso_provider_id else None
        }

    class Settings:
        name = "users"
        indexes = [
            "email",
            "role_id",
            "is_active",
        ]
