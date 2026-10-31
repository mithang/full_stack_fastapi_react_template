
from typing import Optional
from pydantic import BaseModel, EmailStr, model_validator

from api.domain.dtos.role_dto import RoleDto
from api.domain.dtos.subcription_plan_dto import SubscriptionPlanDto
from api.domain.dtos.user_dto import UserDto


class PasswordResetRequestDto(BaseModel):
    email: EmailStr

class PasswordResetConfirmRequestDto(BaseModel):
    new_password: str

class PasswordResetResponseDto(BaseModel):
    message: str

class ChangeEmailRequestDto(BaseModel):
    new_email: EmailStr

class ChangeEmailConfirmRequestDto(BaseModel):
    token: str

    @model_validator(mode="after")
    def normalize_token(self):
        # Trim before verification: the endpoint passes this token
        # verbatim to JWT verification, so a token pasted from an email
        # with surrounding whitespace fails with the generic "Email
        # change confirmation failed" error instead of confirming — the
        # same deferred-failure class as the other identifier trims in
        # this sweep. A JWT cannot legitimately carry surrounding
        # whitespace, and a whitespace-only token still fails
        # verification afterwards, so the error path is unchanged.
        if isinstance(self.token, str):
            self.token = self.token.strip()
        return self

class ChangeEmailResponseDto(BaseModel):
    message: str

class MeResponseDto(UserDto):
    role: RoleDto
    subscription: Optional[SubscriptionPlanDto] | None


class MagicLinkResponseDto(BaseModel):
    message: str
