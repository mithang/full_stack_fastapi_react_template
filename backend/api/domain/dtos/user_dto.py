from typing import  List, Optional
from pydantic import BaseModel, EmailStr, Field, field_serializer, model_validator
from beanie import PydanticObjectId
from api.common.enums.gender import Gender



class BaseUserDto(BaseModel):
    first_name: str = Field(min_length=1)
    last_name: str = Field(min_length=1)
    email: EmailStr
    gender: Gender
    tenant_id: PydanticObjectId | None = None
    role_id: PydanticObjectId | None = None
    sso_provider_id: Optional[str] = None

    @model_validator(mode="after")
    def normalize_names(self):
        # Normalize before use: the create-user dialog, register form
        # and user-edit dialog all trim names, but a direct API client
        # bypasses the forms — so a whitespace-only first/last name
        # passed min_length=1 and persisted verbatim, leaving a blank
        # name in user lists, and a padded name persisted with its
        # padding (the same deferred-failure class as the tenant DTO
        # validator, iteration 1273, and the role DTO validator,
        # iteration 1272). This covers CreateUserDto (admin create,
        # register, tenant-admin worker payload, SSO signup, seeder).
        # A value trimming to empty is rejected outright (422)
        # instead of persisting a blank; padded values are stored
        # trimmed. The password is deliberately NOT trimmed
        # (credential semantics), the email is already validated by
        # EmailStr, and the response DTO is deliberately left alone
        # so a pre-existing blank record can still be read.
        for field_name in ("first_name", "last_name"):
            value = getattr(self, field_name)
            if isinstance(value, str):
                trimmed = value.strip()
                if not trimmed:
                    raise ValueError(f"{field_name} must not be blank")
                setattr(self, field_name, trimmed)
        return self

class CreateUserDto(BaseUserDto):
    password: str
    sub_domain: Optional[str] = None

    @field_serializer("tenant_id", "role_id")
    def serialize(v: PydanticObjectId | None) -> str | None:
        if isinstance(v, PydanticObjectId) and v is not None:
            return str(v)
        return None


class UpdateUserDto(BaseModel):
    first_name: Optional[str] = Field(default=None, min_length=1)
    last_name: Optional[str] = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def normalize_names(self):
        # Same class as BaseUserDto.normalize_names above, for the
        # update path (PUT /users/{id} and profile update): a
        # whitespace-only name passed min_length=1 and persisted
        # verbatim. None still means "leave unchanged" (partial
        # updates and internal role-only/image-only constructions),
        # and a provided value trimming to empty is rejected (422)
        # instead of persisting a blank; padded values are stored
        # trimmed.
        for field_name in ("first_name", "last_name"):
            value = getattr(self, field_name)
            if isinstance(value, str):
                trimmed = value.strip()
                if not trimmed:
                    raise ValueError(f"{field_name} must not be blank")
                setattr(self, field_name, trimmed)
        # Same deferred-failure class for role_id: update_user() passes
        # it verbatim to PydanticObjectId(), so a padded id failed
        # conversion and surfaced as a 404 for a role that exists
        # (the assign-role path got the same fix in iteration 1279).
        # None still means "leave unchanged"; a value trimming to
        # empty is rejected (422) instead of failing the lookup.
        if isinstance(self.role_id, str):
            trimmed_role = self.role_id.strip()
            if not trimmed_role:
                raise ValueError("role_id must not be blank")
            self.role_id = trimmed_role
        return self
    email: Optional[EmailStr] = None
    gender: Optional[Gender] = None
    image_url: Optional[str] = None
    role_id: Optional[str] = None
    is_active: Optional[bool] = None
    tenant_id: PydanticObjectId | None = None
    sso_provider_id: Optional[str] = None

class UserDto(BaseModel):
    id: str
    first_name: str
    last_name: str
    email: EmailStr
    gender: Gender
    role_id: Optional[str] = None
    is_active: bool
    activated_at: Optional[str] = None
    image_url: Optional[str] = None
    created_at: str
    updated_at: str
    tenant_id: Optional[str] = None
    sso_provider_id: Optional[str] = None


class UserListDto(BaseModel):
    users: List[UserDto]
    skip: int
    limit: int
    total: int
    has_previous: bool
    has_next: bool


class CreateUserResponseDto(BaseModel):
    id: str


class UserActivationRequestDto(BaseModel):
    token: str

    @model_validator(mode="after")
    def normalize_token(self):
        # Trim before verification: the /activate endpoint passes
        # this token verbatim to JWT verification, so a token pasted
        # from an email with surrounding whitespace fails with the
        # generic "Account activation failed" error instead of
        # activating — the same deferred-failure class as the
        # change-email confirmation token trim (iteration 1282).
        # A JWT cannot legitimately carry surrounding whitespace,
        # and a whitespace-only token still fails verification
        # afterwards, so the error path is unchanged.
        if isinstance(self.token, str):
            self.token = self.token.strip()
        return self

class UserResendActivationEmailRequestDto(BaseModel):
    email: EmailStr
    id: str
    first_name: str
    tenant_id: Optional[str] = None 

class UserProfileImageUpdateDto(BaseModel):
    image_url: str


class UserRoleUpdateRequestDto(BaseModel):
    # Both PATCH endpoints (assign_role / remove_role) take this DTO, and
    # a role id is always an existing role's id, never empty: an empty
    # value previously fell through to a role lookup (404) or a
    # role-mismatch error instead of failing at validation. Reject it
    # with FastAPI validation (422) before any service call, matching
    # the other min_length=1 request-DTO caps in this sweep.
    role_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def normalize_role_id(self):
        # min_length=1 rejects "" but not a whitespace-only value, so
        # " " still passed validation and failed only at the role
        # lookup (404) or the already-assigned / not-assigned string
        # comparison in the assign/remove endpoints, and a padded
        # real role id failed the same comparisons instead of
        # resolving. Role ids never carry surrounding whitespace, so
        # the value is stripped and a value trimming to empty is
        # rejected outright (422) before any service call, the same
        # deferred-failure class as the checkout/pricing/billing
        # DTO validators in this sweep.
        if isinstance(self.role_id, str):
            value = self.role_id.strip()
            if not value:
                raise ValueError("role_id must not be blank")
            self.role_id = value
        return self

