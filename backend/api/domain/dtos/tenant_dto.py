
from typing import  List, Literal, Optional
from pydantic import BaseModel, EmailStr, Field, model_validator

from api.common.enums.gender import Gender
from api.domain.entities.tenant import CustomDomain, Subdomain
from api.domain.enum.feature import Feature as FeatureEnum

class FeatureDto(BaseModel):
    name: FeatureEnum
    enabled: bool

class TenantDto(BaseModel):
    id: Optional[str]
    name: str
    subdomain: Optional[str] | None
    is_active: bool
    custom_domain: Optional[str] | None
    custom_domain_status: Literal["active", "failed", "activation-progress"] = "failed"
    features: List[FeatureDto] = []
    subscription_id: Optional[str] | None


class CreateTenantDto(BaseModel):
    # The UI sends the subdomain as the tenant name (create-new-tenant
    # dialog) and the SSO/register auto-creation path sends the
    # subdomain's first label, so every legitimate name is non-empty;
    # an empty name from a direct API call would otherwise persist a
    # nameless tenant shown in tenant lists. min_length=1 rejects it
    # (422) before any creation, matching the first/last-name caps
    # added to this DTO. The response DTO is deliberately left uncapped
    # so a pre-existing nameless record can still be read.
    name: str = Field(min_length=1)
    subdomain: Subdomain
    admin_email: EmailStr
    admin_password: str
    first_name: str = Field(min_length=1)
    last_name: str = Field(min_length=1)
    gender: Gender

    @model_validator(mode="after")
    def normalize_names(self):
        # Normalize before use: the create-tenant dialog trims
        # first/last name (and the subdomain validator already strips
        # the subdomain), but a direct API client bypasses the form —
        # so a whitespace-only name/first_name/last_name passed
        # min_length=1 and persisted verbatim, leaving a blank tenant
        # name in tenant lists and a blank admin first/last name on
        # the seeded admin user (tenant_endpoint forwards these
        # fields to CreateUserDto for the post-creation worker). The
        # same deferred-failure class as the role DTO validator
        # (iteration 1272). A value trimming to empty is rejected
        # outright (422) instead of persisting a blank; padded values
        # are stored trimmed. admin_password is deliberately NOT
        # trimmed (credential semantics — surrounding spaces may be
        # significant), admin_email is already validated by EmailStr,
        # and the subdomain already strips via its AfterValidator, so
        # none of those are touched. Seed/SSO/register values carry no
        # surrounding whitespace, so no legitimate flow is affected.
        # The response DTO is deliberately left alone so a
        # pre-existing blank record can still be read.
        for field_name in ("name", "first_name", "last_name"):
            value = getattr(self, field_name)
            if isinstance(value, str):
                trimmed = value.strip()
                if not trimmed:
                    raise ValueError(f"{field_name} must not be blank")
                setattr(self, field_name, trimmed)
        return self

class TenantListDto(BaseModel):
    tenants: List[TenantDto]
    skip: int
    limit: int
    total: int
    has_previous: bool
    has_next: bool


class CreateTenantResponseDto(BaseModel):
    id: str


class SubdomainAvailabilityDto(BaseModel):
    is_available: bool

class UpdateTenantDto(BaseModel):
    is_active: Optional[bool] | None = None
    custom_domain: Optional[CustomDomain] | None = None
    subscription_id: Optional[str] | None = None


class UpdateTenantResponseDto(BaseModel):
   message: str

