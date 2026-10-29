
from typing import  List, Literal, Optional
from pydantic import BaseModel, EmailStr, Field

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

