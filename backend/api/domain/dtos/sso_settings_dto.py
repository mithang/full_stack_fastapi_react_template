from typing import Optional
from pydantic import BaseModel, Field, field_serializer, model_validator

from api.domain.entities.sso_settings import SSOProvider


def _normalize_sso_credentials(dto):
    # Normalize before validating and persisting: the web form trims
    # client_id (zod .trim()) but not client_secret, and direct API
    # clients bypass the form entirely — so a pasted client_id /
    # client_secret with surrounding whitespace, or a whitespace-only
    # client_id (which passes min_length=1), otherwise persisted
    # verbatim and only failed later at provider login time with a
    # generic OAuth error, the same deferred-failure class as the
    # storage-settings validator. OAuth client ids, secrets, and scope
    # tokens cannot legitimately carry leading/trailing whitespace.
    # Trimming cannot break the service's masked-credential round-trip:
    # a masked value has no surrounding whitespace, so it is unchanged.
    if isinstance(dto.client_id, str):
        dto.client_id = dto.client_id.strip()
        if not dto.client_id:
            raise ValueError("client_id must not be blank")
    if isinstance(dto.client_secret, str):
        dto.client_secret = dto.client_secret.strip()
    if isinstance(dto.scopes, list):
        dto.scopes = [s.strip() for s in dto.scopes if isinstance(s, str) and s.strip()]
    return dto


class SSOSettingsDto(BaseModel):
    enabled: bool
    provider: SSOProvider
    client_id: str
    client_secret: Optional[str] | None = None
    scopes: Optional[list[str]] = []
    redirect_uris: Optional[list[str]] = []

class CreateSSOSettingsDto(SSOSettingsDto):
    # The SSO form requires client_id (zod min(1)); an empty string would
    # otherwise persist and only fail later at provider login time.
    # client_secret is deliberately left as-is: the form allows it empty
    # (z.string().default(''), sent as null) for providers without one.
    client_id: str = Field(min_length=1)
    tenant_id: Optional[str] | None = None

    @model_validator(mode="after")
    def normalize_credentials(self):
        return _normalize_sso_credentials(self)

class UpdateSSOSettingsDto(BaseModel):
    enabled: Optional[bool] | None = None
    provider: Optional[SSOProvider] | None = None
    client_id: Optional[str] | None = Field(default=None, min_length=1)
    client_secret: Optional[str] | None = None
    scopes: Optional[list[str]] = None

    @model_validator(mode="after")
    def normalize_credentials(self):
        return _normalize_sso_credentials(self)

class ReadSSOSettingsDto(SSOSettingsDto):
    id: str
    @field_serializer("client_secret")
    def mask_sensitive_fields(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    @field_serializer("client_id")
    def mask_client_id(self, value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

class SSOSettingsListDto(BaseModel):
    items: list[ReadSSOSettingsDto]


class SSOSettingsResponseDto(BaseModel):
    message: str
