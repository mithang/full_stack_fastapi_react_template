from typing import Optional
from pydantic import BaseModel, Field, model_validator

from api.domain.entities.branding import ContactInfo, LogoType, ThemeConfig


class BrandingDto(BaseModel):
    id: str
    logo_type: Optional[LogoType] = None
    contact_info: Optional[ContactInfo] = None
    theme_config: ThemeConfig = Field(default_factory=ThemeConfig)
    tenant_id: str
    created_at: str
    updated_at: str
    app_name: str = "SaaS Org"
    favicon_url: Optional[str] = None
    logo_url: Optional[str] = None

   
    
class IdentityDto(BaseModel):
    app_name: str = "SaaS Org"

    @model_validator(mode="after")
    def normalize_app_name(self):
        # Normalize before use: the branding form sends app_name
        # verbatim (z.string().optional(), no trim/min), and a direct
        # API client bypasses the form entirely — so a whitespace-only
        # value passed validation with no min_length cap and persisted
        # verbatim, rendering as blank branding (the logo component
        # treats any non-empty string as a name to display), and a
        # padded value persisted with its padding — the same
        # deferred-failure class as the name/ID DTO validators in this
        # sweep. An app name cannot legitimately carry surrounding
        # whitespace; a value trimming to empty is rejected outright
        # (422) instead of persisting a blank name, and padded values
        # are stored trimmed. The response DTO is deliberately left
        # alone so a pre-existing blank record can still be read, and
        # identity-less updates (logo-only) carry no IdentityDto, so
        # they are unaffected.
        if isinstance(self.app_name, str):
            trimmed = self.app_name.strip()
            if not trimmed:
                raise ValueError("app_name must not be blank")
            self.app_name = trimmed
        return self

class UpdateBrandingDto(BaseModel):
    identity: Optional[IdentityDto] = None
    contact_info: Optional[ContactInfo] = None
    theme_config: Optional[ThemeConfig] = None
    tenant_id: Optional[str] = None
    logo_url: Optional[str] = None
    logo_type: Optional[LogoType] = None