from typing import Literal, Optional
from pydantic import BaseModel, model_validator

class CoolifyAppDto(BaseModel):
    uuid: str
    name: str
    fqdn: Optional[str] = None

    

class UpdateCoolifyAppDto(BaseModel):
    domain: str

class UpdateDomainDto(UpdateCoolifyAppDto):
    mode: Literal["add", "remove"] = "add"

    @model_validator(mode="after")
    def normalize_domain(self):
        # Normalize before use: CoolifyApp.update_domain() strips
        # each entry of the stored fqdn list before comparing, but
        # compared data.domain verbatim, so a padded domain missed
        # the exact-match add/remove checks — a padded add stored a
        # second, padded entry alongside the clean one, and a padded
        # remove left the clean entry in place. The register worker
        # payload carries CreateUserDto.sub_domain verbatim (the
        # register form does not trim it), while AuthService.register
        # only trims it for the tenant lookup/creation, so a padded
        # subdomain reached Coolify this way even though the stored
        # tenant subdomain is trimmed. Stripping here covers all four
        # celery_worker call sites (and the https:// prefixing in
        # _update_coolify_domain, which rebuilds this DTO from the
        # stripped value). A whitespace-only value is left as "" so
        # the existing behaviour for an empty domain is unchanged,
        # and legitimate domains carry no surrounding whitespace.
        if isinstance(self.domain, str):
            self.domain = self.domain.strip()
        return self
