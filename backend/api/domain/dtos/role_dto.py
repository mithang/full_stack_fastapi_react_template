from typing import List, Optional
from beanie import PydanticObjectId
from pydantic import BaseModel, Field, model_validator

from api.domain.enum.permission import Permission


class RoleDto(BaseModel):
    id: str
    name: str
    description: Optional[str] | None
    permissions: List[Permission] = []
    created_at: str
    updated_at: str
    tenant_id: Optional[str] | None = None


class RoleListDto(BaseModel):
    roles: List[RoleDto]
    skip: int
    limit: int
    total: int
    has_previous: bool
    has_next: bool


class CreateRoleDto(BaseModel):
    name: str = Field(min_length=2, max_length=20)
    description: Optional[str] | None = Field(default=None, min_length=10, max_length=200)
    tenant_id: PydanticObjectId | None = None

    @model_validator(mode="after")
    def normalize_name_and_description(self):
        # Normalize before use: the role dialogs trim name/description
        # (zod .trim()), but direct API clients bypass the forms — so
        # a padded name persisted verbatim and, worse, slipped past
        # the create path's exact-match duplicate check (role_service
        # looks up single_or_none(name=role_data.name)), letting
        # "Admin " coexist with "Admin". A whitespace-only name of
        # 2+ spaces likewise passed min_length=2, and a whitespace-only
        # description of 10+ spaces passed min_length=10, persisting
        # blank values the forms would never send — the same
        # deferred-failure class as the storage/SSO/Stripe/AI DTO
        # validators. Role names and descriptions cannot legitimately
        # carry surrounding whitespace, and UpdateRoleDto inherits
        # this validator, so create and update are covered. A value
        # that trims to empty is rejected outright (422) instead of
        # persisting a blank; None description still means "not
        # provided", and seed/test values carry no surrounding
        # whitespace, so no legitimate flow is affected. The response
        # DTO is deliberately left alone so a pre-existing padded
        # record can still be read.
        if isinstance(self.name, str):
            self.name = self.name.strip()
            if len(self.name) < 2:
                raise ValueError("name must not be blank")
        if isinstance(self.description, str):
            self.description = self.description.strip()
            if self.description and len(self.description) < 10:
                raise ValueError("description must be at least 10 characters")
            if self.description == "":
                raise ValueError("description must not be blank")
        return self

class UpdateRoleDto(CreateRoleDto):
    permissions: List[Permission] = Field(default_factory=list)


class CreateRoleResponseDto(BaseModel):
    id: str


