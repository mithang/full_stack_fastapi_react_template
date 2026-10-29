from typing import List, Optional
from beanie import PydanticObjectId
from pydantic import BaseModel, Field

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
    name: str = Field(max_length=20)
    description: Optional[str] | None = Field(default=None, max_length=200)
    tenant_id: PydanticObjectId | None = None

class UpdateRoleDto(CreateRoleDto):
    permissions: List[Permission] = Field(default_factory=list)


class CreateRoleResponseDto(BaseModel):
    id: str


