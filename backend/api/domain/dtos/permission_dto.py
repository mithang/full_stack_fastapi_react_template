from pydantic import BaseModel


class PermissionDto(BaseModel):
    name: str
