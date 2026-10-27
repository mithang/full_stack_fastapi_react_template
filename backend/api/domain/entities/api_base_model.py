from datetime import datetime
from typing import Optional
from beanie import Document, PydanticObjectId
from pydantic import Field, field_serializer

from api.common.utils import get_utc_now


class ApiBaseModel(Document):
    # default_factory (not a plain get_utc_now() call): a plain call is
    # evaluated once at class definition, so every inheriting document
    # created without explicit timestamps would share the server-start time.
    created_at: datetime = Field(default_factory=get_utc_now)
    updated_at: datetime = Field(default_factory=get_utc_now)
    tenant_id: Optional[PydanticObjectId] = None

    # Todo: Remove all the to_serializable_dict methods and use field_serializers instead
    # @field_serializer("created_at", "updated_at", "tenant_id")
    # def serialize_object_id(self, value):
    #     if isinstance(value, PydanticObjectId):
    #         return str(value)
    #     return str(value)
        
    
    async def to_serializable_dict(self):
        data = self.model_dump()
        data["id"] = str(self.id)
        data["created_at"] = str(self.created_at)
        data["updated_at"] = str(self.updated_at)
        if self.tenant_id:
            data["tenant_id"] = str(self.tenant_id)
        return data



