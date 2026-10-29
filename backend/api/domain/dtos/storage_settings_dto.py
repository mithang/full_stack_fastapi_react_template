from typing import Literal, Optional
from pydantic import BaseModel, Field, field_serializer, model_validator


class StorageSettingsDto(BaseModel):
    provider: Literal["s3", "azure_blob"]
    is_enabled: bool
    region: str
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_bucket_name: Optional[str] = None
    azure_connection_string: Optional[str] = None
    azure_container_name: Optional[str] = None
    updated_by_user_id: Optional[str] = None


class ConfigureStorageSettingsDto(StorageSettingsDto):
    # POST /storage/configure accepted an enabled S3 config with an
    # empty region and persisted it verbatim, returning 201 — the
    # failure only surfaced later, at upload/retrieval time, when
    # file_upload/file_retrieval build boto3.client(region_name="")
    # and the call fails as a generic "Failed to upload file." An
    # enabled S3 config now fails FastAPI validation (422) before
    # any write. This is a separate request DTO, not a cap on the
    # base DTO: the base DTO backs AvailableStorageProviderDto, so
    # capping it would break GET reads of pre-existing records, and
    # disabled configs (either provider) plus enabled Azure configs
    # (whose client is built from the connection string, not region)
    # legitimately carry an empty region and are unaffected.
    @model_validator(mode="after")
    def require_region_for_enabled_s3(self):
        if self.provider == "s3" and self.is_enabled and not self.region.strip():
            raise ValueError("region is required when S3 storage is enabled")
        return self



class AvailableStorageProviderDto(StorageSettingsDto):
    id: str
    created_at: str
    updated_at: str
    tenant_id: str | None = None

    @field_serializer("aws_secret_key", "aws_access_key", "azure_connection_string")
    def serialize_sensitive_fields(self, value):
        if value is not None:
            return "****"
        return None



