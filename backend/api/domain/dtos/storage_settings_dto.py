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
    # any write. The same deferred failure existed for Azure: an
    # enabled azure_blob config with a blank connection string
    # persisted verbatim and only failed later, when file_upload /
    # file_retrieval build BlobServiceClient.from_connection_string
    # with it. It is now rejected the same way. The same deferred
    # failure existed for the container name: an enabled azure_blob
    # config with a blank container persisted verbatim and only
    # failed later, at upload time (file_upload concatenates the
    # container name into the blob key) or at read-URL time
    # (file_retrieval builds a container client with it). It is now
    # rejected the same way. The S3 mirror existed for the bucket
    # name: an enabled s3 config with a blank bucket persisted
    # verbatim and only failed later, at upload time (file_upload
    # concatenates the bucket name into the storage key) or at
    # read-URL time (file_retrieval passes it as the presigned-URL
    # Bucket). It is now rejected the same way. This is a separate
    # request DTO, not a cap on the base DTO: the base DTO backs
    # AvailableStorageProviderDto, so capping it would break GET reads
    # of pre-existing records, and disabled configs (either provider)
    # plus enabled Azure configs (whose client is built from the
    # connection string, not region) legitimately carry an empty
    # region and are unaffected; likewise, disabled Azure configs
    # legitimately carry a blank connection string.
    @model_validator(mode="after")
    def require_fields_for_enabled_provider(self):
        if self.provider == "s3" and self.is_enabled and not self.region.strip():
            raise ValueError("region is required when S3 storage is enabled")
        if (
            self.provider == "s3"
            and self.is_enabled
            and not (self.aws_bucket_name or "").strip()
        ):
            raise ValueError(
                "aws_bucket_name is required when S3 storage is enabled"
            )
        if (
            self.provider == "azure_blob"
            and self.is_enabled
            and not (self.azure_connection_string or "").strip()
        ):
            raise ValueError(
                "azure_connection_string is required when Azure Blob storage is enabled"
            )
        if (
            self.provider == "azure_blob"
            and self.is_enabled
            and not (self.azure_container_name or "").strip()
        ):
            raise ValueError(
                "azure_container_name is required when Azure Blob storage is enabled"
            )
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



