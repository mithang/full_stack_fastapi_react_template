
import logging
from datetime import datetime, timedelta, timezone
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from fastapi import UploadFile

from api.core.exceptions import AzureBlobStorageException

logger = logging.getLogger(__name__)


class AzureBlobStorage:
    def __init__(self, connection_string: str, container_name: str):
        # Fail closed on a missing connection string instead of letting
        # BlobServiceClient.from_connection_string raise a bare ValueError:
        # that is not an ApiBaseException, so it bypassed the central
        # handler and surfaced as an unhandled 500 instead of the 502
        # the S3 path gets via S3StorageException. A pre-existing
        # enabled-Azure record with a blank connection string (the
        # configure-time validator only covers new configs, and the
        # field is Optional) would otherwise 500 every profile-image
        # read and every Azure upload. Mirrors the S3Storage blank-key
        # fail-closed raise.
        if not (connection_string or "").strip():
            raise AzureBlobStorageException(
                "Azure Blob Storage connection string is not configured."
            )
        self.container_name = container_name
        try:
            self.blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        except ValueError:
            # A malformed connection string raises ValueError from the
            # Azure SDK ("Connection string is either blank or
            # malformed."); map it to the same 502 class with a safe
            # message instead of leaking SDK internals or a bare 500.
            raise AzureBlobStorageException(
                "Azure Blob Storage connection string is invalid."
            )
        self.container_client = self.blob_service_client.get_container_client(container_name)

    async def upload_file(self, file: UploadFile, destination: str) -> str:
        try:
            blob_client = self.container_client.get_blob_client(destination)
            data = await file.read()
            blob_client.upload_blob(data, overwrite=True)
            return blob_client.url
        except Exception as e:
            # Azure SDK error strings carry infra internals (account,
            # container, request id) and, via the ApiBaseException handler,
            # reach the client verbatim; keep them server-side only.
            logger.error(f"Failed to upload file to Azure Blob Storage: {e}")
            raise AzureBlobStorageException("Failed to upload file.")

    async def generate_read_url(self, blob_name: str, expires_in: int = 3600) -> str:
        try:
            sas_token = generate_blob_sas(
                account_name=self.blob_service_client.account_name,
                container_name=self.container_name,
                blob_name=blob_name,
                permission=BlobSasPermissions(read=True),
                # Timezone-aware UTC expiry: datetime.utcnow() is deprecated
                # and returns a naive datetime; the rest of the codebase
                # (get_utc_now()) is UTC-aware, and the Azure SDK accepts
                # aware datetimes. Same instant as before, no behaviour change.
                expiry=datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            )
            blob_client = self.container_client.get_blob_client(blob_name)
            return f"{blob_client.url}?{sas_token}"
        except Exception as e:
            # Same verbatim-disclosure class as the upload path above.
            logger.error(f"Failed to generate Azure Blob Storage read URL: {e}")
            raise AzureBlobStorageException("Failed to generate file URL.")
