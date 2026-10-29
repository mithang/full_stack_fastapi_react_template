
import logging

import boto3
from fastapi import UploadFile

from api.core.exceptions import S3StorageException

logger = logging.getLogger(__name__)


class S3Storage:
    def __init__(self, bucket_name: str, aws_access_key: str, aws_secret_key: str, region: str):
        # Fail closed on missing keys instead of letting boto3 silently
        # resolve ambient credentials (env vars, shared config, IAM role):
        # the configure-time validator (iteration 1105) only covers new
        # configs, so a pre-existing enabled-S3 record with blank keys
        # would otherwise upload to the tenant bucket under the
        # deployment's credentials. Host-level settings keys are required
        # fields (core/config.py), so this cannot trip a running
        # deployment's settings-fallback path on None keys.
        if not (aws_access_key or "").strip() or not (aws_secret_key or "").strip():
            raise S3StorageException("S3 storage credentials are not configured.")
        self.bucket_name = bucket_name
        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )

    async def upload_file(self, file: UploadFile, destination: str) -> str:
        try:
            self.s3_client.upload_fileobj(file.file, self.bucket_name, destination)
            return destination
            # return f"https://{self.bucket_name}.s3.{self.s3_client.meta.region_name}.amazonaws.com/{destination}"
        except Exception as e:
            # boto3 error strings carry infra internals (bucket, endpoint,
            # request id) and, via the ApiBaseException handler, reach the
            # client verbatim; keep them server-side only.
            logger.error(f"Failed to upload file to S3: {e}")
            raise S3StorageException("Failed to upload file.")


    async def generate_read_url(self, key: str, expires_in: int = 3600) -> str:
        try:
            return self.s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": key},
                ExpiresIn=expires_in
            )
        except Exception as e:
            # Same verbatim-disclosure class as the upload path above.
            logger.error(f"Failed to generate S3 read URL: {e}")
            raise S3StorageException("Failed to generate file URL.")