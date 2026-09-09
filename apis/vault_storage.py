# apis/vault_storage.py

import asyncio
import logging
import os
import re
from typing import Optional

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Only these characters are ever allowed into a blob key segment.
# This kills path traversal (../, /) at the construction site.
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")


class VaultStorage:
    """
    Thin wrapper over a Storj (S3-compatible) bucket.

    Blob layout:  vault/{userId}/{profileId}/{reservationId}.enc

    A fresh key per reservation means two devices can never overwrite each
    other's in-flight upload. Mongo holds the pointer to the live blob.
    """

    def __init__(self):
        self.bucket = os.getenv("STORJ_BUCKET", "aida-vault")
        access_key = os.getenv("STORJ_ACCESS_KEY_ID")
        secret_key = os.getenv("STORJ_SECRET_ACCESS_KEY")
        if not access_key or not secret_key:
            raise EnvironmentError(
                "STORJ_ACCESS_KEY_ID / STORJ_SECRET_ACCESS_KEY are not set."
            )

        self._s3 = boto3.client(
            "s3",
            endpoint_url=os.getenv("STORJ_ENDPOINT_URL", "https://gateway.storjshare.io"),
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=os.getenv("STORJ_REGION", "us-east-1"),
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )

    def build_blob_key(self, user_id: str, profile_id: str, reservation_id: str) -> str:
        for segment in (user_id, profile_id, reservation_id):
            if not _SAFE_SEGMENT.match(segment):
                raise ValueError("Unsafe blob key segment rejected.")
        return f"vault/{user_id}/{profile_id}/{reservation_id}.enc"

    async def presign_put(self, blob_key: str, ttl_seconds: int) -> str:
        # generate_presigned_url is a local signing operation, no network call
        return await asyncio.to_thread(
            self._s3.generate_presigned_url,
            "put_object",
            Params={"Bucket": self.bucket, "Key": blob_key},
            ExpiresIn=ttl_seconds,
        )

    async def presign_get(self, blob_key: str, ttl_seconds: int) -> str:
        return await asyncio.to_thread(
            self._s3.generate_presigned_url,
            "get_object",
            Params={"Bucket": self.bucket, "Key": blob_key},
            ExpiresIn=ttl_seconds,
        )

    async def head_object_size(self, blob_key: str) -> Optional[int]:
        """Returns the object's size in bytes, or None if it does not exist."""
        def _head() -> Optional[int]:
            try:
                resp = self._s3.head_object(Bucket=self.bucket, Key=blob_key)
                return resp.get("ContentLength")
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("404", "NoSuchKey", "NotFound"):
                    return None
                raise

        return await asyncio.to_thread(_head)

    async def delete_object(self, blob_key: str) -> None:
        """Best-effort delete. Missing keys are not an error."""
        def _delete() -> None:
            try:
                self._s3.delete_object(Bucket=self.bucket, Key=blob_key)
            except ClientError as e:
                logger.warning(f"Failed to delete blob {blob_key}: {e}")

        return await asyncio.to_thread(_delete)


_storage: Optional[VaultStorage] = None


def get_vault_storage() -> VaultStorage:
    global _storage
    if _storage is None:
        _storage = VaultStorage()
    return _storage