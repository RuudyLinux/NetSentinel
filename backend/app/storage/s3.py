from typing import Any

import boto3
from botocore.exceptions import ClientError

from app.storage.base import StorageError

__all__ = ["S3Storage"]


class S3Storage:
    """S3 (or S3-compatible, e.g. MinIO) blob store.

    Implements the same `StorageBackend` protocol as `LocalFileStorage` — callers
    never know or care which one they have (see storage/registry.py). Blob keys are
    used directly as S3 object keys; S3 has no directory-traversal concept the way a
    filesystem does; a key containing arbitrary characters simply addresses that
    object; there is nothing to escape into.
    """

    def __init__(
        self,
        bucket: str,
        *,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str = "us-east-1",
    ) -> None:
        self._bucket = bucket
        client_kwargs: dict[str, Any] = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
        if access_key and secret_key:
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key
        self._client = boto3.client("s3", **client_kwargs)
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        """Create the bucket if it doesn't exist yet — the same self-healing
        convenience `LocalFileStorage` gets from `Path.mkdir(parents=True,
        exist_ok=True)`. A real AWS deployment normally provisions the bucket
        out-of-band (via IaC) and simply won't hit the "doesn't exist" branch."""
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except ClientError:
            try:
                self._client.create_bucket(Bucket=self._bucket)
            except ClientError as exc:
                raise StorageError(
                    f"cannot create or reach bucket {self._bucket!r}: {exc}"
                ) from exc

    def put(self, key: str, data: bytes) -> None:
        try:
            self._client.put_object(Bucket=self._bucket, Key=key, Body=data)
        except ClientError as exc:
            raise StorageError(f"failed to write blob {key!r}: {exc}") from exc

    def get(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            raise StorageError(f"no blob at key {key!r}") from exc
        return response["Body"].read()  # type: ignore[no-any-return]

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError:
            return False
