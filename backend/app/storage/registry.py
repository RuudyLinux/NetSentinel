from app.config import settings
from app.storage.base import StorageBackend
from app.storage.local import LocalFileStorage

__all__ = ["get_storage"]


def get_storage() -> StorageBackend:
    """Select the storage backend named by `NETSENTINEL_STORAGE_BACKEND`.

    Everything above this function (the audit pipeline, ingestion, reporting)
    depends only on the `StorageBackend` protocol — this is the one place that
    decides which concrete implementation backs it, same pattern as the vendor
    registries in services/{detection,parsing,normalization}/registry.py.
    """
    if settings.storage_backend == "s3":
        # Imported lazily: boto3 is a real dependency (see pyproject.toml), but a
        # deployment that never sets storage_backend=s3 shouldn't pay for importing
        # it or need network/credential setup just to run the local dev path.
        from app.storage.s3 import S3Storage

        return S3Storage(
            settings.s3_bucket,
            endpoint_url=settings.s3_endpoint_url,
            access_key=settings.s3_access_key,
            secret_key=settings.s3_secret_key,
            region=settings.s3_region,
        )
    return LocalFileStorage(settings.storage_dir)
