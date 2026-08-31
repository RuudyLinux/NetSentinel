from typing import Protocol


class StorageError(RuntimeError):
    """Raised when a blob cannot be read, written, or addressed safely."""


class StorageBackend(Protocol):
    """The only interface through which blob content may be reached.

    SP6 swaps LocalFileStorage for an S3/MinIO implementation of this protocol.
    """

    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...
