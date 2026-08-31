import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Configuration, Device, User
from app.security.redaction import redact
from app.services.detection.cisco import detect
from app.storage.base import StorageBackend

ALLOWED_EXTENSIONS = frozenset({".txt", ".cfg", ".conf", ".log", ".json", ".xml", ".yaml", ".yml"})


class IngestionError(ValueError):
    """Raised when an upload is not acceptable. Surfaces to the caller as HTTP 422."""


def validate_upload(filename: str, data: bytes) -> str:
    """Validate an untrusted upload and return its decoded text."""
    suffix = filename[filename.rfind(".") :].lower() if "." in filename else ""
    if suffix not in ALLOWED_EXTENSIONS:
        raise IngestionError(
            f"unsupported file extension {suffix!r}; allowed: {sorted(ALLOWED_EXTENSIONS)}"
        )
    if len(data) > settings.max_upload_bytes:
        raise IngestionError(f"file exceeds the {settings.max_upload_bytes} byte limit")
    if not data.strip():
        raise IngestionError("file is empty")
    if b"\x00" in data:
        raise IngestionError("file contains binary content")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise IngestionError("file is not decodable as text") from exc


def ingest_configuration(
    session: Session,
    storage: StorageBackend,
    user: User,
    filename: str,
    data: bytes,
) -> tuple[Configuration, bool]:
    """Validate, redact, hash, store, and register a configuration.

    Returns the configuration and whether it was newly created. Redaction happens
    before anything is persisted, so no secret material reaches the database.
    """
    text = validate_upload(filename, data)
    redaction = redact(text)
    identity = detect(redaction.text)

    device_name = identity.hostname or filename.rsplit(".", 1)[0]
    device = session.scalar(
        select(Device).where(
            Device.organization_id == user.organization_id, Device.name == device_name
        )
    )
    if device is None:
        device = Device(
            organization_id=user.organization_id,
            name=device_name,
            vendor=identity.vendor,
            os=identity.os,
            os_version=identity.os_version,
        )
        session.add(device)
        session.flush()

    redacted_bytes = redaction.text.encode("utf-8")
    digest = hashlib.sha256(redacted_bytes).hexdigest()

    existing = session.scalar(
        select(Configuration).where(
            Configuration.device_id == device.id, Configuration.sha256 == digest
        )
    )
    if existing is not None:
        return existing, False

    blob_key = f"configurations/{digest[:2]}/{digest}.cfg"
    storage.put(blob_key, redacted_bytes)

    configuration = Configuration(
        device=device,
        sha256=digest,
        blob_key=blob_key,
        filename=filename,
        size_bytes=len(redacted_bytes),
        uploaded_by=user,
        secret_hits=len(redaction.hits),
    )
    session.add(configuration)
    session.flush()
    return configuration, True
