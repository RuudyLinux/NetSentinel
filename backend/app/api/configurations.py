from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.db import get_db
from app.models import Configuration, User
from app.schemas.configurations import ConfigurationDetail, ConfigurationOut, DeviceOut
from app.security.permissions import Permission
from app.services.ingestion.upload import IngestionError, ingest_configuration
from app.storage.base import StorageBackend
from app.storage.local import get_storage

router = APIRouter(prefix="/configurations", tags=["configurations"])


def _to_out(configuration: Configuration) -> ConfigurationOut:
    return ConfigurationOut(
        id=configuration.id,
        sha256=configuration.sha256,
        filename=configuration.filename,
        size_bytes=configuration.size_bytes,
        secret_hits=configuration.secret_hits,
        device=DeviceOut(
            id=configuration.device.id,
            name=configuration.device.name,
            vendor=configuration.device.vendor,
            os=configuration.device.os,
            os_version=configuration.device.os_version,
        ),
    )


@router.post("/upload", response_model=ConfigurationOut, status_code=status.HTTP_201_CREATED)
def upload(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    user: User = Depends(require(Permission.CONFIG_UPLOAD)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> ConfigurationOut:
    data = file.file.read()
    try:
        configuration, created = ingest_configuration(
            session, storage, user, file.filename or "upload.cfg", data
        )
    except IngestionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    record_event(
        session,
        action="UPLOAD_CONFIGURATION",
        user_id=user.id,
        resource=configuration.sha256,
        ip=client_ip(request),
    )
    session.commit()
    if not created:
        response.status_code = status.HTTP_200_OK
    return _to_out(configuration)


@router.get("/{configuration_id}", response_model=ConfigurationDetail)
def read(
    configuration_id: int,
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> ConfigurationDetail:
    configuration = session.get(Configuration, configuration_id)
    if configuration is None or configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Configuration not found")

    base = _to_out(configuration)
    return ConfigurationDetail(
        **base.model_dump(), text=storage.get(configuration.blob_key).decode("utf-8")
    )
