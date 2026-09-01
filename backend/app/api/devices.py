from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.db import get_db
from app.models import Device, User
from app.schemas.configurations import DeviceOut
from app.schemas.devices import DiscoverRequest, DiscoverResponse
from app.security.permissions import Permission
from app.services.discovery.scan import scan_cidr

router = APIRouter(prefix="/devices", tags=["devices"])


@router.post("/discover", response_model=DiscoverResponse)
def discover(
    payload: DiscoverRequest,
    request: Request,
    user: User = Depends(require(Permission.CONFIG_UPLOAD)),
    session: Session = Depends(get_db),
) -> DiscoverResponse:
    """Probe a CIDR range for hosts with an open SSH-sized port. Returns IPs only — no
    credentials are involved or tried; the operator picks one and connects manually."""
    try:
        hosts = scan_cidr(payload.cidr, payload.port)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    record_event(
        session,
        action="DISCOVER_DEVICES",
        user_id=user.id,
        resource=payload.cidr,
        ip=client_ip(request),
    )
    session.commit()
    return DiscoverResponse(hosts=hosts, port=payload.port)


@router.get("", response_model=list[DeviceOut])
def list_devices(
    user: User = Depends(require(Permission.DEVICE_READ)),
    session: Session = Depends(get_db),
) -> list[DeviceOut]:
    devices = session.scalars(
        select(Device).where(Device.organization_id == user.organization_id).order_by(Device.name)
    )
    return [DeviceOut.model_validate(device, from_attributes=True) for device in devices]


@router.get("/{device_id}", response_model=DeviceOut)
def read_device(
    device_id: int,
    user: User = Depends(require(Permission.DEVICE_READ)),
    session: Session = Depends(get_db),
) -> DeviceOut:
    device = session.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    return DeviceOut.model_validate(device, from_attributes=True)
