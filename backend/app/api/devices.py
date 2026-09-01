from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.db import get_db
from app.models import Device, User
from app.schemas.configurations import DeviceOut
from app.schemas.devices import (
    DiscoveredHostOut,
    DiscoverRequest,
    DiscoverResponse,
    LocalNetworkResponse,
)
from app.security.permissions import Permission
from app.services.discovery.scan import discover_ssh, local_network

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("/local-network", response_model=LocalNetworkResponse)
def get_local_network(
    user: User = Depends(require(Permission.CONFIG_UPLOAD)),
) -> LocalNetworkResponse:
    """Best-effort guess at the operator's own subnet, to pre-fill the scan CIDR field.
    Purely informational (reads this server's own interface) — no audit event, since
    nothing on the network is touched."""
    try:
        return LocalNetworkResponse(cidr=local_network())
    except OSError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "could not determine local network"
        ) from exc


@router.post("/discover", response_model=DiscoverResponse)
def discover(
    payload: DiscoverRequest,
    request: Request,
    user: User = Depends(require(Permission.CONFIG_UPLOAD)),
    session: Session = Depends(get_db),
) -> DiscoverResponse:
    """Probe a CIDR range for hosts actually running SSH (verified by banner, not just an
    open port) and identify which port it's on. No credentials are involved or tried —
    device_name is always "Unknown" (there's no way to know it without connecting); the
    operator picks a result and connects manually."""
    try:
        found = discover_ssh(payload.cidr, payload.ports)
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
    return DiscoverResponse(hosts=[DiscoveredHostOut(ip=h.ip, port=h.port) for h in found])


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
