from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.db import get_db
from app.models import Device, User
from app.schemas.configurations import DeviceOut
from app.security.permissions import Permission

router = APIRouter(prefix="/devices", tags=["devices"])


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
