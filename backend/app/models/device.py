from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.org import Organization, User


class Device(Base, TimestampMixin):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(200))
    vendor: Mapped[str] = mapped_column(String(60))
    os: Mapped[str] = mapped_column(String(60))
    model: Mapped[str | None] = mapped_column(String(120), default=None)
    os_version: Mapped[str | None] = mapped_column(String(60), default=None)

    organization: Mapped[Organization] = relationship()


class Configuration(Base, TimestampMixin):
    __tablename__ = "configurations"
    __table_args__ = (UniqueConstraint("device_id", "sha256"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    blob_key: Mapped[str] = mapped_column(String(255))
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    uploaded_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    secret_hits: Mapped[int] = mapped_column(Integer, default=0)

    device: Mapped[Device] = relationship()
    uploaded_by: Mapped[User] = relationship()
