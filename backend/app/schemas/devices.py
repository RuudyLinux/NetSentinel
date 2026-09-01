from typing import Literal

from pydantic import BaseModel


class DiscoverRequest(BaseModel):
    cidr: str
    ports: list[int] = [22, 2222]


class DiscoveredHostOut(BaseModel):
    device_name: str = "Unknown"
    ip: str
    status: Literal["ssh_available", "ssh_unavailable"]
    port: int | None = None
    vendor: str | None = None


class DiscoverResponse(BaseModel):
    hosts: list[DiscoveredHostOut]


class LocalNetworkResponse(BaseModel):
    interface: str
    local_ip: str
    cidr: str
