from pydantic import BaseModel


class DiscoverRequest(BaseModel):
    cidr: str
    ports: list[int] = [22, 2222]


class DiscoveredHostOut(BaseModel):
    device_name: str = "Unknown"
    ip: str
    port: int


class DiscoverResponse(BaseModel):
    hosts: list[DiscoveredHostOut]


class LocalNetworkResponse(BaseModel):
    cidr: str
