from pydantic import BaseModel


class DiscoverRequest(BaseModel):
    cidr: str
    port: int = 22


class DiscoverResponse(BaseModel):
    hosts: list[str]
    port: int
