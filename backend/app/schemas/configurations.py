from pydantic import BaseModel


class ConnectRequest(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str
    enable_password: str | None = None


class DeviceOut(BaseModel):
    id: int
    name: str
    vendor: str
    os: str
    os_version: str | None = None


class ConfigurationOut(BaseModel):
    id: int
    sha256: str
    filename: str
    size_bytes: int
    secret_hits: int
    device: DeviceOut


class ConfigurationDetail(ConfigurationOut):
    text: str
