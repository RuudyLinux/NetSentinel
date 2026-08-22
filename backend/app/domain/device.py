from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceIdentity:
    """The result of vendor/OS detection, carrying the reasoning behind the confidence."""

    vendor: str
    os: str
    confidence: float
    product_family: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    reasons: list[str] = field(default_factory=list)

    @property
    def needs_confirmation(self) -> bool:
        return self.confidence < 0.70
