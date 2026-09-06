from dataclasses import dataclass, field


class UnsupportedVendorError(ValueError):
    """A vendor was identified (by detection or operator override) but the parsing
    or normalization stage has no implementation for it yet.

    Distinct from a plain KeyError/ImportError so callers (audit/runner.py,
    api/audits.py) can translate it into a clear "this vendor is planned, not
    yet supported" response instead of a 500.
    """


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
