from typing import Protocol

from app.domain.device import DeviceIdentity


class VendorDetector(Protocol):
    """One vendor's signature-matching strategy.

    `detect` always returns an identity — never raises, never returns None — even
    for text that looks nothing like this vendor's output. A near-zero-confidence
    identity IS the "not this vendor" signal; the registry compares confidences
    across every registered detector rather than asking each one "is this yours?"
    """

    #: Lowercase vendor name this detector claims, matching DeviceIdentity.vendor.
    vendor: str

    def detect(self, text: str) -> DeviceIdentity: ...
