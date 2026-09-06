from app.domain.device import DeviceIdentity
from app.services.detection.base import VendorDetector
from app.services.detection.cisco import CiscoDetector
from app.services.detection.fortinet import FortinetDetector

# Every registered vendor detector. Adding a vendor is exactly this: implement
# VendorDetector (services/detection/base.py) and append an instance here.
# Nothing else in the pipeline changes.
DETECTORS: list[VendorDetector] = [CiscoDetector(), FortinetDetector()]


def detect_vendor(text: str) -> DeviceIdentity:
    """Run every registered detector and return the identity with the highest confidence.

    Ties are broken by registration order (first-registered wins) — deterministic,
    and in practice ties only happen on degenerate input (e.g. empty text) where
    every detector returns confidence 0.0 and the result is disposable pending
    `DeviceIdentity.needs_confirmation` anyway.
    """
    if not DETECTORS:
        raise RuntimeError("no vendor detectors are registered")
    candidates = [detector.detect(text) for detector in DETECTORS]
    return max(candidates, key=lambda identity: identity.confidence)
