import re

from app.domain.device import DeviceIdentity

# FortiOS backup/`show full-configuration` output always opens with a header line
# `#config-version=<model>-<major.minor.patch>-...:opmode=...:vdom=...:user=...`,
# which is the single strongest signal available — nothing else looks like it.
_SIGNATURES: list[tuple[str, re.Pattern[str], int]] = [
    ("config-version header", re.compile(r"^#config-version=", re.MULTILINE), 4),
    ("config system global", re.compile(r"^config system global\s*$", re.MULTILINE), 3),
    ("set hostname", re.compile(r'^\s*set hostname\s+"?\S+"?', re.MULTILINE), 2),
    ("config system interface", re.compile(r"^config system interface\s*$", re.MULTILINE), 2),
    ("config system admin", re.compile(r"^config system admin\s*$", re.MULTILINE), 2),
    ("edit block", re.compile(r'^\s*edit\s+"', re.MULTILINE), 1),
    ("bare end statement", re.compile(r"^end\s*$", re.MULTILINE), 1),
]

_TOTAL_WEIGHT = sum(weight for _, _, weight in _SIGNATURES)

_CONFIG_VERSION = re.compile(r"^#config-version=([A-Za-z0-9]+)-(\d+\.\d+\.\d+)", re.MULTILINE)
_HOSTNAME = re.compile(r'^\s*set hostname\s+"?([^"\s]+)"?', re.MULTILINE)


def detect(text: str) -> DeviceIdentity:
    matched_weight = 0
    reasons: list[str] = []
    for label, pattern, weight in _SIGNATURES:
        if pattern.search(text):
            matched_weight += weight
            reasons.append(f"matched '{label}' (w={weight})")

    confidence = round(matched_weight / _TOTAL_WEIGHT, 2)

    version_match = _CONFIG_VERSION.search(text)
    hostname_match = _HOSTNAME.search(text)

    return DeviceIdentity(
        vendor="fortinet",
        os="fortios",
        os_version=version_match.group(2) if version_match else None,
        product_family=version_match.group(1).lower() if version_match else None,
        hostname=hostname_match.group(1) if hostname_match else None,
        confidence=confidence,
        reasons=reasons,
    )


class FortinetDetector:
    """Registry adapter around `detect` — see services/detection/registry.py."""

    vendor = "fortinet"

    def detect(self, text: str) -> DeviceIdentity:
        return detect(text)
