import re

from app.domain.device import DeviceIdentity

# Weighted signatures. The total is the denominator, so adding a signature without
# reweighting deliberately makes every score more conservative, never less.
_SIGNATURES: list[tuple[str, re.Pattern[str], int]] = [
    ("Building configuration...", re.compile(r"^Building configuration\.\.\.", re.MULTILINE), 3),
    ("Current configuration :", re.compile(r"^Current configuration\s*:", re.MULTILINE), 3),
    ("boot-start-marker", re.compile(r"^boot-start-marker", re.MULTILINE), 3),
    ("service timestamps", re.compile(r"^service timestamps\b", re.MULTILINE), 2),
    ("line con 0", re.compile(r"^line con 0", re.MULTILINE), 2),
    ("version token", re.compile(r"^version \d+\.\d+", re.MULTILINE), 2),
    ("bare end statement", re.compile(r"^end\s*$", re.MULTILINE), 1),
]

_TOTAL_WEIGHT = sum(weight for _, _, weight in _SIGNATURES)

_VERSION = re.compile(r"^version (\d+)\.(\d+)", re.MULTILINE)
_HOSTNAME = re.compile(r"^hostname (\S+)", re.MULTILINE)

# IOS-XE reports major versions 16 and above; classic IOS reports 12 through 15.
_IOS_XE_MAJOR_FLOOR = 16


def detect(text: str) -> DeviceIdentity:
    matched_weight = 0
    reasons: list[str] = []

    for label, pattern, weight in _SIGNATURES:
        if pattern.search(text):
            matched_weight += weight
            reasons.append(f"matched '{label}' (w={weight})")

    confidence = round(matched_weight / _TOTAL_WEIGHT, 2)

    version_match = _VERSION.search(text)
    os_version = f"{version_match.group(1)}.{version_match.group(2)}" if version_match else None

    os_name = "ios"
    if version_match:
        major = int(version_match.group(1))
        if major >= _IOS_XE_MAJOR_FLOOR:
            os_name = "ios-xe"
            reasons.append(f"version major {major} implies IOS-XE")
        else:
            reasons.append(f"version major {major} implies classic IOS")

    hostname_match = _HOSTNAME.search(text)

    return DeviceIdentity(
        vendor="cisco",
        os=os_name,
        os_version=os_version,
        product_family="ios",
        hostname=hostname_match.group(1) if hostname_match else None,
        confidence=confidence,
        reasons=reasons,
    )
