import re

from app.domain.device import DeviceIdentity

# Two independent weighted signature sets, each its own denominator. A config either
# looks like a live terminal capture ("show running-config", banners included) or a
# saved/backed-up config body (banners stripped, core directives intact) — requiring
# hits from both would unfairly punish whichever style a given file happens to be.
# Confidence is the better of the two ratios, so adding a signature to either list
# without reweighting still only makes that list's own score more conservative.
_CAPTURE_SIGNATURES: list[tuple[str, re.Pattern[str], int]] = [
    ("Building configuration...", re.compile(r"^Building configuration\.\.\.", re.MULTILINE), 3),
    ("Current configuration :", re.compile(r"^Current configuration\s*:", re.MULTILINE), 3),
    ("boot-start-marker", re.compile(r"^boot-start-marker", re.MULTILINE), 3),
    ("service timestamps", re.compile(r"^service timestamps\b", re.MULTILINE), 2),
    ("line con 0", re.compile(r"^line con 0", re.MULTILINE), 2),
    ("version token", re.compile(r"^version \d+\.\d+", re.MULTILINE), 2),
    ("bare end statement", re.compile(r"^end\s*$", re.MULTILINE), 1),
]

_BODY_SIGNATURES: list[tuple[str, re.Pattern[str], int]] = [
    ("version token", re.compile(r"^version \d+\.\d+", re.MULTILINE), 2),
    ("bare end statement", re.compile(r"^end\s*$", re.MULTILINE), 1),
    ("hostname directive", re.compile(r"^hostname \S+", re.MULTILINE), 3),
    ("enable password/secret", re.compile(r"^enable (password|secret)\b", re.MULTILINE), 2),
    (
        "ip http server/secure-server",
        re.compile(r"^(no )?ip http (server|secure-server)\b", re.MULTILINE),
        2,
    ),
    ("snmp-server directive", re.compile(r"^snmp-server\b", re.MULTILINE), 1),
    ("line vty", re.compile(r"^line vty \d+ \d+", re.MULTILINE), 2),
    (
        "security passwords min-length",
        re.compile(r"^security passwords min-length \d+", re.MULTILINE),
        2,
    ),
]

_CAPTURE_TOTAL_WEIGHT = sum(weight for _, _, weight in _CAPTURE_SIGNATURES)
_BODY_TOTAL_WEIGHT = sum(weight for _, _, weight in _BODY_SIGNATURES)

_VERSION = re.compile(r"^version (\d+)\.(\d+)", re.MULTILINE)
_HOSTNAME = re.compile(r"^hostname (\S+)", re.MULTILINE)

# IOS-XE reports major versions 16 and above; classic IOS reports 12 through 15.
_IOS_XE_MAJOR_FLOOR = 16


def _score(text: str, signatures: list[tuple[str, re.Pattern[str], int]]) -> tuple[float, list[str]]:
    matched_weight = 0
    reasons: list[str] = []
    for label, pattern, weight in signatures:
        if pattern.search(text):
            matched_weight += weight
            reasons.append(f"matched '{label}' (w={weight})")
    total = sum(weight for _, _, weight in signatures)
    return matched_weight / total, reasons


def detect(text: str) -> DeviceIdentity:
    capture_ratio, capture_reasons = _score(text, _CAPTURE_SIGNATURES)
    body_ratio, body_reasons = _score(text, _BODY_SIGNATURES)

    if capture_ratio >= body_ratio:
        confidence = round(capture_ratio, 2)
        reasons = capture_reasons
    else:
        confidence = round(body_ratio, 2)
        reasons = body_reasons

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
