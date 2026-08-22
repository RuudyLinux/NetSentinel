from dataclasses import dataclass, field
from typing import Literal

ControlOrigin = Literal["deterministic", "inferred", "learned"]
ControlPrimitive = bool | int | str | list[str] | None


@dataclass(frozen=True)
class ControlValue:
    """A normalized security control observation, with the evidence that produced it."""

    value: ControlPrimitive
    source_lines: list[int] = field(default_factory=list)
    excerpt: str = ""
    parser_confidence: float = 1.0
    origin: ControlOrigin = "deterministic"


ControlSet = dict[str, ControlValue]

CONTROL_KEYS: frozenset[str] = frozenset(
    {
        "management.ssh.enabled",
        "management.ssh.version",
        "management.telnet.enabled",
        "management.http.enabled",
        "management.https.enabled",
        "management.session_timeout",
        "management.acl.present",
        "auth.password.min_length",
        "auth.aaa.enabled",
        "auth.enable_secret.encrypted",
        "auth.default_accounts.present",
        "logging.local.enabled",
        "logging.remote.enabled",
        "time.ntp.enabled",
        "snmp.v3.only",
        "banner.login.present",
    }
)
