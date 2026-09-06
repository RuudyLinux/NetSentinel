from collections.abc import Callable
from dataclasses import dataclass, field

from app.domain.controls import ControlPrimitive, ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.services.parsing.base import ConfigNode, ConfigTree


@dataclass(frozen=True)
class UnknownConstruct:
    text: str
    lineno: int
    block: str | None = None


@dataclass
class NormalizationResult:
    controls: ControlSet = field(default_factory=dict)
    unknowns: list[UnknownConstruct] = field(default_factory=list)


#: The shape every vendor normalizer implements — a plain function, not a class,
#: since normalization has no per-call state (unlike detection's confidence
#: bookkeeping). Registered in services/normalization/registry.py.
VendorNormalizer = Callable[[ConfigTree, DeviceIdentity], NormalizationResult]


def record(
    controls: ControlSet, key: str, value: ControlPrimitive, node: ConfigNode | None
) -> None:
    """Write one control observation, carrying its evidence (or none, for a
    negative inferred from silence elsewhere — e.g. Cisco's "no vty block names
    telnet" case)."""
    controls[key] = ControlValue(
        value=value,
        source_lines=[node.lineno] if node else [],
        excerpt=node.text if node else "",
    )
