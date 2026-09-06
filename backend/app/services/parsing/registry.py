from collections.abc import Callable

from app.domain.device import UnsupportedVendorError
from app.services.parsing.base import ConfigTree
from app.services.parsing.cisco import parse_cisco
from app.services.parsing.fortinet import parse_fortinet

__all__ = ["UnsupportedVendorError", "get_parser"]

# Every registered vendor parser, keyed by DeviceIdentity.vendor. Adding a vendor
# is exactly this: implement `parse(text) -> ConfigTree` and add it here.
_PARSERS: dict[str, Callable[[str], ConfigTree]] = {
    "cisco": parse_cisco,
    "fortinet": parse_fortinet,
}


def get_parser(vendor: str) -> Callable[[str], ConfigTree]:
    try:
        return _PARSERS[vendor.lower()]
    except KeyError:
        raise UnsupportedVendorError(
            f"no parser registered for vendor {vendor!r} — this vendor is not yet supported"
        ) from None
