from app.domain.device import UnsupportedVendorError
from app.services.normalization.base import VendorNormalizer
from app.services.normalization.cisco import normalize_cisco
from app.services.normalization.fortinet import normalize_fortinet

__all__ = ["UnsupportedVendorError", "get_normalizer"]

# Every registered vendor normalizer, keyed by DeviceIdentity.vendor. Adding a
# vendor is exactly this: implement `normalize(tree, identity) -> NormalizationResult`
# and add it here.
_NORMALIZERS: dict[str, VendorNormalizer] = {
    "cisco": normalize_cisco,
    "fortinet": normalize_fortinet,
}


def get_normalizer(vendor: str) -> VendorNormalizer:
    try:
        return _NORMALIZERS[vendor.lower()]
    except KeyError:
        raise UnsupportedVendorError(
            f"no normalizer registered for vendor {vendor!r} — this vendor is not yet supported"
        ) from None
