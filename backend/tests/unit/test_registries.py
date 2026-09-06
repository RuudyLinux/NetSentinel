import pytest

from app.domain.device import UnsupportedVendorError
from app.services.detection.registry import detect_vendor
from app.services.normalization.registry import get_normalizer
from app.services.parsing.registry import get_parser

CISCO_TEXT = "Building configuration...\n!\nversion 15.2\nhostname r1\n!\nend\n"
FORTIOS_TEXT = (
    "#config-version=FGT60F-7.4.5-FW-build2687-231213:opmode=0:vdom=0:user=admin\n"
    'config system global\n    set hostname "fw1"\nend\n'
)


def test_detect_vendor_picks_the_highest_confidence_candidate() -> None:
    cisco_identity = detect_vendor(CISCO_TEXT)
    assert cisco_identity.vendor == "cisco"

    fortios_identity = detect_vendor(FORTIOS_TEXT)
    assert fortios_identity.vendor == "fortinet"


def test_detect_vendor_ties_break_by_registration_order() -> None:
    # Neither detector recognizes this text — both score 0.0, so the first
    # registered detector (Cisco) wins deterministically rather than at random.
    identity = detect_vendor("system {\n    host-name mx-01;\n}\n")
    assert identity.vendor == "cisco"
    assert identity.needs_confirmation


@pytest.mark.parametrize("vendor", ["cisco", "Cisco", "CISCO"])
def test_get_parser_is_case_insensitive_for_supported_vendors(vendor: str) -> None:
    get_parser(vendor)  # must not raise


@pytest.mark.parametrize("vendor", ["cisco", "fortinet"])
def test_get_normalizer_resolves_every_supported_vendor(vendor: str) -> None:
    get_normalizer(vendor)  # must not raise


def test_get_parser_rejects_an_unsupported_vendor_cleanly() -> None:
    with pytest.raises(UnsupportedVendorError, match="juniper"):
        get_parser("juniper")


def test_get_normalizer_rejects_an_unsupported_vendor_cleanly() -> None:
    with pytest.raises(UnsupportedVendorError, match="paloalto"):
        get_normalizer("paloalto")
