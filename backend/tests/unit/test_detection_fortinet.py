from app.services.detection.fortinet import detect

FORTIOS = """#config-version=FGT60F-7.4.5-FW-build2687-231213:opmode=0:vdom=0:user=admin
config system global
    set hostname "fw-core-01"
    set admintimeout 10
end
config system interface
    edit "port1"
        set allowaccess ping https ssh
    next
end
config system admin
    edit "netops"
        set accprofile "super_admin"
    next
end
end
"""

CISCO_LIKE = """Building configuration...

Current configuration : 512 bytes
!
version 15.2
hostname edge-rtr-02
!
end
"""


def test_detects_fortios_with_high_confidence() -> None:
    identity = detect(FORTIOS)
    assert identity.vendor == "fortinet"
    assert identity.os == "fortios"
    assert identity.os_version == "7.4.5"
    assert identity.product_family == "fgt60f"
    assert identity.hostname == "fw-core-01"
    assert not identity.needs_confirmation


def test_detection_explains_itself() -> None:
    identity = detect(FORTIOS)
    assert identity.reasons
    assert any("config-version" in reason for reason in identity.reasons)


def test_cisco_config_falls_below_the_confirmation_threshold() -> None:
    identity = detect(CISCO_LIKE)
    assert identity.needs_confirmation
    assert identity.confidence < 0.70


def test_empty_input_needs_confirmation() -> None:
    assert detect("").needs_confirmation
