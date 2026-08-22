from app.services.detection.cisco import detect

IOS_XE = """Building configuration...

Current configuration : 4213 bytes
!
version 17.6
service timestamps debug datetime msec
!
hostname core-sw-01
!
boot-start-marker
boot-end-marker
!
line con 0
!
end
"""

IOS_CLASSIC = """Building configuration...
!
version 15.2
service timestamps log datetime
!
hostname edge-rtr-02
!
boot-start-marker
boot-end-marker
!
line con 0
!
end
"""

JUNOS = """system {
    host-name mx-01;
    services {
        ssh;
    }
}
"""


def test_detects_ios_xe_with_high_confidence() -> None:
    identity = detect(IOS_XE)
    assert identity.vendor == "cisco"
    assert identity.os == "ios-xe"
    assert identity.os_version == "17.6"
    assert identity.hostname == "core-sw-01"
    assert identity.confidence >= 0.95
    assert not identity.needs_confirmation


def test_detects_classic_ios() -> None:
    identity = detect(IOS_CLASSIC)
    assert identity.os == "ios"
    assert identity.os_version == "15.2"
    assert identity.hostname == "edge-rtr-02"


def test_detection_explains_itself() -> None:
    identity = detect(IOS_XE)
    assert identity.reasons, "detection must state why"
    assert any("boot-start-marker" in reason for reason in identity.reasons)


def test_non_cisco_config_falls_below_the_confirmation_threshold() -> None:
    identity = detect(JUNOS)
    assert identity.needs_confirmation
    assert identity.confidence < 0.70


def test_empty_input_needs_confirmation() -> None:
    assert detect("").needs_confirmation
