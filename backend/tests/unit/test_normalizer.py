from app.domain.device import DeviceIdentity
from app.services.normalization.cisco import normalize_cisco
from app.services.parsing.cisco import parse_cisco

CISCO = DeviceIdentity(vendor="cisco", os="ios-xe", confidence=0.98)

HARDENED = """hostname core-sw-01
enable secret 5 <REDACTED:enable-secret-strong>
aaa new-model
security passwords min-length 12
ip ssh version 2
no ip http server
ip http secure-server
logging buffered 16384
logging host 10.0.0.10
ntp server 10.0.0.5
snmp-server group NETMON v3 priv
banner login ^C Authorized access only ^C
username netops privilege 15 secret 9 <REDACTED:user-secret>
line vty 0 4
 transport input ssh
 exec-timeout 5 0
 access-class MGMT-ACL in
end
"""

WEAK = """hostname old-rtr
enable password cisco
ip ssh version 1
ip http server
username cisco privilege 15 password 7 <REDACTED:type7-password>
snmp-server community <REDACTED:snmp-community> RO
line vty 0 4
 transport input telnet
 exec-timeout 60 0
end
"""


def normalize(text: str) -> dict[str, object]:
    result = normalize_cisco(parse_cisco(text), CISCO)
    return {key: value.value for key, value in result.controls.items()}


def test_hardened_config_normalizes_to_compliant_values() -> None:
    controls = normalize(HARDENED)
    assert controls["management.ssh.enabled"] is True
    assert controls["management.ssh.version"] == 2
    assert controls["management.telnet.enabled"] is False
    assert controls["management.http.enabled"] is False
    assert controls["management.https.enabled"] is True
    assert controls["management.session_timeout"] == 300
    assert controls["management.acl.present"] is True
    assert controls["auth.password.min_length"] == 12
    assert controls["auth.aaa.enabled"] is True
    assert controls["auth.enable_secret.encrypted"] is True
    assert controls["auth.default_accounts.present"] is False
    assert controls["logging.local.enabled"] is True
    assert controls["logging.remote.enabled"] is True
    assert controls["time.ntp.enabled"] is True
    assert controls["snmp.v3.only"] is True
    assert controls["banner.login.present"] is True


def test_weak_config_normalizes_to_violating_values() -> None:
    controls = normalize(WEAK)
    assert controls["management.ssh.version"] == 1
    assert controls["management.telnet.enabled"] is True
    assert controls["management.http.enabled"] is True
    assert controls["management.session_timeout"] == 3600
    assert controls["management.acl.present"] is False
    assert controls["auth.aaa.enabled"] is False
    assert controls["auth.enable_secret.encrypted"] is False
    assert controls["auth.default_accounts.present"] is True
    assert controls["snmp.v3.only"] is False


def test_controls_carry_line_level_provenance() -> None:
    result = normalize_cisco(parse_cisco(HARDENED), CISCO)
    ssh = result.controls["management.ssh.version"]
    assert ssh.source_lines == [5]
    assert ssh.excerpt == "ip ssh version 2"
    assert ssh.origin == "deterministic"
    assert ssh.parser_confidence == 1.0


def test_absent_construct_yields_no_key_rather_than_a_false_value() -> None:
    result = normalize_cisco(parse_cisco("hostname bare\nend\n"), CISCO)
    assert "time.ntp.enabled" not in result.controls
    assert "auth.password.min_length" not in result.controls


def test_unrecognized_commands_are_recorded_as_unknown_constructs() -> None:
    text = "hostname x\nsecure-session-timeout 300\nfoo-bar-baz enable\nend\n"
    result = normalize_cisco(parse_cisco(text), CISCO)
    unknown = {construct.text for construct in result.unknowns}
    assert "secure-session-timeout 300" in unknown
    assert "foo-bar-baz enable" in unknown


def test_timeout_of_zero_minutes_means_no_timeout_not_a_compliant_zero() -> None:
    text = "line vty 0 4\n exec-timeout 0 0\nend\n"
    controls = normalize(text)
    assert controls["management.session_timeout"] is None


def test_ssh_recorded_disabled_when_only_telnet_transport_configured() -> None:
    """Ruling R3(a): no ip ssh version line, no ssh in transport input -> explicit False,
    not a missing key. Exercises the negative branch Task 13's noncompliant.cfg depends on."""
    text = "line vty 0 4\n transport input telnet\nend\n"
    controls = normalize(text)
    assert controls["management.ssh.enabled"] is False


def test_no_banner_line_is_recorded_disabled_not_absent() -> None:
    """Ruling R11: an explicit "no banner login" is a deliberate negative, not silence —
    without this branch an absent banner is always NOT_ASSESSABLE, never FAIL."""
    text = "hostname x\nno banner login\nend\n"
    controls = normalize(text)
    assert controls["banner.login.present"] is False


def test_no_logging_and_no_banner_lines_are_not_unknown_constructs() -> None:
    """Ruling R11: the negation lines are deliberate, not unrecognized commands."""
    text = "hostname x\nno logging buffered\nno banner login\nend\n"
    result = normalize_cisco(parse_cisco(text), CISCO)
    unknown = {construct.text for construct in result.unknowns}
    assert "no logging buffered" not in unknown
    assert "no banner login" not in unknown
