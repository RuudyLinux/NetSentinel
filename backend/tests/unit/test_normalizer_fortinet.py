from app.domain.device import DeviceIdentity
from app.services.normalization.fortinet import normalize_fortinet
from app.services.parsing.fortinet import parse_fortinet

FORTINET = DeviceIdentity(vendor="fortinet", os="fortios", confidence=0.95)

HARDENED = """#config-version=FGT60F-7.4.5-FW-build2687-231213:opmode=0:vdom=0:user=admin
config system global
    set hostname "fw-core-01"
    set admintimeout 10
    set pre-login-banner enable
end
config system interface
    edit "port1"
        set mode static
        set allowaccess ping https ssh
    next
end
config system admin
    edit "netops"
        set accprofile "super_admin"
        set trusthost1 10.0.0.0 255.255.255.0
    next
end
config system password-policy
    set status enable
    set apply-to admin-password
    set minimum-length 12
end
config log disk setting
    set status enable
end
config log syslogd setting
    set status enable
    set server "10.0.0.10"
end
config system ntp
    set ntpsync enable
end
config system snmp user
    edit "netsentinel"
        set security-level auth-priv
    next
end
"""

WEAK = """#config-version=FGT60F-6.4.8-FW-build2013-210630:opmode=0:vdom=0:user=admin
config system global
    set hostname "old-fw"
    set pre-login-banner disable
end
config system interface
    edit "port1"
        set allowaccess ping http https ssh telnet
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
end
config log disk setting
    set status disable
end
config log syslogd setting
    set status disable
end
config system ntp
    set ntpsync disable
end
config system snmp community
    edit 1
        set name "public"
    next
end
"""


def normalize(text: str) -> dict[str, object]:
    result = normalize_fortinet(parse_fortinet(text), FORTINET)
    return {key: value.value for key, value in result.controls.items()}


def test_hardened_config_normalizes_to_compliant_values() -> None:
    controls = normalize(HARDENED)
    assert controls["management.ssh.enabled"] is True
    assert controls["management.telnet.enabled"] is False
    assert controls["management.http.enabled"] is False
    assert controls["management.https.enabled"] is True
    assert controls["management.session_timeout"] == 600
    assert controls["management.acl.present"] is True
    assert controls["auth.password.min_length"] == 12
    assert controls["auth.default_accounts.present"] is False
    assert controls["logging.local.enabled"] is True
    assert controls["logging.remote.enabled"] is True
    assert controls["time.ntp.enabled"] is True
    assert controls["snmp.v3.only"] is True
    assert controls["banner.login.present"] is True


def test_weak_config_normalizes_to_violating_values() -> None:
    controls = normalize(WEAK)
    assert controls["management.telnet.enabled"] is True
    assert controls["management.http.enabled"] is True
    assert controls["management.acl.present"] is False
    assert controls["auth.default_accounts.present"] is True
    assert controls["logging.local.enabled"] is False
    assert controls["logging.remote.enabled"] is False
    assert controls["time.ntp.enabled"] is False
    assert controls["snmp.v3.only"] is False
    assert controls["banner.login.present"] is False


def test_controls_carry_line_level_provenance() -> None:
    result = normalize_fortinet(parse_fortinet(HARDENED), FORTINET)
    timeout = result.controls["management.session_timeout"]
    assert timeout.source_lines == [4]
    assert timeout.excerpt == "set admintimeout 10"
    assert timeout.origin == "deterministic"


def test_controls_with_no_signal_are_left_unassessed() -> None:
    """auth.aaa.enabled and auth.enable_secret.encrypted have no FortiOS analog and
    must never be stretched to fit — see normalization/fortinet.py's module docstring."""
    controls = normalize(HARDENED)
    assert "auth.aaa.enabled" not in controls
    assert "auth.enable_secret.encrypted" not in controls
    assert "management.ssh.version" not in controls


def test_unrecognized_admin_settings_are_recorded_as_unknown_constructs() -> None:
    text = (
        "#config-version=FGT60F-7.4.5-FW-build2687-231213:opmode=0:vdom=0:user=admin\n"
        "config system admin\n"
        '    edit "netops"\n'
        "        set some-future-fortios-setting enable\n"
        "    next\n"
        "end\n"
    )
    result = normalize_fortinet(parse_fortinet(text), FORTINET)
    unknown = {construct.text for construct in result.unknowns}
    assert "set some-future-fortios-setting enable" in unknown


def test_firewall_policy_blocks_are_entirely_out_of_scope_not_unknown() -> None:
    """Thousands of firewall-policy lines in a real FortiOS export must never flood
    the unknown-construct queue — see normalization/fortinet.py's module docstring."""
    text = (
        "#config-version=FGT60F-7.4.5-FW-build2687-231213:opmode=0:vdom=0:user=admin\n"
        "config firewall policy\n"
        "    edit 1\n"
        '        set srcintf "port1"\n'
        "    next\n"
        "end\n"
    )
    result = normalize_fortinet(parse_fortinet(text), FORTINET)
    assert result.unknowns == []


def test_interface_internals_other_than_allowaccess_are_not_flagged_unknown() -> None:
    """config system interface is mined only for allowaccess — see module docstring."""
    text = (
        "#config-version=FGT60F-7.4.5-FW-build2687-231213:opmode=0:vdom=0:user=admin\n"
        "config system interface\n"
        '    edit "port1"\n'
        "        set mode static\n"
        "        set ip 10.0.0.1 255.255.255.0\n"
        "        set allowaccess ping https ssh\n"
        "    next\n"
        "end\n"
    )
    result = normalize_fortinet(parse_fortinet(text), FORTINET)
    assert result.unknowns == []
    assert result.controls["management.ssh.enabled"].value is True
