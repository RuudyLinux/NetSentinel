from app.security.redaction import redact

CONFIG = """hostname core-sw-01
enable secret 5 $1$mERr$Ml5Kf1TZKFbGfBjMDwCCM0
username admin privilege 15 password 7 070C285F4D06
snmp-server community publicRO RO
line vty 0 4
 password 7 104D000A0618
crypto key generate rsa
 key-string ABCDEF0123456789
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890
-----END RSA PRIVATE KEY-----
"""


def test_no_secret_material_survives_redaction() -> None:
    result = redact(CONFIG)
    for secret in (
        "$1$mERr$Ml5Kf1TZKFbGfBjMDwCCM0",
        "070C285F4D06",
        "publicRO",
        "104D000A0618",
        "ABCDEF0123456789",
        "MIIEowIBAAKCAQEA1234567890",
    ):
        assert secret not in result.text


def test_redaction_preserves_line_count_and_structure() -> None:
    result = redact(CONFIG)
    assert len(result.text.splitlines()) == len(CONFIG.splitlines())
    assert "hostname core-sw-01" in result.text


def test_redaction_marks_the_kind_of_each_secret() -> None:
    kinds = {hit.kind for hit in redact(CONFIG).hits}
    assert "enable-secret-strong" in kinds
    assert "type7-password" in kinds
    assert "snmp-community" in kinds
    assert "private-key" in kinds


def test_hits_carry_one_indexed_line_numbers() -> None:
    hits = {hit.kind: hit.lineno for hit in redact(CONFIG).hits}
    assert hits["enable-secret-strong"] == 2


def test_clean_config_produces_no_hits() -> None:
    result = redact("hostname router\nip ssh version 2\n")
    assert result.hits == []
    assert result.text == "hostname router\nip ssh version 2\n"


def test_redaction_is_idempotent() -> None:
    once = redact(CONFIG).text
    assert redact(once).text == once


def test_redaction_does_not_corrupt_non_secret_lines_containing_trigger_words() -> None:
    """Trigger substrings appearing outside a known directive position must not be touched."""
    text = (
        "banner login ^C Please choose a password 7 characters minimum ^C\n"
        "! remember to rotate pre-shared-key annually\n"
        "description this line mentions password 0 in passing\n"
    )
    result = redact(text)
    assert "characters" in result.text
    assert "annually" in result.text
    assert "passing" in result.text
    assert result.hits == []


CISCO_AAA_SECRETS = """tacacs-server key 0 SuperSecretTacacsKey
radius-server key 7 104D000A0618
crypto isakmp key MyPreSharedKey123 address 10.0.0.1
snmp-server user netops NETMON v3 auth sha AuthKey123 priv aes 128 PrivKey456
"""


def test_tacacs_and_radius_server_keys_are_redacted() -> None:
    result = redact(CISCO_AAA_SECRETS)
    assert "SuperSecretTacacsKey" not in result.text
    assert "104D000A0618" not in result.text
    kinds = {hit.kind for hit in result.hits}
    assert {"tacacs-server-key", "radius-server-key"} <= kinds


def test_isakmp_key_is_redacted_but_peer_address_is_preserved() -> None:
    result = redact(CISCO_AAA_SECRETS)
    assert "MyPreSharedKey123" not in result.text
    assert "address 10.0.0.1" in result.text


def test_snmp_v3_user_line_redacts_both_auth_and_priv_keys() -> None:
    result = redact(CISCO_AAA_SECRETS)
    assert "AuthKey123" not in result.text
    assert "PrivKey456" not in result.text
    assert "netops" in result.text  # username is evidence, not a secret
    assert "priv aes 128" in result.text  # the priv algorithm/keysize stays visible
    hit_kinds = [hit.kind for hit in result.hits]
    assert hit_kinds.count("snmp-user-auth-priv") == 1  # one hit, two secrets redacted


FORTIOS_SECRETS = """    set password ENC AK1abcdefghijklmnop
    set psksecret MyIpsecPreSharedKey
    set auth-pwd ENC BK2qrstuvwxyz
    set priv-pwd ENC CK3zyxwvutsrq
"""


def test_fortios_secret_directives_are_redacted() -> None:
    result = redact(FORTIOS_SECRETS)
    for secret in ("AK1abcdefghijklmnop", "MyIpsecPreSharedKey", "BK2qrstuvwxyz", "CK3zyxwvutsrq"):
        assert secret not in result.text
    kinds = {hit.kind for hit in result.hits}
    assert kinds == {
        "fortios-password",
        "fortios-psksecret",
        "fortios-snmp-auth-pwd",
        "fortios-snmp-priv-pwd",
    }
