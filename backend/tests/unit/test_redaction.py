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
