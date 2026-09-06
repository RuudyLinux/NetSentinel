import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretHit:
    kind: str
    lineno: int


@dataclass(frozen=True)
class RedactionResult:
    text: str
    hits: list[SecretHit] = field(default_factory=list)


# Each pattern keeps the keyword prefix (which is evidence) and replaces only the
# secret material (which is not). `template` is applied with `.format(marker=...)`
# after substituting numbered groups, so most patterns retain one prefix group
# (`\g<1>`) and a single trailing marker; a line with two independent secrets
# (e.g. SNMP v3's auth+priv keys) uses two groups and two markers instead.
_MARKER_TEMPLATE = r"\g<1>{marker}"

_LINE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "enable-secret-strong",
        re.compile(r"^(\s*enable secret\s+(?:5|8|9)\s+)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "enable-secret-type7",
        re.compile(r"^(\s*enable secret\s+7\s+)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "enable-password-cleartext",
        re.compile(r"^(\s*enable password\s+)(?!7\s)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "type7-password",
        re.compile(r"^(\s*(?:username\s+\S+(?:\s+\S+)*\s+)?password\s+7\s+)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "cleartext-password",
        re.compile(r"^(\s*(?:username\s+\S+(?:\s+\S+)*\s+)?password\s+0\s+)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "user-secret",
        re.compile(r"^(\s*username\s+\S+.*\bsecret\s+\d\s+)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "snmp-community",
        re.compile(r"^(\s*snmp-server community\s+)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    ("key-string", re.compile(r"^(\s*key-string\s+)\S+", re.IGNORECASE), _MARKER_TEMPLATE),
    ("pre-shared-key", re.compile(r"^(\s*pre-shared-key\s+)\S+", re.IGNORECASE), _MARKER_TEMPLATE),
    (
        "tacacs-server-key",
        re.compile(r"^(\s*tacacs-server key\s+(?:0\s+|7\s+)?)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "radius-server-key",
        re.compile(r"^(\s*radius-server key\s+(?:0\s+|7\s+)?)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "isakmp-key",
        re.compile(r"^(\s*crypto isakmp key\s+)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        # `snmp-server user <name> <group> v3 auth <proto> <key> priv <proto> [bits] <key>`
        # carries two independent secrets on one line — both must be redacted. `priv`'s
        # algorithm is sometimes followed by a numeric key length (e.g. `aes 128`).
        "snmp-user-auth-priv",
        re.compile(
            r"^(\s*snmp-server user\s+\S+\s+\S+\s+v3\s+auth\s+\S+\s+)\S+"
            r"(\s+priv\s+\S+(?:\s+\d+)?\s+)\S+",
            re.IGNORECASE,
        ),
        r"\g<1>{marker}\g<2>{marker}",
    ),
    # FortiOS: `set password`/`set psksecret`/`set auth-pwd`/`set priv-pwd` are the
    # vendor's own secret-bearing directives, parallel to Cisco's `password`/
    # `key-string`/`pre-shared-key` above. FortiOS prefixes an already-encrypted
    # value with the literal token `ENC` — that token is evidence (it says the
    # value is not plaintext), the blob after it is not.
    (
        "fortios-password",
        re.compile(r"^(\s*set password\s+(?:ENC\s+)?)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "fortios-psksecret",
        re.compile(r"^(\s*set psksecret\s+(?:ENC\s+)?)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "fortios-snmp-auth-pwd",
        re.compile(r"^(\s*set auth-pwd\s+(?:ENC\s+)?)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
    (
        "fortios-snmp-priv-pwd",
        re.compile(r"^(\s*set priv-pwd\s+(?:ENC\s+)?)\S+", re.IGNORECASE),
        _MARKER_TEMPLATE,
    ),
]

_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_REDACTION = "<REDACTED:{kind}>"


def redact(text: str) -> RedactionResult:
    """Replace secret material with typed markers, preserving line structure.

    Redaction is idempotent: a marker is not itself a secret, so re-running is safe.
    """
    hits: list[SecretHit] = []
    output: list[str] = []
    inside_pem = False

    for index, line in enumerate(text.splitlines(), start=1):
        if inside_pem:
            if _PEM_END.search(line):
                inside_pem = False
                output.append(line)
            else:
                output.append(_REDACTION.format(kind="private-key"))
            continue

        if _PEM_BEGIN.search(line):
            inside_pem = True
            hits.append(SecretHit(kind="private-key", lineno=index))
            output.append(line)
            continue

        redacted = line
        for kind, pattern, template in _LINE_PATTERNS:
            match = pattern.match(redacted)
            if match and "<REDACTED:" not in redacted:
                marker = _REDACTION.format(kind=kind)
                redacted = pattern.sub(template.format(marker=marker), redacted)
                hits.append(SecretHit(kind=kind, lineno=index))
                break
        output.append(redacted)

    trailing = "\n" if text.endswith("\n") else ""
    return RedactionResult(text="\n".join(output) + trailing, hits=hits)
