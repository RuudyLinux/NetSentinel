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
# secret material (which is not). Group 1 is always the retained prefix.
_LINE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("enable-secret-strong", re.compile(r"^(\s*enable secret\s+(?:5|8|9)\s+)\S+", re.IGNORECASE)),
    ("enable-secret-type7", re.compile(r"^(\s*enable secret\s+7\s+)\S+", re.IGNORECASE)),
    ("enable-password-cleartext", re.compile(r"^(\s*enable password\s+)(?!7\s)\S+", re.IGNORECASE)),
    (
        "type7-password",
        re.compile(r"^(\s*(?:username\s+\S+(?:\s+\S+)*\s+)?password\s+7\s+)\S+", re.IGNORECASE),
    ),
    (
        "cleartext-password",
        re.compile(r"^(\s*(?:username\s+\S+(?:\s+\S+)*\s+)?password\s+0\s+)\S+", re.IGNORECASE),
    ),
    ("user-secret", re.compile(r"^(\s*username\s+\S+.*\bsecret\s+\d\s+)\S+", re.IGNORECASE)),
    ("snmp-community", re.compile(r"^(\s*snmp-server community\s+)\S+", re.IGNORECASE)),
    ("key-string", re.compile(r"^(\s*key-string\s+)\S+", re.IGNORECASE)),
    ("pre-shared-key", re.compile(r"^(\s*pre-shared-key\s+)\S+", re.IGNORECASE)),
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
        for kind, pattern in _LINE_PATTERNS:
            match = pattern.match(redacted)
            if match and "<REDACTED:" not in redacted:
                redacted = pattern.sub(rf"\g<1>{_REDACTION.format(kind=kind)}", redacted)
                hits.append(SecretHit(kind=kind, lineno=index))
                break
        output.append(redacted)

    trailing = "\n" if text.endswith("\n") else ""
    return RedactionResult(text="\n".join(output) + trailing, hits=hits)
