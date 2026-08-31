import re
from dataclasses import dataclass, field

from app.domain.controls import ControlPrimitive, ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.services.parsing.cisco import ConfigNode, ConfigTree

_DEFAULT_ACCOUNTS = {"cisco", "admin", "root", "default"}

# Commands the normalizer knowingly ignores: structural, cosmetic, or out of scope
# for the sixteen controls. Anything not matched here and not consumed by a rule
# below becomes an UnknownConstruct for SP4's training loop.
_IGNORED = re.compile(
    r"^(hostname|end|exit|version|service|boot-|interface|ip address|no shutdown|shutdown"
    r"|router|network|address-family|exit-address-family|line |transport|access-class"
    r"|exec-timeout|username|enable |aaa |security passwords|ip ssh|ip http|no ip http"
    r"|logging|ntp |snmp-server|banner|crypto|key-string|access-list|ip access-list"
    r"|permit|deny|description|<REDACTED)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class UnknownConstruct:
    text: str
    lineno: int
    block: str | None = None


@dataclass
class NormalizationResult:
    controls: ControlSet = field(default_factory=dict)
    unknowns: list[UnknownConstruct] = field(default_factory=list)


def _record(
    controls: ControlSet, key: str, value: ControlPrimitive, node: ConfigNode | None
) -> None:
    controls[key] = ControlValue(
        value=value,
        source_lines=[node.lineno] if node else [],
        excerpt=node.text if node else "",
    )


def normalize_cisco(tree: ConfigTree, identity: DeviceIdentity) -> NormalizationResult:
    """Map a parsed Cisco tree onto the sixteen universal controls.

    A control key is written only when the configuration actually says something about
    it. Silence stays silent — the rule engine turns that into NOT_ASSESSABLE.
    """
    controls: ControlSet = {}

    _normalize_ssh(tree, controls)
    _normalize_telnet(tree, controls)
    _normalize_web(tree, controls)
    _normalize_session_timeout(tree, controls)
    _normalize_management_acl(tree, controls)
    _normalize_auth(tree, controls)
    _normalize_logging(tree, controls)
    _normalize_ntp(tree, controls)
    _normalize_snmp(tree, controls)
    _normalize_banner(tree, controls)

    return NormalizationResult(controls=controls, unknowns=_collect_unknowns(tree))


def _normalize_ssh(tree: ConfigTree, controls: ControlSet) -> None:
    version_node = tree.first(r"^ip ssh version (\d)")
    if version_node:
        match = re.search(r"version (\d)", version_node.text)
        assert match is not None
        _record(controls, "management.ssh.version", int(match.group(1)), version_node)
        _record(controls, "management.ssh.enabled", True, version_node)
        return

    transport = tree.first(r"^transport input .*\bssh\b")
    if transport:
        _record(controls, "management.ssh.enabled", True, transport)
        return

    # Ruling R3(a): a vty block that names a transport but never ssh means ssh is
    # affirmatively off, not merely unassessed — Task 13's noncompliant.cfg depends on this.
    any_transport = tree.first(r"^transport input")
    if any_transport:
        _record(controls, "management.ssh.enabled", False, any_transport)


def _normalize_telnet(tree: ConfigTree, controls: ControlSet) -> None:
    transports = tree.find(r"^transport input")
    if not transports:
        return
    enabled_on = next((node for node in transports if re.search(r"\btelnet\b", node.text)), None)
    if enabled_on:
        _record(controls, "management.telnet.enabled", True, enabled_on)
    else:
        _record(controls, "management.telnet.enabled", False, transports[0])


def _normalize_web(tree: ConfigTree, controls: ControlSet) -> None:
    disabled = tree.first(r"^no ip http server")
    enabled = tree.first(r"^ip http server")
    if disabled:
        _record(controls, "management.http.enabled", False, disabled)
    elif enabled:
        _record(controls, "management.http.enabled", True, enabled)

    secure_off = tree.first(r"^no ip http secure-server")
    secure_on = tree.first(r"^ip http secure-server")
    if secure_off:
        _record(controls, "management.https.enabled", False, secure_off)
    elif secure_on:
        _record(controls, "management.https.enabled", True, secure_on)


def _normalize_session_timeout(tree: ConfigTree, controls: ControlSet) -> None:
    """`exec-timeout 0 0` disables the timeout entirely — record it as unset, not zero."""
    timeouts = tree.find(r"^exec-timeout (\d+)\s+(\d+)")
    if not timeouts:
        return

    worst_node: ConfigNode | None = None
    worst_seconds: int | None = None

    for node in timeouts:
        match = re.search(r"exec-timeout (\d+)\s+(\d+)", node.text)
        assert match is not None
        seconds = int(match.group(1)) * 60 + int(match.group(2))
        if seconds == 0:
            _record(controls, "management.session_timeout", None, node)
            return
        if worst_seconds is None or seconds > worst_seconds:
            worst_seconds, worst_node = seconds, node

    _record(controls, "management.session_timeout", worst_seconds, worst_node)


def _normalize_management_acl(tree: ConfigTree, controls: ControlSet) -> None:
    vty_blocks = tree.find(r"^line vty")
    if not vty_blocks:
        return
    for block in vty_blocks:
        access_class = block.first(r"^access-class \S+ in")
        if access_class:
            _record(controls, "management.acl.present", True, access_class)
            return
    _record(controls, "management.acl.present", False, vty_blocks[0])


def _normalize_auth(tree: ConfigTree, controls: ControlSet) -> None:
    aaa = tree.first(r"^aaa new-model")
    if aaa:
        _record(controls, "auth.aaa.enabled", True, aaa)
    elif tree.roots:
        _record(controls, "auth.aaa.enabled", False, tree.roots[0])

    min_length = tree.first(r"^security passwords min-length (\d+)")
    if min_length:
        match = re.search(r"min-length (\d+)", min_length.text)
        assert match is not None
        _record(controls, "auth.password.min_length", int(match.group(1)), min_length)

    # The redaction marker names the hash class, so strength is assessable without the value.
    strong = tree.first(r"^enable secret .*<REDACTED:enable-secret-strong>")
    weak = tree.first(r"^enable (password|secret 7)")
    if strong:
        _record(controls, "auth.enable_secret.encrypted", True, strong)
    elif weak:
        _record(controls, "auth.enable_secret.encrypted", False, weak)

    usernames = tree.find(r"^username (\S+)")
    if usernames:
        defaults = [
            node
            for node in usernames
            if (match := re.search(r"^username (\S+)", node.text))
            and match.group(1).lower() in _DEFAULT_ACCOUNTS
        ]
        if defaults:
            _record(controls, "auth.default_accounts.present", True, defaults[0])
        else:
            _record(controls, "auth.default_accounts.present", False, usernames[0])


def _normalize_logging(tree: ConfigTree, controls: ControlSet) -> None:
    buffered = tree.first(r"^logging buffered")
    if buffered:
        _record(controls, "logging.local.enabled", True, buffered)
    elif tree.first(r"^no logging buffered"):
        _record(controls, "logging.local.enabled", False, tree.first(r"^no logging buffered"))

    remote = tree.first(r"^logging (host |server |\d+\.\d+\.\d+\.\d+)")
    if remote:
        _record(controls, "logging.remote.enabled", True, remote)
    elif tree.find(r"^logging "):
        _record(controls, "logging.remote.enabled", False, tree.find(r"^logging ")[0])


def _normalize_ntp(tree: ConfigTree, controls: ControlSet) -> None:
    server = tree.first(r"^ntp server ")
    if server:
        _record(controls, "time.ntp.enabled", True, server)
    elif tree.find(r"^ntp "):
        _record(controls, "time.ntp.enabled", False, tree.find(r"^ntp ")[0])


def _normalize_snmp(tree: ConfigTree, controls: ControlSet) -> None:
    snmp_lines = tree.find(r"^snmp-server")
    if not snmp_lines:
        return
    legacy = next(
        (node for node in snmp_lines if re.search(r"^snmp-server community|v1|v2c", node.text)),
        None,
    )
    v3 = next((node for node in snmp_lines if re.search(r"\bv3\b", node.text)), None)
    if legacy:
        _record(controls, "snmp.v3.only", False, legacy)
    elif v3:
        _record(controls, "snmp.v3.only", True, v3)


def _normalize_banner(tree: ConfigTree, controls: ControlSet) -> None:
    banner = tree.first(r"^banner (login|motd)")
    if banner:
        _record(controls, "banner.login.present", True, banner)


def _collect_unknowns(tree: ConfigTree) -> list[UnknownConstruct]:
    """Every command the normalizer neither consumed nor knowingly ignored.

    This is the single seam where SP4's AI interpreter attaches. Slice 1 only counts them.
    """
    unknowns: list[UnknownConstruct] = []

    def walk(nodes: list[ConfigNode], block: str | None) -> None:
        for node in nodes:
            if not _IGNORED.match(node.text):
                unknowns.append(UnknownConstruct(text=node.text, lineno=node.lineno, block=block))
            if node.children:
                walk(node.children, node.text)

    walk(tree.roots, None)
    return unknowns
