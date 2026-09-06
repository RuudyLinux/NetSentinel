import re

from app.domain.controls import ControlSet
from app.domain.device import DeviceIdentity
from app.services.normalization.base import NormalizationResult, UnknownConstruct
from app.services.normalization.base import record as _record
from app.services.parsing.base import ConfigNode, ConfigTree

__all__ = ["NormalizationResult", "UnknownConstruct", "normalize_fortinet"]

# FortiOS full-configuration exports run to thousands of lines covering firewall
# policy, routing, VPN, web filtering, and more — almost none of it relevant to
# these sixteen controls. Rather than pretend to understand all of it, this
# normalizer only collects "unknown constructs" from the specific top-level
# blocks that can actually speak to a control; everything else (firewall,
# router, vpn, webfilter, and — deliberately — the per-interface internals of
# `config system interface`, which is only ever mined for its `allowaccess`
# signal below) is genuinely out of scope, never walked, and never reported as
# unknown. This keeps the AI-review queue meaningful instead of drowning in
# firewall-policy or per-interface noise.
_UNKNOWN_SCOPE_BLOCKS = re.compile(
    r"^config (system (global|admin|password-policy|ntp|snmp (community|user|sysinfo))"
    r"|log (disk|syslogd) setting)\s*$"
)

# Lines within an in-scope block that are structural/cosmetic, or already
# consumed by a normalizer function above — not "unknown", just not new
# information about one of the sixteen controls.
_IGNORED = re.compile(
    r"^(config |edit |next|end|set admintimeout|set trusthost|set minimum-length|set status"
    r"|set ntpsync|set pre-login-banner|set post-login-banner"
    # Common, predictable per-account/global attributes this normalizer doesn't
    # assess — flagging them as "unknown" on every single audit would be noise,
    # not signal (the same reasoning as Cisco's normalizer ignoring `username`
    # wholesale even though it separately inspects it for default accounts).
    r"|set accprofile|set apply-to|set server|set hostname)",
    re.IGNORECASE,
)


def normalize_fortinet(tree: ConfigTree, identity: DeviceIdentity) -> NormalizationResult:
    """Map a parsed FortiOS tree onto as many of the sixteen universal controls as
    FortiOS has a real, well-known equivalent for.

    Three controls have no clean FortiOS analog and are deliberately left
    unpopulated (`auth.aaa.enabled`, `auth.enable_secret.encrypted`,
    `management.ssh.version`) rather than stretched to fit — any CIS-FortiOS rule
    targeting them will correctly read NOT_ASSESSABLE. See rules/cis/fortios-v2.yaml.
    """
    controls: ControlSet = {}

    _normalize_management_access(tree, controls)
    _normalize_session_timeout(tree, controls)
    _normalize_admin_trusted_hosts(tree, controls)
    _normalize_password_policy(tree, controls)
    _normalize_default_admin_account(tree, controls)
    _normalize_logging(tree, controls)
    _normalize_ntp(tree, controls)
    _normalize_snmp(tree, controls)
    _normalize_banner(tree, controls)

    return NormalizationResult(controls=controls, unknowns=_collect_unknowns(tree))


# FortiOS accepts both `edit "name"` and bare `edit name` — real examples in the
# vendor's own documentation use both forms interchangeably.
_EDIT_NAME = re.compile(r'^edit\s+"?([^"\s]+)"?')


def _allowaccess_tokens(node: ConfigNode) -> set[str]:
    match = re.search(r"^set allowaccess\s+(.*)$", node.text, re.IGNORECASE)
    return set(match.group(1).split()) if match else set()


def _normalize_management_access(tree: ConfigTree, controls: ControlSet) -> None:
    """`set allowaccess <protocols...>` on each `config system interface` edit block
    is FortiOS's equivalent of Cisco's per-vty `transport input` — the union across
    every interface is the worst case, same reasoning as the Cisco normalizer."""
    allowaccess_nodes = tree.find(r"^set allowaccess\b")
    if not allowaccess_nodes:
        return

    tokens: set[str] = set()
    for node in allowaccess_nodes:
        tokens |= _allowaccess_tokens(node)

    reference = allowaccess_nodes[0]
    _record(controls, "management.ssh.enabled", "ssh" in tokens, reference)
    _record(controls, "management.telnet.enabled", "telnet" in tokens, reference)
    _record(controls, "management.http.enabled", "http" in tokens, reference)
    _record(controls, "management.https.enabled", "https" in tokens, reference)


def _normalize_session_timeout(tree: ConfigTree, controls: ControlSet) -> None:
    """`set admintimeout <minutes>` in `config system global` is FortiOS's idle
    admin-session timeout — the direct analog of Cisco's `exec-timeout`."""
    node = tree.first(r"^set admintimeout (\d+)")
    if not node:
        return
    match = re.search(r"admintimeout (\d+)", node.text)
    assert match is not None
    _record(controls, "management.session_timeout", int(match.group(1)) * 60, node)


def _normalize_admin_trusted_hosts(tree: ConfigTree, controls: ControlSet) -> None:
    """A `set trusthost*` line under a `config system admin` account restricts
    where that account may log in from — FortiOS's analog of Cisco's vty
    `access-class`."""
    admin_block = tree.first(r"^config system admin\s*$")
    if not admin_block:
        return
    trusted = admin_block.find(r"^set trusthost\d")
    _record(
        controls, "management.acl.present", bool(trusted), trusted[0] if trusted else admin_block
    )


def _normalize_password_policy(tree: ConfigTree, controls: ControlSet) -> None:
    """`set minimum-length <n>` in `config system password-policy` is FortiOS's
    equivalent of Cisco's `security passwords min-length`."""
    policy_block = tree.first(r"^config system password-policy\s*$")
    if not policy_block:
        return
    node = policy_block.first(r"^set minimum-length (\d+)")
    if not node:
        return
    match = re.search(r"minimum-length (\d+)", node.text)
    assert match is not None
    _record(controls, "auth.password.min_length", int(match.group(1)), node)


def _normalize_default_admin_account(tree: ConfigTree, controls: ControlSet) -> None:
    """FortiOS's built-in super-admin account is always named literally `admin` —
    the same exact-name heuristic the Cisco normalizer uses for its default
    account list, scoped to the one name FortiOS reserves."""
    admin_block = tree.first(r"^config system admin\s*$")
    if not admin_block:
        return
    accounts = admin_block.find(_EDIT_NAME.pattern)
    if not accounts:
        return
    default = next(
        (
            node
            for node in accounts
            if (match := _EDIT_NAME.search(node.text)) and match.group(1).lower() == "admin"
        ),
        None,
    )
    _record(controls, "auth.default_accounts.present", default is not None, default or accounts[0])


def _normalize_logging(tree: ConfigTree, controls: ControlSet) -> None:
    """`config log disk setting` / `config log syslogd setting`, each with
    `set status enable|disable`, are FortiOS's local-buffer and remote-syslog
    toggles — direct analogs of Cisco's `logging buffered` / `logging host`."""
    disk_block = tree.first(r"^config log disk setting\s*$")
    if disk_block:
        node = disk_block.first(r"^set status (enable|disable)")
        if node:
            _record(controls, "logging.local.enabled", "enable" in node.text.split()[-1], node)

    syslog_block = tree.first(r"^config log syslogd setting\s*$")
    if syslog_block:
        node = syslog_block.first(r"^set status (enable|disable)")
        if node:
            _record(controls, "logging.remote.enabled", "enable" in node.text.split()[-1], node)


def _normalize_ntp(tree: ConfigTree, controls: ControlSet) -> None:
    """`set ntpsync enable|disable` in `config system ntp`."""
    ntp_block = tree.first(r"^config system ntp\s*$")
    if not ntp_block:
        return
    node = ntp_block.first(r"^set ntpsync (enable|disable)")
    if node:
        _record(controls, "time.ntp.enabled", node.text.split()[-1] == "enable", node)


def _normalize_snmp(tree: ConfigTree, controls: ControlSet) -> None:
    """Presence of any `edit` entry under `config system snmp community` means
    legacy v1/v2c access is configured (community strings only exist for those
    versions); presence under `config system snmp user` with no legacy community
    means v3-only — the same precedence Cisco's normalizer applies."""
    community_block = tree.first(r"^config system snmp community\s*$")
    community_entries = community_block.find(_EDIT_NAME.pattern) if community_block else []
    if community_entries:
        _record(controls, "snmp.v3.only", False, community_entries[0])
        return

    user_block = tree.first(r"^config system snmp user\s*$")
    user_entries = user_block.find(_EDIT_NAME.pattern) if user_block else []
    if user_entries:
        _record(controls, "snmp.v3.only", True, user_entries[0])


def _normalize_banner(tree: ConfigTree, controls: ControlSet) -> None:
    """`set pre-login-banner enable|disable` in `config system global` is
    FortiOS's pre-authentication disclaimer — the direct analog of Cisco's
    `banner login`."""
    node = tree.first(r"^set pre-login-banner (enable|disable)")
    if node:
        _record(controls, "banner.login.present", node.text.split()[-1] == "enable", node)


def _collect_unknowns(tree: ConfigTree) -> list[UnknownConstruct]:
    """Every `set` line inside an in-scope (`config system`/`config log`) block that
    no normalizer function above consumed. Out-of-scope blocks (firewall, router,
    vpn, webfilter, ...) are never walked at all — see module docstring."""
    unknowns: list[UnknownConstruct] = []

    def walk(nodes: list[ConfigNode], block: str | None) -> None:
        for node in nodes:
            if not _IGNORED.match(node.text):
                unknowns.append(UnknownConstruct(text=node.text, lineno=node.lineno, block=block))
            if node.children:
                walk(node.children, node.text)

    for root in tree.roots:
        if _UNKNOWN_SCOPE_BLOCKS.match(root.text):
            walk(root.children, root.text)

    return unknowns
