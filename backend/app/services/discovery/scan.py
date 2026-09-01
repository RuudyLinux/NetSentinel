import ipaddress
import socket
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal

import psutil

# Bounds a single scan to at most a /24 — keeps request latency and network
# blast-radius small regardless of what CIDR an operator types in.
_MAX_HOSTS = 256
_DEFAULT_TIMEOUT = 0.5
_MAX_WORKERS = 64

# Checked in order per host; the first one that actually answers with an SSH banner wins.
# Covers the standard port plus the most common non-standard choice — an operator whose
# device uses something else can still connect manually with that port.
DEFAULT_SSH_PORTS: tuple[int, ...] = (22, 2222)

# Tried only when every SSH candidate port fails, purely to tell "nothing here" apart from
# "something's here, just not SSH" for the status column. This is a heuristic, not ground
# truth: real host discovery would need ICMP/ARP, which needs raw sockets (admin on
# Windows) or a new heavy dependency (scapy + npcap) — deliberately not doing that here. A
# host with every one of these ports firewalled won't show up at all, same as before.
_REACHABILITY_PORTS: tuple[int, ...] = (80, 443, 3389)

# Case-insensitive substrings checked against an SSH banner (e.g. "SSH-2.0-Cisco-1.25")
# to best-effort guess the vendor. Not active fingerprinting — just reading text already
# fetched to confirm SSH in the first place.
_VENDOR_BANNER_MARKERS: tuple[tuple[str, str], ...] = (
    ("cisco", "Cisco"),
    ("juniper", "Juniper"),
    ("arista", "Arista"),
    ("mikrotik", "MikroTik"),
    ("rosssh", "MikroTik"),
    ("huawei", "Huawei"),
    ("fortinet", "Fortinet"),
    ("fortissh", "Fortinet"),
    ("paloalto", "Palo Alto"),
)

Status = Literal["ssh_available", "ssh_unavailable"]


def _hosts_in_range(cidr: str) -> list[str]:
    """Parse a CIDR into its scannable host addresses.

    Raises ValueError for an unparseable CIDR or one exceeding the /24 (256-address) cap.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    # ip_network().hosts() excludes the network/broadcast addresses, which is empty for a
    # /31 or /32 — fall back to the address itself so a single-host "range" still scans.
    hosts = list(network.hosts()) if network.num_addresses > 2 else [network.network_address]
    if len(hosts) > _MAX_HOSTS:
        raise ValueError(
            f"{cidr!r} has {len(hosts)} addresses; scans are capped at {_MAX_HOSTS} (a /24)"
        )
    return [str(ip) for ip in hosts]


def _read_ssh_banner(host: str, port: int, timeout: float) -> bytes | None:
    """Open the port and read its banner. Returns None for anything but a real SSH
    greeting — an open port alone isn't proof of SSH."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(32)
            return banner if banner.startswith(b"SSH-") else None
    except OSError:
        return None


def _is_reachable(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _guess_vendor(banner: bytes) -> str | None:
    text = banner.decode("ascii", errors="ignore").lower()
    for marker, vendor in _VENDOR_BANNER_MARKERS:
        if marker in text:
            return vendor
    return None


@dataclass(frozen=True)
class DiscoveredHost:
    ip: str
    status: Status
    port: int | None = None
    vendor: str | None = None


def discover_hosts(
    cidr: str,
    ssh_ports: Sequence[int] = DEFAULT_SSH_PORTS,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[DiscoveredHost]:
    """Find hosts in a CIDR range that are either running SSH or otherwise reachable.

    Per host: try each of `ssh_ports` in order, banner-verified, and stop at the first
    real SSH match (`status="ssh_available"`, with a best-effort vendor guess from the
    banner text). If none match, fall back to a short reachability probe
    (`status="ssh_unavailable"`, no port/vendor). A host that answers nothing at all is
    omitted — this only ever reports hosts that responded to *something*.
    """
    hosts = _hosts_in_range(cidr)

    def probe(ip: str) -> DiscoveredHost | None:
        for port in ssh_ports:
            banner = _read_ssh_banner(ip, port, timeout)
            if banner is not None:
                return DiscoveredHost(
                    ip=ip, status="ssh_available", port=port, vendor=_guess_vendor(banner)
                )
        for port in _REACHABILITY_PORTS:
            if _is_reachable(ip, port, timeout):
                return DiscoveredHost(ip=ip, status="ssh_unavailable")
        return None

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        found = list(pool.map(probe, hosts))

    results = [host for host in found if host is not None]
    results.sort(key=lambda host: int(ipaddress.ip_address(host.ip)))
    return results


@dataclass(frozen=True)
class NetworkInfo:
    interface: str
    local_ip: str
    cidr: str


def detect_network() -> NetworkInfo:
    """Identify the active local network: which interface the OS would actually route
    outbound traffic through, its address, and its real subnet (not an assumed /24).

    Opens no real connection — a UDP "connect" just asks the OS which local interface/
    address it would use, without sending a packet. Raises OSError if that address can't
    be matched to a live interface (no usable network, or a transient race with an
    interface coming up/down) — the caller turns this into a clean error response rather
    than guessing.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("8.8.8.8", 80))
        local_ip = probe.getsockname()[0]

    if local_ip.startswith("127."):
        # The OS should never route external traffic via loopback; this guards against
        # a misbehaving/virtualized network stack rather than a case seen in practice.
        raise OSError("outbound route resolved to loopback, not a real interface")

    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                network = ipaddress.ip_network(f"{local_ip}/{addr.netmask}", strict=False)
                return NetworkInfo(interface=name, local_ip=local_ip, cidr=str(network))

    raise OSError(f"could not match outbound address {local_ip} to a local interface")
