import ipaddress
import socket
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

# Bounds a single scan to at most a /24 — keeps request latency and network
# blast-radius small regardless of what CIDR an operator types in.
_MAX_HOSTS = 256
_DEFAULT_TIMEOUT = 0.5
_MAX_WORKERS = 64

# Checked in order per host; the first one that actually answers with an SSH banner wins.
# Covers the standard port plus the most common non-standard choice — an operator whose
# device uses something else can still connect manually with that port.
DEFAULT_SSH_PORTS: tuple[int, ...] = (22, 2222)


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


def _probe_ssh(host: str, port: int, timeout: float) -> bool:
    """Open the port and read its banner — an open port alone isn't proof of SSH."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(32).startswith(b"SSH-")
    except OSError:
        return False


@dataclass(frozen=True)
class DiscoveredHost:
    ip: str
    port: int


def discover_ssh(
    cidr: str,
    ports: Sequence[int] = DEFAULT_SSH_PORTS,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[DiscoveredHost]:
    """Find hosts in a CIDR range actually running SSH, and which port it's on.

    Tries each of `ports` per host, in order, and stops at the first one that answers
    with a real SSH banner — most devices run a single SSH port, so this identifies
    *which* one, rather than claiming a host couldn't also listen elsewhere.
    """
    hosts = _hosts_in_range(cidr)

    def probe(ip: str) -> DiscoveredHost | None:
        for port in ports:
            if _probe_ssh(ip, port, timeout):
                return DiscoveredHost(ip=ip, port=port)
        return None

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        found = list(pool.map(probe, hosts))

    results = [host for host in found if host is not None]
    results.sort(key=lambda host: int(ipaddress.ip_address(host.ip)))
    return results


def local_network(prefix_length: int = 24) -> str:
    """Best-effort guess at the server's own local subnet, to pre-fill a scan range.

    Opens no real connection — a UDP "connect" just asks the OS which local interface/
    address it would route through, without sending a packet. Raises OSError if the host
    has no usable network interface.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("8.8.8.8", 80))
        local_ip = probe.getsockname()[0]
    return str(ipaddress.ip_interface(f"{local_ip}/{prefix_length}").network)
