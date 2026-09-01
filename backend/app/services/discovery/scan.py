import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

# Bounds a single scan to at most a /24 — keeps request latency and network
# blast-radius small regardless of what CIDR an operator types in.
_MAX_HOSTS = 256
_DEFAULT_TIMEOUT = 0.5
_MAX_WORKERS = 64


def _probe(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return host
    except OSError:
        return None


def scan_cidr(cidr: str, port: int = 22, timeout: float = _DEFAULT_TIMEOUT) -> list[str]:
    """Probe every host in a CIDR range for an open TCP port, returning the ones that answer.

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

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        found = pool.map(lambda ip: _probe(str(ip), port, timeout), hosts)

    return sorted(
        (ip for ip in found if ip is not None), key=lambda ip: int(ipaddress.ip_address(ip))
    )
