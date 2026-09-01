from dataclasses import dataclass

import pytest

from app.services.discovery import scan as scan_module
from app.services.discovery.scan import DiscoveredHost, detect_network, discover_hosts


class _FakeUDPSocket:
    """Stands in for the throwaway UDP socket detect_network() uses to ask the OS which
    local address it would route outbound traffic through."""

    def __init__(self, local_ip: str = "192.168.1.42") -> None:
        self._local_ip = local_ip

    def __enter__(self) -> "_FakeUDPSocket":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def connect(self, address: tuple[str, int]) -> None:
        pass

    def getsockname(self) -> tuple[str, int]:
        return (self._local_ip, 54321)


@dataclass
class _FakeAddr:
    family: object
    address: str
    netmask: str | None


class _FakeBannerSocket:
    """Stands in for a connected socket — used for both the SSH-banner read and the
    plain reachability check (which never calls recv)."""

    def __init__(self, banner: bytes = b"") -> None:
        self._banner = banner

    def __enter__(self) -> "_FakeBannerSocket":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def settimeout(self, timeout: float | None) -> None:
        pass

    def recv(self, size: int) -> bytes:
        return self._banner


def _fake_create_connection(responses: dict[tuple[str, int], bytes]) -> object:
    def create_connection(address: tuple[str, int], timeout: float | None = None) -> object:
        if address in responses:
            return _FakeBannerSocket(responses[address])
        raise OSError("connection refused")

    return create_connection


def test_discover_hosts_identifies_which_port_is_actually_ssh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        ("10.0.0.1", 22): b"SSH-2.0-OpenSSH_9.6",
        ("10.0.0.2", 22): b"HTTP/1.1 400 Bad Request",  # open, but not SSH
        ("10.0.0.2", 2222): b"SSH-2.0-Cisco-1.25",
        # 10.0.0.3..6: nothing open at all
    }
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))

    found = discover_hosts("10.0.0.0/29", ssh_ports=(22, 2222))

    assert found == [
        DiscoveredHost(ip="10.0.0.1", status="ssh_available", port=22, vendor=None),
        DiscoveredHost(ip="10.0.0.2", status="ssh_available", port=2222, vendor="Cisco"),
    ]


def test_discover_hosts_reports_a_reachable_host_with_no_ssh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Nothing answers SSH on 22/2222, but port 80 (a reachability fallback) does — e.g. a
    # home router's web UI. Matches the "SSH unavailable" row from the request's example.
    responses = {("10.0.0.1", 80): b""}
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))

    found = discover_hosts("10.0.0.1/32")

    assert found == [DiscoveredHost(ip="10.0.0.1", status="ssh_unavailable")]


def test_discover_hosts_omits_a_host_that_answers_nothing_at_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection({}))
    assert discover_hosts("10.0.0.1/32") == []


def test_discover_hosts_respects_a_custom_ssh_port_list(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {("10.0.0.1", 2200): b"SSH-2.0-dropbear"}
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))
    # 22 and 2222 (the defaults) aren't in `ssh_ports`, so they're never tried.
    found = discover_hosts("10.0.0.0/29", ssh_ports=(2200,))
    assert found == [DiscoveredHost(ip="10.0.0.1", status="ssh_available", port=2200, vendor=None)]


def test_a_single_host_range_still_scans_its_own_address(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {("10.0.0.5", 22): b"SSH-2.0-OpenSSH_9.6"}
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))
    found = discover_hosts("10.0.0.5/32")
    assert found == [DiscoveredHost(ip="10.0.0.5", status="ssh_available", port=22, vendor=None)]


def test_oversized_range_is_rejected_without_scanning(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(address: tuple[str, int], timeout: float | None = None) -> object:
        raise AssertionError("scan should have been rejected before probing any host")

    monkeypatch.setattr(scan_module.socket, "create_connection", fail_if_called)
    with pytest.raises(ValueError, match="capped"):
        discover_hosts("10.0.0.0/23")


def test_invalid_cidr_raises_value_error() -> None:
    with pytest.raises(ValueError):
        discover_hosts("not-a-cidr")


def test_detect_network_reports_the_matching_interface_and_real_netmask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket as real_socket

    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _FakeUDPSocket())
    monkeypatch.setattr(
        scan_module.psutil,
        "net_if_addrs",
        lambda: {
            "Loopback": [_FakeAddr(real_socket.AF_INET, "127.0.0.1", "255.0.0.0")],
            "Wi-Fi": [_FakeAddr(real_socket.AF_INET, "192.168.1.42", "255.255.255.0")],
        },
    )

    info = detect_network()

    assert info.interface == "Wi-Fi"
    assert info.local_ip == "192.168.1.42"
    assert info.cidr == "192.168.1.0/24"


def test_detect_network_honors_a_non_24_netmask(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket as real_socket

    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _FakeUDPSocket())
    monkeypatch.setattr(
        scan_module.psutil,
        "net_if_addrs",
        lambda: {"Ethernet": [_FakeAddr(real_socket.AF_INET, "192.168.1.42", "255.255.254.0")]},
    )
    assert detect_network().cidr == "192.168.0.0/23"


def test_detect_network_raises_when_no_interface_matches_the_outbound_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _FakeUDPSocket())
    monkeypatch.setattr(scan_module.psutil, "net_if_addrs", lambda: {})
    with pytest.raises(OSError, match="could not match"):
        detect_network()


def test_detect_network_rejects_a_loopback_outbound_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _FakeUDPSocket("127.0.0.1"))
    with pytest.raises(OSError, match="loopback"):
        detect_network()


def test_detect_network_propagates_a_real_interface_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoRoute(_FakeUDPSocket):
        def connect(self, address: tuple[str, int]) -> None:
            raise OSError("network is unreachable")

    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _NoRoute())
    with pytest.raises(OSError, match="unreachable"):
        detect_network()
