import pytest

from app.services.discovery import scan as scan_module
from app.services.discovery.scan import DiscoveredHost, discover_ssh, local_network


class _FakeUDPSocket:
    """Stands in for the throwaway UDP socket local_network() uses to ask the OS which
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


class _FakeBannerSocket:
    """Stands in for the connected socket _probe_ssh() reads a banner from."""

    def __init__(self, banner: bytes) -> None:
        self._banner = banner

    def __enter__(self) -> "_FakeBannerSocket":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def settimeout(self, timeout: float | None) -> None:
        pass

    def recv(self, size: int) -> bytes:
        return self._banner


def _fake_create_connection(
    responses: dict[tuple[str, int], bytes],
) -> object:
    def create_connection(address: tuple[str, int], timeout: float | None = None) -> object:
        if address in responses:
            return _FakeBannerSocket(responses[address])
        raise OSError("connection refused")

    return create_connection


def test_discover_ssh_identifies_which_port_is_actually_ssh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        ("10.0.0.1", 22): b"SSH-2.0-OpenSSH_9.6",
        ("10.0.0.2", 22): b"HTTP/1.1 400 Bad Request",  # open, but not SSH
        ("10.0.0.2", 2222): b"SSH-2.0-Cisco-1.25",
        # 10.0.0.3..6: nothing open at all
    }
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))

    found = discover_ssh("10.0.0.0/29", ports=(22, 2222))

    assert found == [
        DiscoveredHost(ip="10.0.0.1", port=22),
        DiscoveredHost(ip="10.0.0.2", port=2222),
    ]


def test_discover_ssh_returns_empty_when_nothing_speaks_ssh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {("10.0.0.1", 22): b"HTTP/1.1 400 Bad Request"}
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))
    assert discover_ssh("10.0.0.0/29", ports=(22, 2222)) == []


def test_discover_ssh_respects_a_custom_port_list(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {("10.0.0.1", 2200): b"SSH-2.0-dropbear"}
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))
    # 22 and 2222 (the defaults) aren't in `ports`, so they're never tried.
    assert discover_ssh("10.0.0.0/29", ports=(2200,)) == [DiscoveredHost(ip="10.0.0.1", port=2200)]


def test_a_single_host_range_still_scans_its_own_address(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {("10.0.0.5", 22): b"SSH-2.0-OpenSSH_9.6"}
    monkeypatch.setattr(scan_module.socket, "create_connection", _fake_create_connection(responses))
    assert discover_ssh("10.0.0.5/32") == [DiscoveredHost(ip="10.0.0.5", port=22)]


def test_oversized_range_is_rejected_without_scanning(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(address: tuple[str, int], timeout: float | None = None) -> object:
        raise AssertionError("scan should have been rejected before probing any host")

    monkeypatch.setattr(scan_module.socket, "create_connection", fail_if_called)
    with pytest.raises(ValueError, match="capped"):
        discover_ssh("10.0.0.0/23")


def test_invalid_cidr_raises_value_error() -> None:
    with pytest.raises(ValueError):
        discover_ssh("not-a-cidr")


def test_local_network_derives_the_24_containing_the_outbound_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _FakeUDPSocket())
    assert local_network() == "192.168.1.0/24"


def test_local_network_honors_a_different_prefix_length(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _FakeUDPSocket())
    assert local_network(prefix_length=16) == "192.168.0.0/16"


def test_local_network_propagates_a_real_interface_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoRoute(_FakeUDPSocket):
        def connect(self, address: tuple[str, int]) -> None:
            raise OSError("network is unreachable")

    monkeypatch.setattr(scan_module.socket, "socket", lambda *a, **k: _NoRoute())
    with pytest.raises(OSError, match="unreachable"):
        local_network()
