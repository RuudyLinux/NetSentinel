from contextlib import nullcontext

import pytest

from app.services.discovery import scan as scan_module
from app.services.discovery.scan import local_network, scan_cidr


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


def test_scan_finds_only_hosts_with_the_port_open(monkeypatch: pytest.MonkeyPatch) -> None:
    open_hosts = {"10.0.0.1", "10.0.0.3"}

    def fake_create_connection(address: tuple[str, int], timeout: float | None = None) -> object:
        host, _port = address
        if host in open_hosts:
            return nullcontext()
        raise OSError("connection refused")

    monkeypatch.setattr(scan_module.socket, "create_connection", fake_create_connection)
    found = scan_cidr("10.0.0.0/29", port=22)
    assert found == ["10.0.0.1", "10.0.0.3"]


def test_scan_returns_empty_list_when_nothing_responds(monkeypatch: pytest.MonkeyPatch) -> None:
    def always_refused(address: tuple[str, int], timeout: float | None = None) -> object:
        raise OSError("connection refused")

    monkeypatch.setattr(scan_module.socket, "create_connection", always_refused)
    assert scan_cidr("10.0.0.0/29", port=22) == []


def test_a_single_host_range_still_scans_its_own_address(monkeypatch: pytest.MonkeyPatch) -> None:
    def always_open(address: tuple[str, int], timeout: float | None = None) -> object:
        return nullcontext()

    monkeypatch.setattr(scan_module.socket, "create_connection", always_open)
    assert scan_cidr("10.0.0.5/32", port=22) == ["10.0.0.5"]


def test_oversized_range_is_rejected_without_scanning(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(address: tuple[str, int], timeout: float | None = None) -> object:
        raise AssertionError("scan should have been rejected before probing any host")

    monkeypatch.setattr(scan_module.socket, "create_connection", fail_if_called)
    with pytest.raises(ValueError, match="capped"):
        scan_cidr("10.0.0.0/23", port=22)


def test_invalid_cidr_raises_value_error() -> None:
    with pytest.raises(ValueError):
        scan_cidr("not-a-cidr", port=22)


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
