from contextlib import nullcontext

import pytest

from app.services.discovery import scan as scan_module
from app.services.discovery.scan import scan_cidr


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
