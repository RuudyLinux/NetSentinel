import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditEvent
from app.services.discovery.scan import DiscoveredHost, NetworkInfo


def test_local_network_returns_the_detected_network(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.api.devices.detect_network",
        lambda: NetworkInfo(interface="Wi-Fi", local_ip="192.168.1.42", cidr="192.168.1.0/24"),
    )
    response = client.get(
        "/api/v1/devices/local-network", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "interface": "Wi-Fi",
        "local_ip": "192.168.1.42",
        "cidr": "192.168.1.0/24",
    }


def test_local_network_failure_is_service_unavailable(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_no_route() -> NetworkInfo:
        raise OSError("network is unreachable")

    monkeypatch.setattr("app.api.devices.detect_network", raise_no_route)
    response = client.get(
        "/api/v1/devices/local-network", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 503


def test_local_network_requires_the_config_upload_permission(
    client: TestClient, ciso_token: str
) -> None:
    response = client.get(
        "/api/v1/devices/local-network", headers={"Authorization": f"Bearer {ciso_token}"}
    )
    assert response.status_code == 403


def test_discover_returns_ssh_available_and_ssh_unavailable_hosts(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.api.devices.discover_hosts",
        lambda cidr, ports: [
            DiscoveredHost(ip="10.0.0.1", status="ssh_unavailable"),
            DiscoveredHost(ip="10.0.0.10", status="ssh_available", port=22, vendor="Cisco"),
            DiscoveredHost(ip="10.0.0.20", status="ssh_available", port=2222, vendor=None),
        ],
    )
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/24", "ports": [22, 2222]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "hosts": [
            {
                "device_name": "Unknown",
                "ip": "10.0.0.1",
                "status": "ssh_unavailable",
                "port": None,
                "vendor": None,
            },
            {
                "device_name": "Unknown",
                "ip": "10.0.0.10",
                "status": "ssh_available",
                "port": 22,
                "vendor": "Cisco",
            },
            {
                "device_name": "Unknown",
                "ip": "10.0.0.20",
                "status": "ssh_available",
                "port": 2222,
                "vendor": None,
            },
        ]
    }


def test_discover_rejects_an_oversized_range(client: TestClient, admin_token: str) -> None:
    # No mock: discover_hosts rejects a /23 before touching any socket, so this exercises
    # the real cap with no network I/O involved.
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/23"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 422


def test_discover_requires_the_config_upload_permission(
    client: TestClient, ciso_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.devices.discover_hosts", lambda cidr, ports: [])
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/29"},
        headers={"Authorization": f"Bearer {ciso_token}"},
    )
    assert response.status_code == 403


def test_discover_audit_event_records_the_range_scanned(
    client: TestClient,
    admin_token: str,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.api.devices.discover_hosts", lambda cidr, ports: [])
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/29"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text

    with session_factory() as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.action == "DISCOVER_DEVICES"))
        assert event is not None
        assert event.resource == "10.0.0.0/29"
