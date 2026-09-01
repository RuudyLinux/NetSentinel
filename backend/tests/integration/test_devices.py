import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditEvent
from app.services.discovery.scan import DiscoveredHost


def test_local_network_returns_the_detected_cidr(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.devices.local_network", lambda: "192.168.1.0/24")
    response = client.get(
        "/api/v1/devices/local-network", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"cidr": "192.168.1.0/24"}


def test_local_network_failure_is_service_unavailable(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_no_route() -> str:
        raise OSError("network is unreachable")

    monkeypatch.setattr("app.api.devices.local_network", raise_no_route)
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


def test_discover_returns_the_mocked_hosts_with_device_name_unknown(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.api.devices.discover_ssh",
        lambda cidr, ports: [
            DiscoveredHost(ip="10.0.0.1", port=22),
            DiscoveredHost(ip="10.0.0.4", port=2222),
        ],
    )
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/29", "ports": [22, 2222]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "hosts": [
            {"device_name": "Unknown", "ip": "10.0.0.1", "port": 22},
            {"device_name": "Unknown", "ip": "10.0.0.4", "port": 2222},
        ]
    }


def test_discover_rejects_an_oversized_range(client: TestClient, admin_token: str) -> None:
    # No mock: discover_ssh rejects a /23 before touching any socket, so this exercises
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
    monkeypatch.setattr("app.api.devices.discover_ssh", lambda cidr, ports: [])
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
    monkeypatch.setattr("app.api.devices.discover_ssh", lambda cidr, ports: [])
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
