import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditEvent


def test_discover_returns_the_mocked_hosts(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.devices.scan_cidr", lambda cidr, port: ["10.0.0.1", "10.0.0.4"])
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/29", "port": 22},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"hosts": ["10.0.0.1", "10.0.0.4"], "port": 22}


def test_discover_rejects_an_oversized_range(client: TestClient, admin_token: str) -> None:
    # No mock: scan_cidr rejects a /23 before touching any socket, so this exercises
    # the real cap with no network I/O involved.
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/23", "port": 22},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 422


def test_discover_requires_the_config_upload_permission(
    client: TestClient, ciso_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.devices.scan_cidr", lambda cidr, port: [])
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/29", "port": 22},
        headers={"Authorization": f"Bearer {ciso_token}"},
    )
    assert response.status_code == 403


def test_discover_audit_event_records_the_range_scanned(
    client: TestClient,
    admin_token: str,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.api.devices.scan_cidr", lambda cidr, port: [])
    response = client.post(
        "/api/v1/devices/discover",
        json={"cidr": "10.0.0.0/29", "port": 22},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text

    with session_factory() as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.action == "DISCOVER_DEVICES"))
        assert event is not None
        assert event.resource == "10.0.0.0/29"
