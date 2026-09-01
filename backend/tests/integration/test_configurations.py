import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditEvent
from app.services.ingestion.connect import DeviceConnectionError


def connect_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "host": "10.0.0.9",
        "port": 22,
        "username": "netops",
        "password": "correct-horse",
        "enable_password": "enable-secret",
    }
    payload.update(overrides)
    return payload


def test_connect_ingests_the_fetched_config(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.api.configurations.fetch_running_config",
        lambda *a, **k: "hostname mocked-device\nend\n",
    )
    response = client.post(
        "/api/v1/configurations/connect",
        json=connect_payload(),
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["device"]["name"] == "mocked-device"
    assert body["device"]["vendor"] == "cisco"
    # Same shape as an uploaded Configuration — the audit-run pipeline itself (detection,
    # scoring, findings) is already covered end to end by test_audits.py against this
    # same ConfigurationOut contract; nothing about it differs for a connect-sourced row.


def test_connect_failure_surfaces_as_bad_gateway(
    client: TestClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_connection_error(*_a: object, **_k: object) -> str:
        raise DeviceConnectionError("could not fetch config from 10.0.0.9:22 (timed out)")

    monkeypatch.setattr("app.api.configurations.fetch_running_config", raise_connection_error)
    response = client.post(
        "/api/v1/configurations/connect",
        json=connect_payload(),
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 502


def test_connect_requires_config_upload_permission(
    client: TestClient, ciso_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.api.configurations.fetch_running_config",
        lambda *a, **k: "hostname mocked-device\nend\n",
    )
    response = client.post(
        "/api/v1/configurations/connect",
        json=connect_payload(),
        headers={"Authorization": f"Bearer {ciso_token}"},
    )
    assert response.status_code == 403


def test_connect_audit_event_records_host_never_credentials(
    client: TestClient,
    admin_token: str,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.api.configurations.fetch_running_config",
        lambda *a, **k: "hostname mocked-device\nend\n",
    )
    response = client.post(
        "/api/v1/configurations/connect",
        json=connect_payload(host="10.0.0.42", password="super-secret-password"),
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 201, response.text

    with session_factory() as session:
        event = session.scalar(select(AuditEvent).where(AuditEvent.action == "CONNECT_DEVICE"))
        assert event is not None
        assert event.resource == "10.0.0.42"
        assert "super-secret-password" not in event.resource
