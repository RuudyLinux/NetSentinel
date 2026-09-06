from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def upload_and_audit(client: TestClient, token: str, name: str) -> dict:
    data = (DATASETS / f"{name}.cfg").read_bytes()
    headers = {"Authorization": f"Bearer {token}"}
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": (f"{name}.cfg", data, "text/plain")},
        headers=headers,
    ).json()["id"]
    response = client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "CIS"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_list_frameworks_returns_the_loaded_rule_pack(client: TestClient, admin_token: str) -> None:
    response = client.get("/api/v1/frameworks", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    frameworks = response.json()
    assert any(f["framework"] == "CIS" for f in frameworks)


def test_compliance_is_empty_before_any_audit(client: TestClient, admin_token: str) -> None:
    response = client.get(
        "/api/v1/frameworks/CIS/compliance", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["score"] is None
    assert body["devices_assessed"] == 0
    assert body["pass_count"] == 0
    assert body["fail_count"] == 0


def test_compliance_unknown_framework_is_404(client: TestClient, admin_token: str) -> None:
    response = client.get(
        "/api/v1/frameworks/NOPE/compliance", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 404


def test_compliance_aggregates_across_devices(client: TestClient, admin_token: str) -> None:
    upload_and_audit(client, admin_token, "compliant")
    upload_and_audit(client, admin_token, "noncompliant")

    response = client.get(
        "/api/v1/frameworks/CIS/compliance", headers={"Authorization": f"Bearer {admin_token}"}
    )
    body = response.json()
    assert body["devices_assessed"] == 2
    assert body["pass_count"] > 0
    assert body["fail_count"] > 0
    assert body["score"] == 50  # mean of 100 (compliant) and 0 (noncompliant)


def test_compliance_uses_only_the_latest_run_per_device(
    client: TestClient, admin_token: str
) -> None:
    data = (DATASETS / "noncompliant.cfg").read_bytes()
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("noncompliant.cfg", data, "text/plain")},
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()["id"]
    client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "CIS"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    # Same device, second (identical) run — compliance must not double-count it.
    client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "CIS"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    response = client.get(
        "/api/v1/frameworks/CIS/compliance", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.json()["devices_assessed"] == 1


def test_audits_can_be_filtered_by_framework(client: TestClient, admin_token: str) -> None:
    upload_and_audit(client, admin_token, "compliant")
    response = client.get(
        "/api/v1/audits?framework=CIS", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert (
        client.get(
            "/api/v1/audits?framework=NIST", headers={"Authorization": f"Bearer {admin_token}"}
        ).json()
        == []
    )


def test_findings_can_be_filtered_by_framework(client: TestClient, admin_token: str) -> None:
    upload_and_audit(client, admin_token, "noncompliant")
    response = client.get(
        "/api/v1/findings?framework=CIS", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert len(response.json()) > 0
    assert (
        client.get(
            "/api/v1/findings?framework=NIST", headers={"Authorization": f"Bearer {admin_token}"}
        ).json()
        == []
    )
