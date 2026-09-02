from pathlib import Path

from fastapi.testclient import TestClient

# Small local helpers, matching the existing per-file convention (test_audits.py,
# test_findings.py each define their own rather than sharing via conftest.py).
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


def get_summary(client: TestClient, token: str):
    return client.get("/api/v1/dashboard/summary", headers={"Authorization": f"Bearer {token}"})


def test_summary_requires_a_token(client: TestClient) -> None:
    assert client.get("/api/v1/dashboard/summary").status_code == 401


def test_summary_before_any_audit_is_empty_but_not_broken(
    client: TestClient, admin_token: str
) -> None:
    body = get_summary(client, admin_token).json()
    assert body["security_score"] is None
    assert body["security_score_previous"] is None
    assert body["audits_total"] == 0
    assert body["devices_needing_attention"] == 0
    assert body["framework_scores"] == []
    assert body["risk_trend"] == []
    assert body["recent_findings"] == []


def test_summary_reflects_the_latest_audit(client: TestClient, admin_token: str) -> None:
    upload_and_audit(client, admin_token, "compliant")
    body = get_summary(client, admin_token).json()
    assert body["security_score"] == 100
    assert body["audits_total"] == 1
    assert body["devices_needing_attention"] == 0
    assert len(body["framework_scores"]) == 1
    assert body["framework_scores"][0]["framework"] == "CIS"
    assert body["framework_scores"][0]["score"] == 100
    assert body["framework_scores"][0]["coverage"] == 1.0
    assert len(body["risk_trend"]) == 1
    assert body["risk_trend"][0]["score"] == 100


def test_summary_flags_a_device_with_a_failing_audit_and_lists_its_finding(
    client: TestClient, admin_token: str
) -> None:
    upload_and_audit(client, admin_token, "noncompliant")
    body = get_summary(client, admin_token).json()
    assert body["security_score"] == 0
    assert body["devices_needing_attention"] == 1
    assert body["critical_findings_open"] >= 1
    assert body["critical_findings_new_7d"] == body["critical_findings_open"]
    assert len(body["recent_findings"]) >= 1
    assert body["recent_findings"][0]["device_name"]


def test_summary_tracks_the_previous_score_across_two_audits(
    client: TestClient, admin_token: str
) -> None:
    upload_and_audit(client, admin_token, "noncompliant")
    upload_and_audit(client, admin_token, "compliant")
    body = get_summary(client, admin_token).json()
    assert body["security_score"] == 100
    assert body["security_score_previous"] == 0
    assert body["audits_total"] == 2


def test_ciso_can_read_the_dashboard_read_only(client: TestClient, ciso_token: str) -> None:
    assert get_summary(client, ciso_token).status_code == 200
