from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def audit(client: TestClient, token: str, name: str) -> int:
    headers = {"Authorization": f"Bearer {token}"}
    data = (DATASETS / f"{name}.cfg").read_bytes()
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": (f"{name}.cfg", data, "text/plain")},
        headers=headers,
    ).json()["id"]
    return int(
        client.post(
            "/api/v1/audits",
            json={"configuration_id": config_id, "framework": "CIS"},
            headers=headers,
        ).json()["id"]
    )


def test_report_generation_returns_a_pdf(client: TestClient, admin_token: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    audit_id = audit(client, admin_token, "noncompliant")

    created = client.post(f"/api/v1/audits/{audit_id}/report", headers=headers)
    assert created.status_code == 201, created.text

    downloaded = client.get(f"/api/v1/reports/{created.json()['id']}", headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"] == "application/pdf"
    assert downloaded.content.startswith(b"%PDF-")
    assert len(downloaded.content) > 2000


def test_report_contains_no_secret_material(client: TestClient, admin_token: str) -> None:
    """The PDF is an export path; redaction must hold all the way through it."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    audit_id = audit(client, admin_token, "noncompliant")
    report_id = client.post(f"/api/v1/audits/{audit_id}/report", headers=headers).json()["id"]
    content = client.get(f"/api/v1/reports/{report_id}", headers=headers).content

    raw = (DATASETS / "noncompliant.cfg").read_text(encoding="utf-8")
    for line in raw.splitlines():
        if "password 7 " in line:
            assert line.split("password 7 ")[1].strip().encode() not in content


def test_report_generation_requires_permission(client: TestClient, admin_token: str) -> None:
    audit_id = audit(client, admin_token, "compliant")
    # Every seeded role holds REPORT_GENERATE, so assert the route is guarded at all
    # by calling it without a token.
    assert client.post(f"/api/v1/audits/{audit_id}/report").status_code == 401


def test_report_records_its_audit_and_generator(client: TestClient, admin_token: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    audit_id = audit(client, admin_token, "mixed")
    body = client.post(f"/api/v1/audits/{audit_id}/report", headers=headers).json()
    assert body["audit_run_id"] == audit_id
    assert body["id"]
