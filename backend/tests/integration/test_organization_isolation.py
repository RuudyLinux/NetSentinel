"""Cross-organization IDOR regression tests.

Every resource-by-ID endpoint in this codebase checks `resource.organization_id
== user.organization_id` before returning anything (see the security audit this
suite exists to backstop). That check is currently correct everywhere but is
implemented by hand, once per endpoint — nothing central enforces it. Without a
second organization to test against, a future refactor that silently drops one
of those checks would go undetected indefinitely. This file is that fixture in
use: org A creates a resource, org B (a full Platform Admin, so no permission
gap could explain a rejection) must never be able to reach it by ID.
"""

from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _upload(client: TestClient, token: str, name: str = "compliant") -> int:
    data = (DATASETS / f"{name}.cfg").read_bytes()
    response = client.post(
        "/api/v1/configurations/upload",
        files={"file": (f"{name}.cfg", data, "text/plain")},
        headers=_auth(token),
    )
    assert response.status_code in (200, 201), response.text
    return int(response.json()["id"])


def _run_audit(client: TestClient, token: str, configuration_id: int) -> int:
    response = client.post(
        "/api/v1/audits",
        json={"configuration_id": configuration_id, "framework": "CIS"},
        headers=_auth(token),
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _first_finding_id(client: TestClient, token: str, audit_id: int) -> int:
    response = client.get("/api/v1/findings", params={"audit_id": audit_id}, headers=_auth(token))
    assert response.status_code == 200, response.text
    findings = response.json()
    assert findings, "noncompliant.cfg must produce at least one finding"
    return int(findings[0]["id"])


def test_device_from_another_org_is_not_reachable(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token)
    device_id = client.get(
        f"/api/v1/configurations/{config_id}", headers=_auth(admin_token)
    ).json()["device"]["id"]

    assert (
        client.get(f"/api/v1/devices/{device_id}", headers=_auth(second_org_token)).status_code
        == 404
    )


def test_configuration_from_another_org_is_not_reachable(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token)

    response = client.get(f"/api/v1/configurations/{config_id}", headers=_auth(second_org_token))
    assert response.status_code == 404


def test_audit_from_another_org_is_not_reachable(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token)
    audit_id = _run_audit(client, admin_token, config_id)

    assert (
        client.get(f"/api/v1/audits/{audit_id}", headers=_auth(second_org_token)).status_code == 404
    )
    # Cross-org configuration_id must not let the other org start its own audit
    # against a device it doesn't own, either.
    forged = client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "CIS"},
        headers=_auth(second_org_token),
    )
    assert forged.status_code == 404


def test_audit_list_never_includes_another_orgs_runs(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token)
    audit_id = _run_audit(client, admin_token, config_id)

    other_orgs_view = client.get("/api/v1/audits", headers=_auth(second_org_token)).json()
    assert audit_id not in {item["id"] for item in other_orgs_view}


def test_finding_from_another_org_is_not_reachable(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token, "noncompliant")
    audit_id = _run_audit(client, admin_token, config_id)
    finding_id = _first_finding_id(client, admin_token, audit_id)

    assert (
        client.get(f"/api/v1/findings/{finding_id}", headers=_auth(second_org_token)).status_code
        == 404
    )
    # Nor may the other org triage a finding it cannot even see.
    triage = client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"triage_status": "resolved"},
        headers=_auth(second_org_token),
    )
    assert triage.status_code == 404


def test_finding_list_never_includes_another_orgs_findings(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token, "noncompliant")
    audit_id = _run_audit(client, admin_token, config_id)
    finding_id = _first_finding_id(client, admin_token, audit_id)

    other_orgs_view = client.get("/api/v1/findings", headers=_auth(second_org_token)).json()
    assert finding_id not in {item["id"] for item in other_orgs_view}


def test_report_from_another_org_is_not_reachable(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token)
    audit_id = _run_audit(client, admin_token, config_id)
    report_id = client.post(f"/api/v1/audits/{audit_id}/report", headers=_auth(admin_token)).json()[
        "id"
    ]

    assert (
        client.get(f"/api/v1/reports/{report_id}", headers=_auth(second_org_token)).status_code
        == 404
    )
    # Nor may the other org generate its own report against an audit it doesn't own.
    forged = client.post(f"/api/v1/audits/{audit_id}/report", headers=_auth(second_org_token))
    assert forged.status_code == 404


def test_unknown_constructs_from_another_org_are_not_reachable(
    client: TestClient, admin_token: str, second_org_token: str
) -> None:
    config_id = _upload(client, admin_token, "mixed")
    audit_id = _run_audit(client, admin_token, config_id)

    assert (
        client.get(
            f"/api/v1/audits/{audit_id}/unknown-constructs", headers=_auth(second_org_token)
        ).status_code
        == 404
    )
    forged = client.post(
        f"/api/v1/audits/{audit_id}/unknown-constructs/0/interpret",
        headers=_auth(second_org_token),
    )
    assert forged.status_code == 404
