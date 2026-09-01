from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def audit_noncompliant(client: TestClient, token: str) -> int:
    data = (DATASETS / "noncompliant.cfg").read_bytes()
    headers = {"Authorization": f"Bearer {token}"}
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("bad.cfg", data, "text/plain")},
        headers=headers,
    ).json()["id"]
    return int(
        client.post(
            "/api/v1/audits",
            json={"configuration_id": config_id, "framework": "CIS"},
            headers=headers,
        ).json()["id"]
    )


def test_every_failing_rule_produces_a_finding(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    response = client.get(
        f"/api/v1/findings?audit_id={audit_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    # Ruling R3(c): noncompliant.cfg produces 15 FAIL results and exactly one
    # NOT_ASSESSABLE (management.ssh.version) — findings are only created for
    # FAIL/WARNING, not NOT_ASSESSABLE, so 15 findings, not 16.
    assert len(response.json()) == 15


def test_findings_can_be_filtered_by_severity(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    response = client.get(
        f"/api/v1/findings?audit_id={audit_id}&severity=CRITICAL",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.json()
    assert {item["severity"] for item in response.json()} == {"CRITICAL"}


def test_finding_detail_carries_the_full_provenance_chain(
    client: TestClient, admin_token: str
) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0][
        "id"
    ]

    body = client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    assert body["rule_id"]
    assert body["framework"] == "CIS"
    assert body["framework_version"]
    assert len(body["configuration_sha256"]) == 64
    assert len(body["rule_pack_hash"]) == 64
    assert body["parameter"]
    assert body["evidence_excerpt"] != ""


def test_finding_detail_includes_remediation_with_the_validation_banner(
    client: TestClient, admin_token: str
) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0][
        "id"
    ]

    remediation = client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()[
        "remediation"
    ]
    assert remediation["cli"].strip() != ""
    assert remediation["verification"].strip() != ""
    assert remediation["banner"] == "Review and validate before production deployment."


def test_triage_updates_persist(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0][
        "id"
    ]

    patched = client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"triage_status": "accepted_risk", "notes": "Compensating control in place."},
        headers=headers,
    )
    assert patched.status_code == 200
    assert patched.json()["triage_status"] == "accepted_risk"
    assert client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()["notes"]


def test_invalid_triage_status_is_rejected(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0][
        "id"
    ]
    response = client.patch(
        f"/api/v1/findings/{finding_id}", json={"triage_status": "ignored"}, headers=headers
    )
    assert response.status_code == 422


def test_read_only_roles_cannot_triage(
    client: TestClient, admin_token: str, ciso_token: str
) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    finding_id = client.get(
        f"/api/v1/findings?audit_id={audit_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()[0]["id"]

    response = client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"triage_status": "false_positive"},
        headers={"Authorization": f"Bearer {ciso_token}"},
    )
    assert response.status_code == 403


def test_frameworks_endpoint_reports_loaded_packs(client: TestClient, admin_token: str) -> None:
    response = client.get("/api/v1/frameworks", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    pack = response.json()[0]
    assert pack["framework"] == "CIS"
    assert pack["rule_count"] == 16
    assert len(pack["sha256"]) == 64
