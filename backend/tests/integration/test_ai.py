from pathlib import Path

from fastapi.testclient import TestClient

from tests.integration.conftest import login

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def interpret_url(audit_id: int, index: int = 0) -> str:
    return f"/api/v1/audits/{audit_id}/unknown-constructs/{index}/interpret"


def audit_with_unknowns(client: TestClient, token: str) -> int:
    headers = {"Authorization": f"Bearer {token}"}
    data = (DATASETS / "mixed.cfg").read_bytes()
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("mixed.cfg", data, "text/plain")},
        headers=headers,
    ).json()["id"]
    return int(
        client.post(
            "/api/v1/audits",
            json={"configuration_id": config_id, "framework": "CIS"},
            headers=headers,
        ).json()["id"]
    )


def test_list_unknown_constructs_starts_with_no_interpretations(
    client: TestClient, admin_token: str
) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    response = client.get(
        f"/api/v1/audits/{audit_id}/unknown-constructs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 2
    assert all(item["interpretation"] is None for item in body)


def test_interpret_creates_a_pending_suggestion(client: TestClient, admin_token: str) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post(interpret_url(audit_id), headers=headers)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "pending"
    assert body["suggested_parameter"] == "logging.local.enabled"
    assert body["confidence"] == 0.75
    assert body["model"] == "fake/test-model"

    listed = client.get(f"/api/v1/audits/{audit_id}/unknown-constructs", headers=headers).json()
    assert listed[0]["interpretation"]["status"] == "pending"


def test_interpret_requires_mapping_suggest_permission(
    client: TestClient, admin_token: str
) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    ciso = login(client, "ciso@netsentinel.ai")
    response = client.post(
        f"/api/v1/audits/{audit_id}/unknown-constructs/0/interpret",
        headers={"Authorization": f"Bearer {ciso}"},
    )
    assert response.status_code == 403


def test_interpret_out_of_range_index_is_404(client: TestClient, admin_token: str) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    response = client.post(
        f"/api/v1/audits/{audit_id}/unknown-constructs/999/interpret",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


def test_review_approves_and_records_the_reviewer(client: TestClient, admin_token: str) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post(interpret_url(audit_id), headers=headers)

    secadmin = login(client, "secadmin@netsentinel.ai")
    response = client.patch(
        f"/api/v1/audits/{audit_id}/unknown-constructs/0/interpretation",
        json={"status": "approved", "notes": "Confirmed against the device manual."},
        headers={"Authorization": f"Bearer {secadmin}"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "approved"
    assert body["reviewed_by"] == "secadmin@netsentinel.ai"
    assert body["notes"] == "Confirmed against the device manual."


def test_review_requires_mapping_approve_permission(client: TestClient, admin_token: str) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post(interpret_url(audit_id), headers=headers)

    # Network Engineer holds MAPPING_SUGGEST but not MAPPING_APPROVE.
    engineer = login(client, "engineer@netsentinel.ai")
    response = client.patch(
        f"/api/v1/audits/{audit_id}/unknown-constructs/0/interpretation",
        json={"status": "approved"},
        headers={"Authorization": f"Bearer {engineer}"},
    )
    assert response.status_code == 403


def test_review_without_a_prior_interpretation_is_404(client: TestClient, admin_token: str) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    secadmin = login(client, "secadmin@netsentinel.ai")
    response = client.patch(
        f"/api/v1/audits/{audit_id}/unknown-constructs/0/interpretation",
        json={"status": "approved"},
        headers={"Authorization": f"Bearer {secadmin}"},
    )
    assert response.status_code == 404


def test_reinterpreting_resets_a_prior_review(client: TestClient, admin_token: str) -> None:
    audit_id = audit_with_unknowns(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post(interpret_url(audit_id), headers=headers)

    secadmin = login(client, "secadmin@netsentinel.ai")
    client.patch(
        f"/api/v1/audits/{audit_id}/unknown-constructs/0/interpretation",
        json={"status": "approved"},
        headers={"Authorization": f"Bearer {secadmin}"},
    )

    # A fresh suggestion is new advice — it shouldn't inherit the old approval.
    response = client.post(interpret_url(audit_id), headers=headers)
    body = response.json()
    assert body["status"] == "pending"
    assert body["reviewed_by"] is None


