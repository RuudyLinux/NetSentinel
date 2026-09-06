from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def upload(client: TestClient, token: str, name: str) -> int:
    data = (DATASETS / f"{name}.cfg").read_bytes()
    response = client.post(
        "/api/v1/configurations/upload",
        files={"file": (f"{name}.cfg", data, "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code in (200, 201), response.text
    return int(response.json()["id"])


def run_audit(client: TestClient, token: str, configuration_id: int):
    return client.post(
        "/api/v1/audits",
        json={"configuration_id": configuration_id, "framework": "CIS"},
        headers={"Authorization": f"Bearer {token}"},
    )


def test_audit_of_a_compliant_config_scores_one_hundred(
    client: TestClient, admin_token: str
) -> None:
    config_id = upload(client, admin_token, "compliant")
    response = run_audit(client, admin_token, config_id)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["score"] == 100
    assert body["coverage"] == 1.0


def test_audit_of_a_noncompliant_config_scores_zero(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "noncompliant")
    body = run_audit(client, admin_token, config_id).json()
    assert body["score"] == 0
    assert body["fail_counts"]["CRITICAL"] >= 1


def test_nist_framework_is_selectable_for_a_cisco_device(
    client: TestClient, admin_token: str
) -> None:
    """The same normalized controls back both CIS and NIST rule packs (see
    rules/nist/cisco-ios-800-53r5.yaml) — this is the "framework, not
    vendor-specific engine" architecture actually working end to end."""
    config_id = upload(client, admin_token, "compliant")
    response = client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "NIST"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["framework"] == "NIST"
    assert body["framework_version"] == "800-53r5"
    assert body["score"] == 100


def test_audit_records_provenance_for_reproducibility(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "compliant")
    body = run_audit(client, admin_token, config_id).json()
    assert len(body["rule_pack_hash"]) == 64
    assert body["engine_version"]
    assert body["detection"]["vendor"] == "cisco"
    assert body["detection"]["reasons"]


def test_audit_detail_exposes_controls_results_and_unknowns(
    client: TestClient, admin_token: str
) -> None:
    config_id = upload(client, admin_token, "mixed")
    audit_id = run_audit(client, admin_token, config_id).json()["id"]
    response = client.get(
        f"/api/v1/audits/{audit_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["controls"]) >= 10
    assert len(body["results"]) == 16
    assert len(body["unknown_constructs"]) >= 2
    ssh = next(item for item in body["controls"] if item["key"] == "management.ssh.version")
    assert ssh["source_lines"]
    assert ssh["excerpt"]


def test_reaudit_of_identical_input_is_reproducible(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "compliant")
    first = run_audit(client, admin_token, config_id).json()
    second = run_audit(client, admin_token, config_id).json()
    assert first["id"] != second["id"]
    assert first["score"] == second["score"]
    assert first["rule_pack_hash"] == second["rule_pack_hash"]


def test_low_confidence_detection_demands_an_explicit_vendor(
    client: TestClient, admin_token: str
) -> None:
    junos = b"system {\n    host-name mx-01;\n    services {\n        ssh;\n    }\n}\n"
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("mx01.conf", junos, "text/plain")},
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()["id"]

    response = run_audit(client, admin_token, config_id)
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["confidence"] < 0.70
    assert detail["reasons"] is not None


def test_running_an_audit_requires_the_audit_run_permission(
    client: TestClient, admin_token: str, ciso_token: str
) -> None:
    config_id = upload(client, admin_token, "compliant")
    assert run_audit(client, ciso_token, config_id).status_code == 403


def test_reading_an_audit_is_allowed_for_read_only_roles(
    client: TestClient, admin_token: str, ciso_token: str
) -> None:
    config_id = upload(client, admin_token, "compliant")
    audit_id = run_audit(client, admin_token, config_id).json()["id"]
    response = client.get(
        f"/api/v1/audits/{audit_id}", headers={"Authorization": f"Bearer {ciso_token}"}
    )
    assert response.status_code == 200


def _device_id_of(client: TestClient, token: str, configuration_id: int) -> int:
    response = client.get(
        f"/api/v1/configurations/{configuration_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    return int(response.json()["device"]["id"])


def test_audits_can_be_filtered_by_device(client: TestClient, admin_token: str) -> None:
    compliant_config = upload(client, admin_token, "compliant")
    noncompliant_config = upload(client, admin_token, "mixed")  # a distinct device
    compliant_audit = run_audit(client, admin_token, compliant_config).json()["id"]
    run_audit(client, admin_token, noncompliant_config)

    device_id = _device_id_of(client, admin_token, compliant_config)
    response = client.get(
        f"/api/v1/audits?device_id={device_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert {audit["id"] for audit in response.json()} == {compliant_audit}


def test_unknown_framework_is_rejected_as_bad_request(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "compliant")
    response = client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "NIST-800-NOPE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 400


def test_vendor_override_to_an_unsupported_vendor_is_rejected_not_faked(
    client: TestClient, admin_token: str
) -> None:
    """Juniper has neither a CIS rule pack nor a parser/normalizer registered yet
    (see services/parsing/registry.py). Overriding to it must fail cleanly rather
    than silently picking some other vendor's rule pack — e.g. running Cisco's
    CIS 8.0 rules against a Juniper device and reporting a wall of NOT_APPLICABLE
    under a framework_version that was never actually relevant to it — exactly
    the kind of fake vendor support this platform must never present.
    """
    junos = b"system {\n    host-name mx-01;\n    services {\n        ssh;\n    }\n}\n"
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("mx01.conf", junos, "text/plain")},
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()["id"]
    # Upload-time detection defaults every config to "cisco" pending confirmation.
    before = client.get(
        f"/api/v1/configurations/{config_id}", headers={"Authorization": f"Bearer {admin_token}"}
    ).json()
    assert before["device"]["vendor"] == "cisco"

    response = client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "CIS", "vendor_override": "juniper"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 400, response.text
    assert "juniper" in response.text

    # A rejected audit must not leave a partial side effect behind: the device
    # row keeps its prior (unconfirmed) vendor rather than being stamped with a
    # vendor this deployment cannot actually produce a compliance result for.
    after = client.get(
        f"/api/v1/configurations/{config_id}", headers={"Authorization": f"Bearer {admin_token}"}
    ).json()
    assert after["device"]["vendor"] == "cisco"


def test_vendor_override_to_a_supported_vendor_runs_a_real_audit(
    client: TestClient, admin_token: str
) -> None:
    fortios = (
        b"#config-version=FGT60F-7.2.5-FW-build1517-230510:opmode=0:vdom=0:user=admin\n"
        b"config system global\n"
        b'    set hostname "fgt-edge-01"\n'
        b"end\n"
    )
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("edge01.conf", fortios, "text/plain")},
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()["id"]

    response = client.post(
        "/api/v1/audits",
        json={"configuration_id": config_id, "framework": "CIS", "vendor_override": "fortinet"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "completed"

    after = client.get(
        f"/api/v1/configurations/{config_id}", headers={"Authorization": f"Bearer {admin_token}"}
    ).json()
    assert after["device"]["vendor"] == "fortinet"
