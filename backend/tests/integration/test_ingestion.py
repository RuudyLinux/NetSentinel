from fastapi.testclient import TestClient

CONFIG = b"""Building configuration...
!
version 17.6
boot-start-marker
!
hostname core-sw-01
enable secret 5 $1$abcd$EFGHIJKLMNOPQRSTUV
ip ssh version 2
line con 0
!
end
"""


def upload(client: TestClient, token: str, data: bytes = CONFIG, name: str = "core.cfg"):
    return client.post(
        "/api/v1/configurations/upload",
        files={"file": (name, data, "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )


def test_upload_stores_hash_and_redaction_count(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token)
    assert response.status_code == 201, response.text
    body = response.json()
    assert len(body["sha256"]) == 64
    assert body["secret_hits"] == 1
    assert body["device"]["vendor"] == "cisco"
    assert body["device"]["name"] == "core-sw-01"


def test_uploaded_text_is_returned_redacted(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token).json()["id"]
    response = client.get(
        f"/api/v1/configurations/{config_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert "$1$abcd$EFGHIJKLMNOPQRSTUV" not in response.text
    assert "<REDACTED:enable-secret-strong>" in response.json()["text"]


def test_reupload_of_identical_content_is_idempotent(client: TestClient, admin_token: str) -> None:
    first = upload(client, admin_token)
    second = upload(client, admin_token)
    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]


def test_unsupported_extension_is_rejected(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token, name="payload.exe")
    assert response.status_code == 422
    assert "extension" in response.json()["detail"].lower()


def test_oversized_upload_is_rejected(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token, data=b"a" * (5 * 1024 * 1024 + 1))
    assert response.status_code == 422


def test_binary_upload_is_rejected(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token, data=b"\x00\x01\x02\xff\xfe", name="x.cfg")
    assert response.status_code == 422


def test_upload_requires_the_config_upload_permission(client: TestClient, ciso_token: str) -> None:
    assert upload(client, ciso_token).status_code == 403


def test_upload_is_recorded_in_the_audit_trail(client: TestClient, admin_token: str) -> None:
    upload(client, admin_token)
    # The event is written in the same transaction as the configuration row.
    response = client.get("/api/v1/devices", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    assert response.json()[0]["name"] == "core-sw-01"
