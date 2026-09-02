from fastapi.testclient import TestClient


def test_list_users_requires_user_admin(client: TestClient, ciso_token: str) -> None:
    response = client.get("/api/v1/users", headers={"Authorization": f"Bearer {ciso_token}"})
    assert response.status_code == 403


def test_list_users_returns_the_seeded_accounts(client: TestClient, admin_token: str) -> None:
    response = client.get("/api/v1/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    emails = {u["email"] for u in response.json()}
    assert "admin@netsentinel.ai" in emails
    assert "ciso@netsentinel.ai" in emails
    assert len(response.json()) == 6


def test_list_roles_requires_user_admin(client: TestClient, ciso_token: str) -> None:
    response = client.get("/api/v1/users/roles", headers={"Authorization": f"Bearer {ciso_token}"})
    assert response.status_code == 403


def test_list_roles_shows_the_real_permission_matrix(client: TestClient, admin_token: str) -> None:
    response = client.get(
        "/api/v1/users/roles", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    roles = {r["name"]: r["permissions"] for r in response.json()}
    assert "AUDIT_RUN" in roles["Network Engineer"]
    assert "DEVICE_WRITE" not in roles["Network Engineer"]
    assert "USER_ADMIN" in roles["Platform Admin"]
    assert "USER_ADMIN" not in roles["CISO"]


def test_audit_logs_requires_user_admin(client: TestClient, ciso_token: str) -> None:
    response = client.get(
        "/api/v1/audit-logs", headers={"Authorization": f"Bearer {ciso_token}"}
    )
    assert response.status_code == 403


def test_audit_logs_records_login(client: TestClient, admin_token: str) -> None:
    # admin_token's own login already generated a LOGIN event.
    response = client.get(
        "/api/v1/audit-logs", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    body = response.json()
    actions = [entry["action"] for entry in body["entries"]]
    assert "LOGIN" in actions
    assert all(entry["user_email"] for entry in body["entries"])


def test_audit_logs_pagination(client: TestClient, admin_token: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    for _ in range(3):
        client.post(
            "/api/v1/auth/login",
            json={"email": "admin@netsentinel.ai", "password": "demo-password-1"},
        )

    first_page = client.get("/api/v1/audit-logs?limit=2", headers=headers).json()
    assert len(first_page["entries"]) == 2
    assert first_page["next_before_id"] is not None

    second_page = client.get(
        f"/api/v1/audit-logs?limit=2&before_id={first_page['next_before_id']}", headers=headers
    ).json()
    assert len(second_page["entries"]) >= 1
    first_ids = {e["id"] for e in first_page["entries"]}
    second_ids = {e["id"] for e in second_page["entries"]}
    assert first_ids.isdisjoint(second_ids)
