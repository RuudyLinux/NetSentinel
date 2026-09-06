from fastapi.testclient import TestClient


def test_login_returns_a_token_pair(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.ai", "password": "demo-password-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]


def test_login_with_a_wrong_password_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.ai", "password": "nope"},
    )
    assert response.status_code == 401


def test_login_does_not_reveal_whether_an_account_exists(client: TestClient) -> None:
    """Both responses must be identical, or the endpoint is a user enumeration oracle."""
    unknown = client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x"}
    )
    known = client.post(
        "/api/v1/auth/login", json={"email": "admin@netsentinel.ai", "password": "x"}
    )
    assert unknown.status_code == known.status_code == 401
    assert unknown.json() == known.json()


def test_forgot_password_does_not_reveal_whether_an_account_exists(client: TestClient) -> None:
    unknown = client.post("/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})
    known = client.post("/api/v1/auth/forgot-password", json={"email": "admin@netsentinel.ai"})
    assert unknown.status_code == known.status_code == 202
    assert unknown.json() == known.json()


def test_forgot_password_issues_a_real_token_only_for_a_known_account(client: TestClient) -> None:
    client.post("/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})
    client.post("/api/v1/auth/forgot-password", json={"email": "admin@netsentinel.ai"})
    tokens = client.reset_delivery.tokens  # type: ignore[attr-defined]
    assert "nobody@example.com" not in tokens
    assert "admin@netsentinel.ai" in tokens


def test_reset_password_changes_the_password_and_revokes_sessions(client: TestClient) -> None:
    old_tokens = client.post(
        "/api/v1/auth/login",
        json={"email": "secadmin@netsentinel.ai", "password": "demo-password-1"},
    ).json()

    client.post("/api/v1/auth/forgot-password", json={"email": "secadmin@netsentinel.ai"})
    token = client.reset_delivery.tokens["secadmin@netsentinel.ai"]  # type: ignore[attr-defined]

    response = client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "a-new-strong-password"},
    )
    assert response.status_code == 204

    # Old password no longer works; new one does.
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "secadmin@netsentinel.ai", "password": "demo-password-1"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "secadmin@netsentinel.ai", "password": "a-new-strong-password"},
        ).status_code
        == 200
    )

    # The pre-reset refresh token must be revoked.
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": old_tokens["refresh_token"]}
        ).status_code
        == 401
    )


def test_reset_password_token_is_single_use(client: TestClient) -> None:
    client.post("/api/v1/auth/forgot-password", json={"email": "admin@netsentinel.ai"})
    token = client.reset_delivery.tokens["admin@netsentinel.ai"]  # type: ignore[attr-defined]

    first = client.post(
        "/api/v1/auth/reset-password", json={"token": token, "new_password": "first-new-password"}
    )
    assert first.status_code == 204

    replay = client.post(
        "/api/v1/auth/reset-password", json={"token": token, "new_password": "second-new-password"}
    )
    assert replay.status_code == 400


def test_reset_password_rejects_an_unknown_token(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/reset-password",
        json={"token": "not-a-real-token", "new_password": "whatever-password"},
    )
    assert response.status_code == 400


def test_me_requires_a_token(client: TestClient) -> None:
    assert client.get("/api/v1/users/me").status_code == 401


def test_me_returns_the_caller(client: TestClient, admin_token: str) -> None:
    response = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "admin@netsentinel.ai"
    assert "CONFIG_UPLOAD" in response.json()["permissions"]


def test_refresh_rotates_the_token(client: TestClient) -> None:
    tokens = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.ai", "password": "demo-password-1"},
    ).json()
    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != tokens["refresh_token"]


def test_reusing_a_rotated_refresh_token_revokes_the_family(client: TestClient) -> None:
    original = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.ai", "password": "demo-password-1"},
    ).json()["refresh_token"]
    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": original}).json()[
        "refresh_token"
    ]

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": original})
    assert replay.status_code == 401

    # The replay must burn the whole family, not only the reused token.
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": rotated}).status_code == 401


def test_logout_revokes_the_refresh_token(client: TestClient) -> None:
    tokens = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.ai", "password": "demo-password-1"},
    ).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (
        client.post(
            "/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=headers
        ).status_code
        == 204
    )
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).status_code
        == 401
    )
