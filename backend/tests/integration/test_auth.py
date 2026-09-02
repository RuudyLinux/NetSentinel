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
