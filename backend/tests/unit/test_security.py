import pytest

from app.security.passwords import hash_password, verify_password
from app.security.permissions import ROLE_NAMES, ROLE_PERMISSIONS, Permission
from app.security.tokens import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_refresh_token,
    new_refresh_token,
)


def test_password_hash_is_argon2id_and_verifies() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert verify_password("correct horse battery staple", hashed)
    assert not verify_password("wrong", hashed)


def test_password_hashes_are_salted_uniquely() -> None:
    assert hash_password("same") != hash_password("same")


def test_verify_rejects_a_malformed_hash_without_raising() -> None:
    assert verify_password("anything", "not-a-hash") is False


def test_access_token_round_trips_claims() -> None:
    token = create_access_token(user_id=7, permissions=[Permission.AUDIT_RUN])
    claims = decode_access_token(token)
    assert claims.user_id == 7
    assert Permission.AUDIT_RUN in claims.permissions


def test_expired_access_token_is_rejected() -> None:
    token = create_access_token(user_id=1, permissions=[], expires_in_seconds=-1)
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_tampered_token_is_rejected() -> None:
    token = create_access_token(user_id=1, permissions=[])
    with pytest.raises(TokenError):
        decode_access_token(token[:-2] + "xy")


def test_refresh_token_is_stored_only_as_a_hash() -> None:
    plain, hashed = new_refresh_token()
    assert plain != hashed
    assert len(hashed) == 64
    assert hash_refresh_token(plain) == hashed


def test_refresh_tokens_are_unique() -> None:
    assert new_refresh_token()[0] != new_refresh_token()[0]


def test_every_role_is_defined_and_least_privileged() -> None:
    assert len(ROLE_NAMES) == 6
    assert set(ROLE_PERMISSIONS) == set(ROLE_NAMES)

    # A role that can suggest a mapping must not automatically be able to approve one.
    engineer = ROLE_PERMISSIONS["Network Engineer"]
    assert Permission.MAPPING_SUGGEST in engineer
    assert Permission.MAPPING_APPROVE not in engineer

    # Read-only roles must not be able to mutate anything.
    for role in ("CISO", "Auditor"):
        assert Permission.CONFIG_UPLOAD not in ROLE_PERMISSIONS[role]
        assert Permission.AUDIT_RUN not in ROLE_PERMISSIONS[role]
        assert Permission.FINDING_TRIAGE not in ROLE_PERMISSIONS[role]

    # Only the platform administrator administers.
    for role in ROLE_NAMES:
        if role != "Platform Admin":
            assert Permission.USER_ADMIN not in ROLE_PERMISSIONS[role]
