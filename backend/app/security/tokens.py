import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from app.config import settings

_ALGORITHM = "HS256"


class TokenError(ValueError):
    """Raised when a token is expired, tampered with, or otherwise unusable."""


@dataclass(frozen=True)
class TokenClaims:
    user_id: int
    permissions: list[str]


def create_access_token(
    user_id: int, permissions: list[str], expires_in_seconds: int | None = None
) -> str:
    ttl = (
        timedelta(seconds=expires_in_seconds)
        if expires_in_seconds is not None
        else timedelta(minutes=settings.access_token_minutes)
    )
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "perms": [str(permission) for permission in permissions],
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> TokenClaims:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    return TokenClaims(user_id=int(payload["sub"]), permissions=list(payload.get("perms", [])))


def _hash_opaque_token(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def hash_refresh_token(plain: str) -> str:
    return _hash_opaque_token(plain)


def new_refresh_token() -> tuple[str, str]:
    """Return (plaintext, hash). Only the hash is ever persisted."""
    plain = secrets.token_urlsafe(48)
    return plain, hash_refresh_token(plain)


def hash_reset_token(plain: str) -> str:
    return _hash_opaque_token(plain)


def new_reset_token() -> tuple[str, str]:
    """Return (plaintext, hash) for a password-reset token. Only the hash is persisted,
    same rationale as `new_refresh_token`: a leaked DB row must not itself be usable."""
    plain = secrets.token_urlsafe(32)
    return plain, hash_reset_token(plain)
