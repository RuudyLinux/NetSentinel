from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerificationError

_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password. A malformed stored hash is a failure, never an exception."""
    try:
        return _hasher.verify(hashed, plain)
    except (VerificationError, Argon2Error, ValueError):
        return False
