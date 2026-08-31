from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.security.permissions import Permission
from app.security.tokens import TokenError, decode_access_token

_bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        claims = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from exc

    user = session.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    return user


def require(*permissions: Permission) -> Callable[[User], User]:
    """Authorize server-side against the role stored on the user, not the token claims.

    A token issued before a role change must not outlive that change.
    """

    def dependency(user: User = Depends(get_current_user)) -> User:
        granted = set(user.role.permissions)
        missing = {str(permission) for permission in permissions} - granted
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"Missing permission(s): {sorted(missing)}"
            )
        return user

    return dependency
