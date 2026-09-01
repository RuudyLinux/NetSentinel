import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user
from app.audit_log import record_event
from app.config import settings
from app.db import get_db
from app.models import RefreshToken, User
from app.schemas.auth import LoginRequest, RefreshRequest, TokenPair
from app.security.passwords import verify_password
from app.security.tokens import create_access_token, hash_refresh_token, new_refresh_token

router = APIRouter(prefix="/auth", tags=["auth"])

# One message for both "no such user" and "wrong password" — anything else is an oracle.
_INVALID = "Invalid email or password"


def _aware(dt: datetime) -> datetime:
    """Treat a naive datetime as UTC; leave an already-aware one untouched.

    SQLite ignores DateTime(timezone=True) and returns naive values, while PostgreSQL
    returns aware ones for the same column — this normalizes either to aware UTC without
    silently overwriting a genuinely different offset on the aware path.
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _issue_pair(session: Session, user: User, family_id: str | None = None) -> TokenPair:
    plain, hashed = new_refresh_token()
    session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hashed,
            family_id=family_id or str(uuid.uuid4()),
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_days),
        )
    )
    access = create_access_token(user_id=user.id, permissions=list(user.role.permissions))
    return TokenPair(access_token=access, refresh_token=plain)


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, session: Session = Depends(get_db)) -> TokenPair:
    user = session.scalar(select(User).where(User.email == payload.email))
    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.password_hash)
    ):
        record_event(
            session,
            action="LOGIN",
            user_id=user.id if user else None,
            resource=payload.email,
            ip=client_ip(request),
            result="FAILURE",
        )
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID)

    pair = _issue_pair(session, user)
    record_event(session, action="LOGIN", user_id=user.id, ip=client_ip(request))
    session.commit()
    return pair


@router.post("/refresh", response_model=TokenPair)
def refresh(
    payload: RefreshRequest, request: Request, session: Session = Depends(get_db)
) -> TokenPair:
    hashed = hash_refresh_token(payload.refresh_token)
    stored = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == hashed))

    if stored is None or _aware(stored.expires_at) < datetime.now(UTC):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    if stored.revoked_at is not None:
        # Replay of an already-rotated token: assume theft and burn the whole family.
        for sibling in session.scalars(
            select(RefreshToken).where(RefreshToken.family_id == stored.family_id)
        ):
            sibling.revoked_at = sibling.revoked_at or datetime.now(UTC)
        record_event(
            session,
            action="REFRESH_REPLAY",
            user_id=stored.user_id,
            ip=client_ip(request),
            result="FAILURE",
        )
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    stored.revoked_at = datetime.now(UTC)
    user = session.get(User, stored.user_id)
    if user is None or not user.is_active:
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    pair = _issue_pair(session, user, family_id=stored.family_id)
    session.commit()
    return pair


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: RefreshRequest,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Response:
    hashed = hash_refresh_token(payload.refresh_token)
    stored = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == hashed))
    if stored is not None and stored.user_id == user.id:
        for sibling in session.scalars(
            select(RefreshToken).where(RefreshToken.family_id == stored.family_id)
        ):
            sibling.revoked_at = sibling.revoked_at or datetime.now(UTC)
    record_event(session, action="LOGOUT", user_id=user.id, ip=client_ip(request))
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
