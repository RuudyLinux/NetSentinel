import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user
from app.audit_log import record_event
from app.config import settings
from app.db import get_db
from app.models import PasswordResetToken, RefreshToken, User
from app.schemas.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    RefreshRequest,
    ResetPasswordRequest,
    TokenPair,
)
from app.security.passwords import hash_password, verify_password
from app.security.reset_delivery import PasswordResetDelivery, get_reset_delivery
from app.security.tokens import (
    create_access_token,
    hash_refresh_token,
    hash_reset_token,
    new_refresh_token,
    new_reset_token,
)

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


@router.post(
    "/forgot-password", response_model=ForgotPasswordResponse, status_code=status.HTTP_202_ACCEPTED
)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    session: Session = Depends(get_db),
    delivery: PasswordResetDelivery = Depends(get_reset_delivery),
) -> ForgotPasswordResponse:
    """Always returns the same generic response — matching or not is never revealed.

    A real, single-use, short-lived reset token is generated and stored (hashed
    only — see PasswordResetToken) whenever the account exists and is active.
    Delivery of that token to the user goes through `PasswordResetDelivery`; no
    real email/SMS provider is wired into this deployment yet (see
    app/security/reset_delivery.py), so the token is logged rather than sent.
    The HTTP response is identical either way — only the log/delivery channel
    ever reveals whether the account exists.
    """
    user = session.scalar(select(User).where(User.email == payload.email))
    if user is not None and user.is_active:
        plain, hashed = new_reset_token()
        session.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hashed,
                expires_at=datetime.now(UTC) + timedelta(minutes=settings.password_reset_minutes),
            )
        )
        delivery.deliver(email=user.email, token=plain)
        record_event(
            session,
            action="PASSWORD_RESET_REQUESTED",
            user_id=user.id,
            ip=client_ip(request),
        )
        session.commit()
    return ForgotPasswordResponse()


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(
    payload: ResetPasswordRequest, request: Request, session: Session = Depends(get_db)
) -> Response:
    """Consume a reset token issued by /auth/forgot-password.

    One generic error for every failure mode (unknown/expired/already-used
    token) — same "don't leak which case it was" discipline as login and
    forgot-password. On success, every refresh token for the user is revoked:
    a password reset is exactly the moment an attacker's stolen session should
    stop working too.
    """
    _invalid = "Invalid or expired reset token"
    hashed = hash_reset_token(payload.token)
    stored = session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hashed)
    )
    if (
        stored is None
        or stored.used_at is not None
        or _aware(stored.expires_at) < datetime.now(UTC)
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _invalid)

    user = session.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _invalid)

    user.password_hash = hash_password(payload.new_password)
    stored.used_at = datetime.now(UTC)
    for token in session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)):
        token.revoked_at = token.revoked_at or datetime.now(UTC)

    record_event(
        session,
        action="PASSWORD_RESET_COMPLETED",
        user_id=user.id,
        ip=client_ip(request),
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
