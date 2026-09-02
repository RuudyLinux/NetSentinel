from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require
from app.db import get_db
from app.models import Role, User
from app.schemas.auth import UserOut
from app.schemas.users import AdminUserOut, RoleOut
from app.security.permissions import Permission

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role=user.role.name,
        permissions=sorted(user.role.permissions),
    )


@router.get("", response_model=list[AdminUserOut])
def list_users(
    user: User = Depends(require(Permission.USER_ADMIN)),
    session: Session = Depends(get_db),
) -> list[AdminUserOut]:
    rows = session.scalars(
        select(User).where(User.organization_id == user.organization_id).order_by(User.email)
    )
    return [
        AdminUserOut(
            id=row.id,
            email=row.email,
            role=row.role.name,
            is_active=row.is_active,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.get("/roles", response_model=list[RoleOut])
def list_roles(
    _: User = Depends(require(Permission.USER_ADMIN)),
    session: Session = Depends(get_db),
) -> list[RoleOut]:
    # security/permissions.py's ROLE_PERMISSIONS is the source of truth and
    # scripts/seed.py seeds these rows from it — reading the DB rows here reflects
    # what's actually persisted, not just what the code currently defines.
    roles = session.scalars(select(Role).order_by(Role.name))
    return [RoleOut(name=role.name, permissions=sorted(role.permissions)) for role in roles]
