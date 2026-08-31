"""Seed the demo organization, the six roles, and one user per role.

Demo passwords are intentionally weak and intentionally committed: this script
never runs against a real deployment. Guard it accordingly before production use.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Organization, Role, User
from app.security.passwords import hash_password
from app.security.permissions import ROLE_PERMISSIONS

DEMO_PASSWORD = "demo-password-1"

DEMO_USERS: dict[str, str] = {
    "admin@netsentinel.ai": "Platform Admin",
    "secadmin@netsentinel.ai": "Security Admin",
    "engineer@netsentinel.ai": "Network Engineer",
    "analyst@netsentinel.ai": "Security Analyst",
    "ciso@netsentinel.ai": "CISO",
    "auditor@netsentinel.ai": "Auditor",
}


def seed_database(session: Session) -> None:
    org = session.scalar(select(Organization).where(Organization.name == "Demo Org"))
    if org is None:
        org = Organization(name="Demo Org")
        session.add(org)

    roles: dict[str, Role] = {}
    for name, permissions in ROLE_PERMISSIONS.items():
        role = session.scalar(select(Role).where(Role.name == name))
        if role is None:
            role = Role(name=name, permissions=sorted(str(item) for item in permissions))
            session.add(role)
        else:
            role.permissions = sorted(str(item) for item in permissions)
        roles[name] = role

    for email, role_name in DEMO_USERS.items():
        if session.scalar(select(User).where(User.email == email)) is None:
            session.add(
                User(
                    organization=org,
                    role=roles[role_name],
                    email=email,
                    password_hash=hash_password(DEMO_PASSWORD),
                )
            )

    session.commit()


if __name__ == "__main__":
    with SessionLocal() as session:
        seed_database(session)
        print(f"Seeded {len(DEMO_USERS)} demo users with password {DEMO_PASSWORD!r}")
