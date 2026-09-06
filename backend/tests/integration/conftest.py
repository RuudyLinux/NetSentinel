from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import get_db
from app.main import create_app
from app.models import Organization, Role, User
from app.models.base import Base
from app.security.passwords import hash_password
from app.security.reset_delivery import get_reset_delivery
from app.services.ai.client import Interpretation, get_ai_client
from scripts.seed import seed_database

SECOND_ORG_PASSWORD = "other-org-password-1"
SECOND_ORG_EMAIL = "admin@other-org.example"


class FakeAiClient:
    """Default AI client for tests — never touches the real network. A test that
    wants different behavior overrides `app.dependency_overrides[get_ai_client]`
    itself (see test_ai.py)."""

    def interpret(self, *, construct_text: str, block: str | None) -> Interpretation:
        return Interpretation(
            interpretation=f"Looks like it configures something in the {block or 'unknown'} block.",
            suggested_parameter="logging.local.enabled",
            suggested_value=True,
            confidence=0.75,
            model="fake/test-model",
        )


class CapturingPasswordResetDelivery:
    """Test double: records the plaintext reset token instead of sending it anywhere.

    Production never sees this class (see app/security/reset_delivery.py) — it exists
    only so tests can drive the full forgot-password -> reset-password flow without a
    real email provider, the same way FakeAiClient stands in for the AI provider.
    """

    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}

    def deliver(self, *, email: str, token: str) -> None:
        self.tokens[email] = token


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def client(session_factory: sessionmaker[Session]) -> Iterator[TestClient]:
    with session_factory() as session:
        seed_database(session)

    def override_get_db() -> Iterator[Session]:
        with session_factory() as session:
            yield session

    reset_delivery = CapturingPasswordResetDelivery()
    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_ai_client] = FakeAiClient
    app.dependency_overrides[get_reset_delivery] = lambda: reset_delivery
    with TestClient(app) as test_client:
        test_client.reset_delivery = reset_delivery  # type: ignore[attr-defined]
        yield test_client


def login(client: TestClient, email: str, password: str = "demo-password-1") -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


@pytest.fixture
def admin_token(client: TestClient) -> str:
    return login(client, "admin@netsentinel.ai")


@pytest.fixture
def ciso_token(client: TestClient) -> str:
    return login(client, "ciso@netsentinel.ai")


@pytest.fixture
def second_org_token(client: TestClient, session_factory: sessionmaker[Session]) -> str:
    """A Platform Admin in a wholly separate organization — the standard fixture
    for cross-org IDOR regression tests (see test_organization_isolation.py).
    Full permissions on purpose: if even a Platform Admin from another org can't
    reach a resource, no lesser role in that org can either.
    """
    with session_factory() as session:
        role = session.scalar(select(Role).where(Role.name == "Platform Admin"))
        assert role is not None
        org = Organization(name="Other Org")
        session.add(org)
        session.flush()
        session.add(
            User(
                organization=org,
                role=role,
                email=SECOND_ORG_EMAIL,
                password_hash=hash_password(SECOND_ORG_PASSWORD),
            )
        )
        session.commit()
    return login(client, SECOND_ORG_EMAIL, SECOND_ORG_PASSWORD)
