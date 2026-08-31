from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AuditRun,
    Configuration,
    Device,
    Finding,
    Organization,
    Role,
    User,
)
from app.models.base import Base


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_full_object_graph_persists(session: Session) -> None:
    org = Organization(name="Demo Org")
    role = Role(name="Security Admin", permissions=["AUDIT_RUN", "CONFIG_UPLOAD"])
    user = User(organization=org, role=role, email="a@example.com", password_hash="x")
    device = Device(organization=org, name="core-sw-01", vendor="cisco", os="ios-xe")
    config = Configuration(
        device=device,
        sha256="a" * 64,
        blob_key="blobs/aa",
        filename="core.cfg",
        size_bytes=100,
        uploaded_by=user,
        secret_hits=2,
    )
    run = AuditRun(
        configuration=config,
        framework="CIS",
        framework_version="8.0",
        status="completed",
        rule_pack_hash="b" * 64,
        engine_version="0.1.0",
        started_at=datetime.now(UTC),
    )
    session.add_all([org, role, user, device, config, run])
    session.commit()

    assert run.id is not None
    assert run.configuration.device.organization.name == "Demo Org"


def test_configuration_sha_is_unique_per_device(session: Session) -> None:
    org = Organization(name="Org")
    device = Device(organization=org, name="d", vendor="cisco", os="ios")
    role = Role(name="R", permissions=[])
    user = User(organization=org, role=role, email="b@example.com", password_hash="x")
    session.add_all(
        [
            Configuration(
                device=device,
                sha256="c" * 64,
                blob_key="k1",
                filename="f",
                size_bytes=1,
                uploaded_by=user,
            ),
            Configuration(
                device=device,
                sha256="c" * 64,
                blob_key="k2",
                filename="f",
                size_bytes=1,
                uploaded_by=user,
            ),
        ]
    )
    with pytest.raises(IntegrityError):
        session.commit()


def test_user_email_is_unique(session: Session) -> None:
    org = Organization(name="Org")
    role = Role(name="R", permissions=[])
    session.add_all(
        [
            User(organization=org, role=role, email="dup@example.com", password_hash="x"),
            User(organization=org, role=role, email="dup@example.com", password_hash="y"),
        ]
    )
    with pytest.raises(IntegrityError):
        session.commit()


def test_finding_defaults_to_open_triage(session: Session) -> None:
    """Ruling R4: mapped_column(default=...) is applied at flush, not at instantiation."""
    finding = Finding(severity="HIGH", title="Telnet enabled", remediation_id="REM-TELNET-001")
    session.add(finding)
    session.flush()
    assert finding.triage_status == "open"
