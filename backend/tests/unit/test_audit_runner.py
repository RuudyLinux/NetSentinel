from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models import AuditRun, Configuration, Device, Organization, Role, User
from app.models.base import Base
from app.services.audit.runner import run_audit
from app.storage.local import LocalFileStorage

COMPLIANT = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco" / "compliant.cfg"


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def configuration(session: Session) -> Configuration:
    org = Organization(name="Demo Org")
    role = Role(name="Platform Admin", permissions=[])
    user = User(organization=org, role=role, email="a@example.com", password_hash="x")
    device = Device(organization=org, name="core-sw-01", vendor="cisco", os="ios-xe")
    config = Configuration(
        device=device,
        sha256="a" * 64,
        blob_key="blobs/compliant.cfg",
        filename="compliant.cfg",
        size_bytes=100,
        uploaded_by=user,
        secret_hits=0,
    )
    session.add(config)
    session.flush()
    return config


def test_a_pipeline_failure_is_persisted_as_a_failed_run_not_lost(
    session: Session, configuration: Configuration, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Section 16's core requirement: an audit must not vanish on failure — the
    operator needs to see *that* it failed and *why* (see audit/runner.py)."""
    storage = LocalFileStorage(tmp_path)
    storage.put(configuration.blob_key, COMPLIANT.read_bytes())

    def explode(vendor: str) -> None:
        raise RuntimeError("simulated parser crash")

    monkeypatch.setattr("app.services.audit.runner.get_parser", explode)

    with pytest.raises(RuntimeError, match="simulated parser crash"):
        run_audit(session, storage, configuration, framework="CIS")

    persisted = session.query(AuditRun).one()
    assert persisted.status == "failed"
    assert persisted.error is not None
    assert "simulated parser crash" in persisted.error
    assert persisted.finished_at is not None
    # No downstream rows should exist for a run that never reached evaluation.
    assert persisted.controls == []
    assert persisted.results == []


def test_a_successful_run_reaches_completed_status(
    session: Session, configuration: Configuration, tmp_path: Path
) -> None:
    storage = LocalFileStorage(tmp_path)
    storage.put(configuration.blob_key, COMPLIANT.read_bytes())

    run = run_audit(session, storage, configuration, framework="CIS")

    assert run.status == "completed"
    assert run.error is None
    assert run.score == 100
    assert run.finished_at is not None
