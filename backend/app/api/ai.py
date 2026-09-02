from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.db import get_db
from app.models import AiInterpretation, AuditRun, User
from app.schemas.ai import AiInterpretationOut, ReviewInterpretationRequest, UnknownConstructOut
from app.security.permissions import Permission
from app.services.ai.client import AiClient, AiClientError, get_ai_client

router = APIRouter(prefix="/audits/{audit_id}/unknown-constructs", tags=["ai"])


def _get_run(session: Session, audit_id: int, user: User) -> AuditRun:
    run = session.get(AuditRun, audit_id)
    if run is None or run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit not found")
    return run


def _get_interpretation(session: Session, audit_id: int, index: int) -> AiInterpretation | None:
    return session.scalar(
        select(AiInterpretation).where(
            AiInterpretation.audit_run_id == audit_id, AiInterpretation.construct_index == index
        )
    )


def _to_out(row: AiInterpretation) -> AiInterpretationOut:
    return AiInterpretationOut(
        id=row.id,
        construct_index=row.construct_index,
        model=row.model,
        interpretation=row.interpretation,
        suggested_parameter=row.suggested_parameter,
        suggested_value=row.suggested_value,
        confidence=row.confidence,
        status=row.status,
        reviewed_by=row.reviewed_by.email if row.reviewed_by else None,
        reviewed_at=row.reviewed_at,
        notes=row.notes,
    )


@router.get("", response_model=list[UnknownConstructOut])
def list_unknown_constructs(
    audit_id: int,
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
) -> list[UnknownConstructOut]:
    run = _get_run(session, audit_id, user)
    return [
        UnknownConstructOut(
            index=index,
            text=item["text"],
            lineno=item["lineno"],
            block=item.get("block"),
            interpretation=(
                _to_out(row) if (row := _get_interpretation(session, audit_id, index)) else None
            ),
        )
        for index, item in enumerate(run.unknown_constructs)
    ]


@router.post(
    "/{index}/interpret", response_model=AiInterpretationOut, status_code=status.HTTP_201_CREATED
)
def interpret_construct(
    audit_id: int,
    index: int,
    user: User = Depends(require(Permission.MAPPING_SUGGEST)),
    session: Session = Depends(get_db),
    client: AiClient = Depends(get_ai_client),
) -> AiInterpretationOut:
    run = _get_run(session, audit_id, user)
    if index < 0 or index >= len(run.unknown_constructs):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown construct not found")
    construct = run.unknown_constructs[index]
    text = construct["text"]
    block = construct.get("block")
    assert isinstance(text, str)
    assert block is None or isinstance(block, str)

    try:
        result = client.interpret(construct_text=text, block=block)
    except AiClientError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    row = _get_interpretation(session, audit_id, index)
    if row is None:
        row = AiInterpretation(audit_run_id=audit_id, construct_index=index)
        session.add(row)

    # A fresh interpretation always resets any prior review — it's new advice.
    row.model = result.model
    row.interpretation = result.interpretation
    row.suggested_parameter = result.suggested_parameter
    row.suggested_value = result.suggested_value
    row.confidence = result.confidence
    row.status = "pending"
    row.reviewed_by_id = None
    row.reviewed_at = None
    row.notes = ""
    session.commit()
    return _to_out(row)


@router.patch("/{index}/interpretation", response_model=AiInterpretationOut)
def review_interpretation(
    audit_id: int,
    index: int,
    payload: ReviewInterpretationRequest,
    user: User = Depends(require(Permission.MAPPING_APPROVE)),
    session: Session = Depends(get_db),
) -> AiInterpretationOut:
    _get_run(session, audit_id, user)
    row = _get_interpretation(session, audit_id, index)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No interpretation to review")

    row.status = payload.status
    if payload.suggested_parameter is not None:
        row.suggested_parameter = payload.suggested_parameter
    if payload.suggested_value is not None:
        row.suggested_value = payload.suggested_value
    if payload.notes is not None:
        row.notes = payload.notes
    row.reviewed_by_id = user.id
    row.reviewed_at = datetime.now(UTC)
    session.commit()
    return _to_out(row)
