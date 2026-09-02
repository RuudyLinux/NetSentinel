from datetime import datetime
from typing import Literal

from pydantic import BaseModel

InterpretationStatus = Literal["pending", "approved", "rejected"]


class AiInterpretationOut(BaseModel):
    id: int
    construct_index: int
    model: str
    interpretation: str
    suggested_parameter: str | None
    suggested_value: object
    confidence: float
    status: InterpretationStatus
    reviewed_by: str | None
    reviewed_at: datetime | None
    notes: str


class UnknownConstructOut(BaseModel):
    index: int
    text: str
    lineno: int
    block: str | None
    interpretation: AiInterpretationOut | None = None


class ReviewInterpretationRequest(BaseModel):
    status: Literal["approved", "rejected"]
    suggested_parameter: str | None = None
    suggested_value: object = None
    notes: str | None = None
