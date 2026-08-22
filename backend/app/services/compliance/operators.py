import re
from enum import StrEnum

from app.domain.controls import ControlPrimitive


class OperatorError(ValueError):
    """Raised when an operator is applied to a value it cannot compare."""


class Operator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GTE = "gte"
    LTE = "lte"
    GT = "gt"
    LT = "lt"
    IN = "in"
    NOT_IN = "not_in"
    PRESENT = "present"
    ABSENT = "absent"
    MATCHES = "matches"


_ORDERING = {Operator.GTE, Operator.LTE, Operator.GT, Operator.LT}


def _as_number(value: ControlPrimitive, op: Operator) -> int:
    # bool is a subclass of int; treating it as a number would make `True >= 8` meaningful.
    if isinstance(value, bool) or not isinstance(value, int):
        raise OperatorError(f"operator {op} requires a numeric value, got {value!r}")
    return value


def apply_operator(op: Operator, observed: ControlPrimitive, expected: ControlPrimitive) -> bool:
    if op is Operator.PRESENT:
        return observed is not None
    if op is Operator.ABSENT:
        return observed is None

    if op in _ORDERING:
        left = _as_number(observed, op)
        right = _as_number(expected, op)
        match op:
            case Operator.GTE:
                return left >= right
            case Operator.LTE:
                return left <= right
            case Operator.GT:
                return left > right
            case _:
                return left < right

    match op:
        case Operator.EQUALS:
            return observed == expected
        case Operator.NOT_EQUALS:
            return observed != expected
        case Operator.IN:
            if not isinstance(expected, list):
                raise OperatorError("operator 'in' requires a list expectation")
            return observed in expected
        case Operator.NOT_IN:
            if not isinstance(expected, list):
                raise OperatorError("operator 'not_in' requires a list expectation")
            return observed not in expected
        case Operator.MATCHES:
            if not isinstance(observed, str) or not isinstance(expected, str):
                raise OperatorError("operator 'matches' requires string operands")
            try:
                return re.search(expected, observed) is not None
            except re.error as exc:
                raise OperatorError(f"invalid regex pattern {expected!r}: {exc}") from exc
        case _:  # pragma: no cover - exhaustive over the enum
            raise OperatorError(f"unhandled operator {op}")
