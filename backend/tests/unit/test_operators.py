import pytest

from app.services.compliance.operators import Operator, OperatorError, apply_operator


@pytest.mark.parametrize(
    ("op", "observed", "expected", "want"),
    [
        (Operator.EQUALS, 2, 2, True),
        (Operator.EQUALS, 1, 2, False),
        (Operator.EQUALS, True, True, True),
        (Operator.NOT_EQUALS, 1, 2, True),
        (Operator.GTE, 12, 8, True),
        (Operator.GTE, 8, 8, True),
        (Operator.GTE, 7, 8, False),
        (Operator.LTE, 300, 600, True),
        (Operator.GT, 9, 8, True),
        (Operator.LT, 7, 8, True),
        (Operator.IN, "sha256", ["sha256", "sha512"], True),
        (Operator.IN, "md5", ["sha256"], False),
        (Operator.NOT_IN, "md5", ["sha256"], True),
        (Operator.PRESENT, False, None, True),
        (Operator.PRESENT, None, None, False),
        (Operator.ABSENT, None, None, True),
        (Operator.ABSENT, 1, None, False),
        (Operator.MATCHES, "10.0.0.0/8", r"^\d+\.\d+\.\d+\.\d+/\d+$", True),
        (Operator.MATCHES, "nope", r"^\d+$", False),
    ],
)
def test_operator_truth_table(op: Operator, observed: object, expected: object, want: bool) -> None:
    assert apply_operator(op, observed, expected) is want  # type: ignore[arg-type]


def test_ordering_operator_rejects_non_numeric_observation() -> None:
    with pytest.raises(OperatorError):
        apply_operator(Operator.GTE, "eight", 8)


def test_bool_is_not_accepted_as_a_number() -> None:
    """True == 1 in Python; ordering comparisons must not silently accept booleans."""
    with pytest.raises(OperatorError):
        apply_operator(Operator.GTE, True, 8)
