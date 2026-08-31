from app.domain.results import ComplianceResult, PostureScore, Severity, Status

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_CREDIT: dict[Status, float] = {
    Status.PASS: 1.0,
    Status.WARNING: 0.5,
    Status.FAIL: 0.0,
}

_ASSESSABLE = frozenset(_CREDIT)


def score_results(results: list[ComplianceResult]) -> PostureScore:
    """Severity-weighted pass rate over assessable rules.

    NOT_ASSESSABLE is excluded from the score and reported as reduced coverage, so a
    configuration that reveals nothing scores zero rather than a misleading 100.
    """
    assessable = [item for item in results if item.status in _ASSESSABLE]
    not_assessable = sum(1 for item in results if item.status is Status.NOT_ASSESSABLE)

    available = sum(SEVERITY_WEIGHTS[item.severity] for item in assessable)
    earned = sum(SEVERITY_WEIGHTS[item.severity] * _CREDIT[item.status] for item in assessable)

    score = round(100 * earned / available) if available else 0
    denominator = len(assessable) + not_assessable
    coverage = round(len(assessable) / denominator, 4) if denominator else 0.0

    fail_counts = {
        severity: sum(
            1 for item in results if item.status is Status.FAIL and item.severity is severity
        )
        for severity in Severity
    }

    return PostureScore(
        score=score,
        coverage=coverage,
        fail_counts=fail_counts,
        assessable=len(assessable),
        not_assessable=not_assessable,
    )
