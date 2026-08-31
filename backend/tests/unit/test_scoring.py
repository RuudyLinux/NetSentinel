from app.domain.results import ComplianceResult, Severity, Status
from app.services.scoring.posture import score_results


def result(status: Status, severity: Severity = Severity.HIGH) -> ComplianceResult:
    return ComplianceResult(
        rule_id="R",
        framework="CIS",
        framework_version="8.0",
        parameter="p",
        observed_value=None,
        expected_value=None,
        status=status,
        severity=severity,
    )


def test_all_passing_scores_one_hundred() -> None:
    score = score_results([result(Status.PASS), result(Status.PASS)])
    assert score.score == 100
    assert score.coverage == 1.0


def test_all_failing_scores_zero() -> None:
    assert score_results([result(Status.FAIL)]).score == 0


def test_warning_earns_half_credit() -> None:
    assert score_results([result(Status.WARNING)]).score == 50


def test_severity_weighting_favors_critical_rules() -> None:
    """One CRITICAL failure must cost more than one LOW failure."""
    critical_fail = score_results(
        [result(Status.FAIL, Severity.CRITICAL), result(Status.PASS, Severity.LOW)]
    )
    low_fail = score_results(
        [result(Status.PASS, Severity.CRITICAL), result(Status.FAIL, Severity.LOW)]
    )
    assert critical_fail.score < low_fail.score


def test_not_assessable_is_excluded_from_the_score_and_lowers_coverage() -> None:
    score = score_results([result(Status.PASS), result(Status.NOT_ASSESSABLE)])
    assert score.score == 100
    assert score.coverage == 0.5
    assert score.not_assessable == 1


def test_a_configuration_revealing_nothing_scores_zero_not_one_hundred() -> None:
    score = score_results([result(Status.NOT_ASSESSABLE), result(Status.NOT_ASSESSABLE)])
    assert score.score == 0
    assert score.coverage == 0.0


def test_not_applicable_affects_neither_score_nor_coverage() -> None:
    score = score_results([result(Status.PASS), result(Status.NOT_APPLICABLE)])
    assert score.score == 100
    assert score.coverage == 1.0


def test_fail_counts_are_reported_by_severity() -> None:
    score = score_results(
        [
            result(Status.FAIL, Severity.CRITICAL),
            result(Status.FAIL, Severity.CRITICAL),
            result(Status.FAIL, Severity.LOW),
            result(Status.PASS, Severity.HIGH),
        ]
    )
    assert score.fail_counts[Severity.CRITICAL] == 2
    assert score.fail_counts[Severity.LOW] == 1
    assert score.fail_counts[Severity.HIGH] == 0


def test_empty_result_set_scores_zero_without_dividing_by_zero() -> None:
    score = score_results([])
    assert score.score == 0
    assert score.coverage == 0.0
