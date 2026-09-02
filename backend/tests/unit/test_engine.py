from app.domain.controls import ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.domain.results import Severity, Status
from app.services.compliance.engine import evaluate_rule
from app.services.compliance.operators import Operator
from app.services.compliance.rules import Applicability, Rule, RuleTest

CISCO = DeviceIdentity(vendor="cisco", os="ios-xe", confidence=0.98)
JUNIPER = DeviceIdentity(vendor="juniper", os="junos", confidence=0.98)


def make_rule(**overrides: object) -> Rule:
    base: dict[str, object] = {
        "id": "CIS-SSH-002",
        "framework": "CIS",
        "framework_version": "8.0",
        "title": "SSH v2 enforced",
        "description": "SSHv1 is broken.",
        "impact": "An attacker can hijack the session.",
        "applicability": Applicability(vendor="cisco", os=["ios", "ios-xe"]),
        "parameter": "management.ssh.version",
        "operator": Operator.EQUALS,
        "expected": 2,
        "severity": Severity.HIGH,
        "remediation_id": "REM-SSH-002",
        "source": "CIS v8.0",
        "tests": [RuleTest(given=2, expect=Status.PASS)],
    }
    return Rule.model_validate(base | overrides)


def controls(value: object) -> ControlSet:
    return {
        "management.ssh.version": ControlValue(
            value=value,  # type: ignore[arg-type]
            source_lines=[41],
            excerpt="ip ssh version 1",
        )
    }


def test_satisfied_expectation_passes() -> None:
    assert evaluate_rule(make_rule(), controls(2), CISCO).status is Status.PASS


def test_violated_expectation_fails_and_carries_evidence() -> None:
    result = evaluate_rule(make_rule(), controls(1), CISCO)
    assert result.status is Status.FAIL
    assert result.observed_value == 1
    assert result.expected_value == 2
    assert result.evidence is not None
    assert result.evidence.source_lines == [41]


def test_missing_control_is_not_assessable() -> None:
    result = evaluate_rule(make_rule(), {}, CISCO)
    assert result.status is Status.NOT_ASSESSABLE
    assert result.evidence is None


def test_control_observed_as_none_is_not_assessable() -> None:
    assert evaluate_rule(make_rule(), controls(None), CISCO).status is Status.NOT_ASSESSABLE


def test_wrong_vendor_is_not_applicable() -> None:
    assert evaluate_rule(make_rule(), controls(1), JUNIPER).status is Status.NOT_APPLICABLE


def test_presence_operators_treat_none_as_an_observation() -> None:
    """`absent` must be assessable against a null value — that is the point of the operator."""
    rule = make_rule(
        id="CIS-TELNET-001",
        parameter="management.telnet.enabled",
        operator=Operator.ABSENT,
        expected=None,
    )
    empty: ControlSet = {"management.telnet.enabled": ControlValue(value=None, excerpt="")}
    assert evaluate_rule(rule, empty, CISCO).status is Status.PASS


def test_uncomparable_value_is_not_assessable_rather_than_a_crash() -> None:
    rule = make_rule(parameter="auth.password.min_length", operator=Operator.GTE, expected=8)
    bad: ControlSet = {"auth.password.min_length": ControlValue(value="eight", excerpt="x")}
    assert evaluate_rule(rule, bad, CISCO).status is Status.NOT_ASSESSABLE
