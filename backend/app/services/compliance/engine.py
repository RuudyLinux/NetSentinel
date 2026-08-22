from app.domain.controls import ControlPrimitive, ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.domain.results import ComplianceResult, Status
from app.services.compliance.operators import Operator, OperatorError, apply_operator
from app.services.compliance.rules import Rule, RulePack

# These operators are meaningful against a null observation; every other operator is not.
_PRESENCE_OPERATORS = {Operator.PRESENT, Operator.ABSENT}


def evaluate_rule(rule: Rule, controls: ControlSet, identity: DeviceIdentity) -> ComplianceResult:
    def result(
        status: Status,
        observed: ControlPrimitive = None,
        evidence: ControlValue | None = None,
    ) -> ComplianceResult:
        return ComplianceResult(
            rule_id=rule.id,
            framework=rule.framework,
            framework_version=rule.framework_version,
            parameter=rule.parameter,
            observed_value=observed,
            expected_value=rule.expected,
            status=status,
            severity=rule.severity,
            evidence=evidence,
        )

    if not rule.applicability.matches(identity.vendor, identity.os):
        return result(Status.NOT_APPLICABLE)

    observation = controls.get(rule.parameter)

    if observation is None:
        # The parser never saw this construct at all. Even the `absent` operator does not
        # pass here: `absent` means the parser observed the key and recorded it as explicitly
        # unset (present in the ControlSet with value=None) -- not a key it never encountered.
        # A key the parser never saw is unassessable regardless of operator.
        return result(Status.NOT_ASSESSABLE)

    if observation.value is None and rule.operator not in _PRESENCE_OPERATORS:
        return result(Status.NOT_ASSESSABLE, evidence=observation)

    try:
        satisfied = apply_operator(rule.operator, observation.value, rule.expected)
    except OperatorError:
        # A rule that cannot compare its operands has not proven compliance.
        return result(Status.NOT_ASSESSABLE, observed=observation.value, evidence=observation)

    status = Status.PASS if satisfied else Status.FAIL
    return result(status, observed=observation.value, evidence=observation)


def evaluate_pack(
    pack: RulePack, controls: ControlSet, identity: DeviceIdentity
) -> list[ComplianceResult]:
    return [evaluate_rule(rule, controls, identity) for rule in pack.rules]
