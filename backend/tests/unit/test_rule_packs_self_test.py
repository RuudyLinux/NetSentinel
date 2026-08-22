import pytest

from app.config import settings
from app.domain.controls import CONTROL_KEYS, ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.domain.results import Status
from app.services.compliance.engine import evaluate_rule
from app.services.compliance.rules import Rule, RulePack, load_all_packs

PACKS: list[RulePack] = load_all_packs(settings.rules_dir)
CASES = [
    pytest.param(pack, rule, case, id=f"{rule.id}[{case.given!r}]")
    for pack in PACKS
    for rule in pack.rules
    for case in rule.tests
]


@pytest.mark.parametrize(("pack", "rule", "case"), CASES)
def test_every_rule_proves_its_own_truth_table(pack: RulePack, rule: Rule, case: object) -> None:
    identity = DeviceIdentity(
        vendor=rule.applicability.vendor, os=rule.applicability.os[0], confidence=1.0
    )
    controls: ControlSet = {
        rule.parameter: ControlValue(value=case.given, source_lines=[1], excerpt="self-test")  # type: ignore[attr-defined]
    }
    result = evaluate_rule(rule, controls, identity)
    assert result.status is Status(case.expect)  # type: ignore[attr-defined]


def test_every_control_key_is_covered_by_at_least_one_rule() -> None:
    covered = {rule.parameter for pack in PACKS for rule in pack.rules}
    assert CONTROL_KEYS - covered == set(), f"uncovered controls: {sorted(CONTROL_KEYS - covered)}"


def test_every_rule_exercises_both_a_pass_and_a_fail() -> None:
    for pack in PACKS:
        for rule in pack.rules:
            outcomes = {case.expect for case in rule.tests}
            assert Status.PASS in outcomes, f"{rule.id} has no PASS case"
            assert Status.FAIL in outcomes, f"{rule.id} has no FAIL case"
