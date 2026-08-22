import pytest

from app.domain.controls import CONTROL_KEYS, ControlValue
from app.domain.results import Severity, Status


def test_control_value_is_immutable() -> None:
    value = ControlValue(value=2, source_lines=[41], excerpt="ip ssh version 2")
    with pytest.raises(AttributeError):
        value.value = 1  # type: ignore[misc]


def test_control_value_defaults_to_deterministic_origin() -> None:
    value = ControlValue(value=True, source_lines=[7], excerpt="ip ssh")
    assert value.origin == "deterministic"
    assert value.parser_confidence == 1.0


def test_control_registry_has_sixteen_keys() -> None:
    assert len(CONTROL_KEYS) == 16
    assert "management.ssh.version" in CONTROL_KEYS


def test_statuses_and_severities_are_string_valued() -> None:
    assert Status.NOT_ASSESSABLE == "NOT_ASSESSABLE"
    assert Severity.CRITICAL == "CRITICAL"
