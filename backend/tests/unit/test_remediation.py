from app.config import settings
from app.services.compliance.rules import load_all_packs
from app.services.remediation.packs import REMEDIATION_BANNER, load_remediations


def test_every_rule_remediation_id_resolves() -> None:
    remediations = load_remediations(settings.mappings_dir)
    referenced = {
        rule.remediation_id for pack in load_all_packs(settings.rules_dir) for rule in pack.rules
    }
    missing = referenced - remediations.keys()
    assert missing == set(), f"rules reference missing remediations: {sorted(missing)}"


def test_every_remediation_carries_the_validation_banner() -> None:
    for remediation in load_remediations(settings.mappings_dir).values():
        assert remediation.banner == REMEDIATION_BANNER


def test_remediation_carries_verification_and_rollback() -> None:
    remediation = load_remediations(settings.mappings_dir)["REM-SSH-002"]
    assert "ip ssh version 2" in remediation.cli
    assert remediation.verification.strip() != ""
    assert remediation.rollback.strip() != ""
