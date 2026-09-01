from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.domain.device import DeviceIdentity
from app.domain.results import Status
from app.models import AuditRun, ComplianceResultRow, Configuration, Finding, NormalizedControlRow
from app.services.compliance.engine import evaluate_pack
from app.services.compliance.rules import RulePack, load_all_packs
from app.services.detection.cisco import detect
from app.services.normalization.cisco import normalize_cisco
from app.services.parsing.cisco import parse_cisco
from app.services.remediation.packs import load_remediations
from app.services.scoring.posture import score_results
from app.storage.base import StorageBackend


class DetectionConfirmationRequired(Exception):
    """Detection confidence is below the threshold; the caller must name the vendor."""

    def __init__(self, identity: DeviceIdentity) -> None:
        super().__init__("device detection requires manual confirmation")
        self.identity = identity


def _select_pack(framework: str) -> RulePack:
    packs = load_all_packs(settings.rules_dir)
    for pack in packs:
        if pack.framework.upper() == framework.upper():
            return pack
    raise ValueError(f"no rule pack loaded for framework {framework!r}")


def run_audit(
    session: Session,
    storage: StorageBackend,
    configuration: Configuration,
    framework: str,
    vendor_override: str | None = None,
) -> AuditRun:
    """Execute the full pipeline and persist every stage's output in one transaction.

    This is the only function in the codebase that both orchestrates stages and writes
    to the database. Every stage it calls is pure.
    """
    text = storage.get(configuration.blob_key).decode("utf-8")
    identity = detect(text)

    if identity.needs_confirmation and vendor_override is None:
        raise DetectionConfirmationRequired(identity)

    if vendor_override is not None:
        identity = DeviceIdentity(
            vendor=vendor_override,
            os=identity.os,
            os_version=identity.os_version,
            product_family=identity.product_family,
            hostname=identity.hostname,
            confidence=identity.confidence,
            reasons=[*identity.reasons, f"vendor overridden to {vendor_override!r} by operator"],
        )

    pack = _select_pack(framework)
    tree = parse_cisco(text)
    normalized = normalize_cisco(tree, identity)
    results = evaluate_pack(pack, normalized.controls, identity)
    score = score_results(results)
    remediations = load_remediations(settings.mappings_dir)
    rules_by_id = {rule.id: rule for rule in pack.rules}

    run = AuditRun(
        configuration=configuration,
        framework=pack.framework,
        framework_version=pack.framework_version,
        status="completed",
        rule_pack_hash=pack.sha256,
        engine_version=settings.engine_version,
        detected_vendor=identity.vendor,
        detected_os=identity.os,
        detection_confidence=identity.confidence,
        detection_reasons=identity.reasons,
        vendor_override=vendor_override,
        unknown_constructs=[
            {"text": item.text, "lineno": item.lineno, "block": item.block}
            for item in normalized.unknowns
        ],
        parse_warnings=[{"lineno": item.lineno, "message": item.message} for item in tree.warnings],
        score=score.score,
        coverage=score.coverage,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()

    for key, value in sorted(normalized.controls.items()):
        session.add(
            NormalizedControlRow(
                audit_run_id=run.id,
                key=key,
                value_json=value.value,
                source_lines=value.source_lines,
                excerpt=value.excerpt,
                parser_confidence=value.parser_confidence,
                origin=value.origin,
            )
        )

    for item in results:
        row = ComplianceResultRow(
            audit_run_id=run.id,
            rule_id=item.rule_id,
            framework=item.framework,
            framework_version=item.framework_version,
            parameter=item.parameter,
            observed_value=item.observed_value,
            expected_value=item.expected_value,
            status=str(item.status),
            severity=str(item.severity),
            evidence_lines=item.evidence.source_lines if item.evidence else [],
            evidence_excerpt=item.evidence.excerpt if item.evidence else "",
        )
        session.add(row)
        session.flush()

        if item.status in (Status.FAIL, Status.WARNING):
            rule = rules_by_id[item.rule_id]
            # Startup validation guarantees this lookup resolves.
            remediation = remediations[rule.remediation_id]
            session.add(
                Finding(
                    compliance_result_id=row.id,
                    severity=str(item.severity),
                    title=rule.title,
                    remediation_id=remediation.id,
                )
            )

    return run
