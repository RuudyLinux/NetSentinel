import traceback
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.domain.device import DeviceIdentity
from app.domain.results import Status
from app.models import AuditRun, ComplianceResultRow, Configuration, Finding, NormalizedControlRow
from app.services.compliance.engine import evaluate_pack
from app.services.compliance.rules import RulePack, load_all_packs
from app.services.detection.registry import detect_vendor
from app.services.normalization.registry import get_normalizer
from app.services.parsing.registry import get_parser
from app.services.remediation.packs import load_remediations
from app.services.scoring.posture import score_results
from app.storage.base import StorageBackend


class DetectionConfirmationRequired(Exception):
    """Detection confidence is below the threshold; the caller must name the vendor."""

    def __init__(self, identity: DeviceIdentity) -> None:
        super().__init__("device detection requires manual confirmation")
        self.identity = identity


class UnknownFramework(ValueError):
    """Raised when no rule pack is loaded for the requested framework."""


def _select_pack(framework: str, vendor: str) -> RulePack:
    """Pick the pack for this framework that actually covers this vendor.

    The same framework name can have more than one active version at once — e.g.
    "CIS" covers both the Cisco IOS Benchmark (v8.0) and the FortiOS Benchmark
    (a different, independently-versioned document) as two separate packs. A
    request only names the framework, so disambiguation has to happen here,
    against the vendor the device was actually identified as.
    """
    packs = load_all_packs(settings.rules_dir)
    matching_framework = [pack for pack in packs if pack.framework.upper() == framework.upper()]
    if not matching_framework:
        raise UnknownFramework(f"no rule pack loaded for framework {framework!r}")

    for pack in matching_framework:
        if any(rule.applicability.vendor.lower() == vendor.lower() for rule in pack.rules):
            return pack

    covered = sorted(
        {rule.applicability.vendor for pack in matching_framework for rule in pack.rules}
    )
    raise UnknownFramework(
        f"no {framework!r} rule pack covers vendor {vendor!r} (covers: {covered})"
    )


def run_audit(
    session: Session,
    storage: StorageBackend,
    configuration: Configuration,
    framework: str,
    vendor_override: str | None = None,
) -> AuditRun:
    """Execute the full pipeline and persist every stage's output in one transaction.

    This is the only function in the codebase that both orchestrates stages and writes
    to the database. Every stage it calls (other than the AuditRun bookkeeping around
    it) is pure.

    Detection confidence and framework selection are preconditions checked *before*
    anything is persisted — like the confirmation gate below, an unresolvable one of
    these means there is nothing yet worth recording a run for. Everything from parsing
    onward runs inside a `running` row: if parsing, normalization, or evaluation raises
    (including an unsupported vendor discovered only once a real parser is requested),
    the run is persisted as `failed` with the error message attached rather than
    silently vanishing — the operator can see *that* it failed and *why*, not just get
    a 5xx.
    """
    text = storage.get(configuration.blob_key).decode("utf-8")
    identity = detect_vendor(text)

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
        # Upload-time detection may have guessed wrong (or defaulted) before the operator
        # confirmed the real vendor here; keep the Device row in sync with that confirmation.
        if configuration.device.vendor != identity.vendor:
            configuration.device.vendor = identity.vendor

    pack = _select_pack(framework, identity.vendor)

    run = AuditRun(
        configuration=configuration,
        framework=pack.framework,
        framework_version=pack.framework_version,
        status="running",
        rule_pack_hash=pack.sha256,
        engine_version=settings.engine_version,
        detected_vendor=identity.vendor,
        detected_os=identity.os,
        detection_confidence=identity.confidence,
        detection_reasons=identity.reasons,
        vendor_override=vendor_override,
        started_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()

    try:
        parse = get_parser(identity.vendor)
        normalize = get_normalizer(identity.vendor)
        tree = parse(text)
        normalized = normalize(tree, identity)
        results = evaluate_pack(pack, normalized.controls, identity)
        score = score_results(results)
        remediations = load_remediations(settings.mappings_dir)
        rules_by_id = {rule.id: rule for rule in pack.rules}
    except Exception as exc:
        run.status = "failed"
        run.error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
        run.finished_at = datetime.now(UTC)
        # Commit here, not flush: the caller's own commit (see api/audits.py) never
        # runs on this path because the exception below skips straight past it, and
        # an uncommitted transaction is rolled back when the request's session
        # closes. Without this commit the failed run would vanish instead of being
        # visible via GET /audits/{id}.
        session.commit()
        raise

    run.unknown_constructs = [
        {"text": item.text, "lineno": item.lineno, "block": item.block}
        for item in normalized.unknowns
    ]
    run.parse_warnings = [
        {"lineno": item.lineno, "message": item.message} for item in tree.warnings
    ]
    run.score = score.score
    run.coverage = score.coverage
    run.status = "completed"
    run.finished_at = datetime.now(UTC)

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
            # Startup validation (main.py's create_app) guarantees this lookup resolves.
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
