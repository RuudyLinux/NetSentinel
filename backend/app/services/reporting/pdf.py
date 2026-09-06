from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import AiInterpretation, AuditRun, ComplianceResultRow, Finding
from app.services.remediation.packs import Remediation

# Ruling R5: these must be hex strings, not colors.HexColor objects — they are
# interpolated directly into a ReportLab `<font color="...">` markup tag, and
# f"{colors.HexColor('#b91c1c')}" renders as "Color(0.72,0.11,0.11,1)", which is
# not a valid color attribute for that tag.
_SEVERITY_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
    "INFO": "#475569",
}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=22, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], spaceBefore=14, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["BodyText"], alignment=TA_LEFT, leading=14),
        "mono": ParagraphStyle("m", parent=base["Code"], fontSize=8, leading=11),
    }


def _round_half_up(value: float) -> int:
    """Round-half-up, matching the frontend's `Math.round`. Python's `:.0f` format
    spec rounds half-to-even instead, so the same value (e.g. an 0.625 coverage
    fraction, 62.5 as a percent) prints as 63% in the UI but 62% in this PDF —
    same number, two different percentages in the same product."""
    return int(value + 0.5) if value >= 0 else -int(-value + 0.5)


def _kv_table(rows: list[tuple[str, str]]) -> Table:
    table = Table([[key, value] for key, value in rows], colWidths=[45 * mm, 115 * mm])
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#334155")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def build_device_report(
    run: AuditRun,
    findings: list[tuple[Finding, ComplianceResultRow]],
    remediations: dict[str, Remediation],
    ai_interpretations: list[AiInterpretation] | None = None,
) -> bytes:
    """Render the device report. Every string here originates in redacted data."""
    style = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"NetSentinel Report — Audit {run.id}",
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    story: list[object] = [
        Paragraph("NetSentinel AI", style["title"]),
        Paragraph("Device Security Compliance Report", style["h3"]),
        Spacer(1, 6 * mm),
        _kv_table(
            [
                ("Organization", run.configuration.device.organization.name),
                ("Device", run.configuration.device.name),
                (
                    "Vendor / OS",
                    f"{run.detected_vendor} {run.detected_os} "
                    f"{run.configuration.device.os_version or ''}",
                ),
                (
                    "Detection confidence",
                    f"{_round_half_up((run.detection_confidence or 0) * 100)}%",
                ),
                ("Configuration SHA-256", run.configuration.sha256),
                ("Framework", f"{run.framework} {run.framework_version}"),
                ("Rule pack SHA-256", run.rule_pack_hash),
                ("Engine version", run.engine_version),
                ("Audit date", run.started_at.isoformat() if run.started_at else ""),
            ]
        ),
        Spacer(1, 8 * mm),
        Paragraph("Executive Summary", style["h2"]),
        _kv_table(
            [
                ("Posture score", f"{run.score} / 100"),
                ("Assessment coverage", f"{_round_half_up((run.coverage or 0) * 100)}%"),
                ("Findings", str(len(findings))),
                ("Unrecognized commands", str(len(run.unknown_constructs))),
            ]
        ),
        Paragraph(
            "The posture score is a severity-weighted measure of assessed controls. "
            "It is an indicator of configuration hardening, not a certification of compliance.",
            style["body"],
        ),
    ]

    if findings:
        story.extend([PageBreak(), Paragraph("Findings", style["h2"])])

    for finding, result in findings:
        remediation = remediations[finding.remediation_id]
        story.extend(
            [
                Paragraph(
                    f'<font color="{_SEVERITY_COLORS.get(finding.severity, "#000000")}">'
                    f"[{finding.severity}]</font> {result.rule_id} — {finding.title}",
                    style["h3"],
                ),
                _kv_table(
                    [
                        ("Parameter", result.parameter),
                        ("Observed", str(result.observed_value)),
                        ("Expected", str(result.expected_value)),
                        ("Status", result.status),
                        ("Triage", finding.triage_status),
                        ("Evidence lines", ", ".join(str(n) for n in result.evidence_lines)),
                    ]
                ),
                Paragraph("Evidence", style["h3"]),
                Paragraph(
                    result.evidence_excerpt or "(no matching configuration line)", style["mono"]
                ),
                Paragraph("Remediation", style["h3"]),
                Paragraph(remediation.cli.replace("\n", "<br/>"), style["mono"]),
                Paragraph(f"<b>Verification:</b> {remediation.verification}", style["body"]),
                Paragraph(
                    f"<b>Rollback:</b> {remediation.rollback.replace(chr(10), ' / ')}",
                    style["body"],
                ),
                Paragraph(f"<i>{remediation.banner}</i>", style["body"]),
                Spacer(1, 4 * mm),
            ]
        )

    if ai_interpretations:
        story.extend(
            [
                PageBreak(),
                Paragraph("AI-Assisted Interpretations", style["h2"]),
                Paragraph(
                    "Advisory only — the deterministic rule engine never reads these. Each "
                    "row is a human-reviewable suggestion for a configuration line the parser "
                    "did not recognize; it does not affect this audit's score or findings "
                    "unless a human separately approves it and it is incorporated into a "
                    "future rule or mapping.",
                    style["body"],
                ),
            ]
        )
        for interpretation in ai_interpretations:
            construct = (
                run.unknown_constructs[interpretation.construct_index]
                if interpretation.construct_index < len(run.unknown_constructs)
                else {"text": "(construct no longer available)", "lineno": None}
            )
            reviewer = interpretation.reviewed_by.email if interpretation.reviewed_by else None
            story.extend(
                [
                    Paragraph(f"Line {construct.get('lineno', '?')}", style["h3"]),
                    _kv_table(
                        [
                            ("Configuration line", str(construct.get("text", ""))),
                            ("Model", interpretation.model),
                            ("Interpretation", interpretation.interpretation),
                            ("Suggested parameter", interpretation.suggested_parameter or "—"),
                            ("Suggested value", str(interpretation.suggested_value)),
                            ("Confidence", f"{_round_half_up(interpretation.confidence * 100)}%"),
                            ("Review status", interpretation.status.upper()),
                            ("Reviewed by", reviewer or "Not yet reviewed"),
                        ]
                    ),
                    Spacer(1, 4 * mm),
                ]
            )

    document.build(story)
    return buffer.getvalue()
