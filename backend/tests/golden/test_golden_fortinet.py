import json
from pathlib import Path

import pytest

from app.config import settings
from app.security.redaction import redact
from app.services.compliance.engine import evaluate_pack
from app.services.compliance.rules import load_all_packs
from app.services.detection.registry import detect_vendor
from app.services.normalization.registry import get_normalizer
from app.services.parsing.registry import get_parser
from app.services.scoring.posture import score_results

DATASETS = settings.rules_dir.parent / "datasets" / "demo" / "fortinet"
EXPECTED = Path(__file__).parent / "expected"
CASES = ["compliant", "noncompliant", "mixed"]


def run_pipeline(name: str) -> dict[str, object]:
    """Same shape as tests/golden/test_golden.py's run_pipeline, but dispatched
    through the vendor registries (services/*/registry.py) instead of importing
    Cisco's functions directly — this is the multi-vendor pipeline path every
    real audit actually takes (see services/audit/runner.py)."""
    raw = (DATASETS / f"{name}.cfg").read_text(encoding="utf-8")
    redacted = redact(raw)
    identity = detect_vendor(redacted.text)
    tree = get_parser(identity.vendor)(redacted.text)
    normalized = get_normalizer(identity.vendor)(tree, identity)
    pack = next(
        pack
        for pack in load_all_packs(settings.rules_dir)
        if pack.framework == "CIS" and any(r.applicability.vendor == "fortinet" for r in pack.rules)
    )
    results = evaluate_pack(pack, normalized.controls, identity)
    score = score_results(results)
    return {
        "vendor": identity.vendor,
        "os": identity.os,
        "controls": {key: value.value for key, value in sorted(normalized.controls.items())},
        "results": {item.rule_id: item.status.value for item in results},
        "score": score.score,
        "coverage": score.coverage,
        "unknown_count": len(normalized.unknowns),
    }


@pytest.mark.parametrize("name", CASES)
def test_golden_pipeline_output_is_stable(name: str) -> None:
    actual = run_pipeline(name)
    expected = json.loads((EXPECTED / f"fortinet_{name}.json").read_text(encoding="utf-8"))
    assert actual == expected


def test_compliant_config_passes_every_rule() -> None:
    output = run_pipeline("compliant")
    statuses = set(output["results"].values())  # type: ignore[union-attr]
    assert statuses == {"PASS"}
    assert output["score"] == 100


def test_noncompliant_config_fails_every_rule() -> None:
    output = run_pipeline("noncompliant")
    statuses: dict[str, str] = output["results"]  # type: ignore[assignment]
    assert set(statuses.values()) == {"FAIL"}
    assert output["score"] == 0


def test_mixed_config_exercises_the_unknown_construct_path() -> None:
    assert run_pipeline("mixed")["unknown_count"] >= 2


def test_no_secret_survives_the_pipeline() -> None:
    for name in CASES:
        raw = (DATASETS / f"{name}.cfg").read_text(encoding="utf-8")
        output = json.dumps(run_pipeline(name))
        for line in raw.splitlines():
            if "set password ENC " in line:
                secret = line.split("set password ENC ")[1].strip()
                assert secret not in output
