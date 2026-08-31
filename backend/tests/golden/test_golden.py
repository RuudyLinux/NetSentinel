import json
from pathlib import Path

import pytest

from app.config import settings
from app.security.redaction import redact
from app.services.compliance.engine import evaluate_pack
from app.services.compliance.rules import load_all_packs
from app.services.detection.cisco import detect
from app.services.normalization.cisco import normalize_cisco
from app.services.parsing.cisco import parse_cisco
from app.services.scoring.posture import score_results

DATASETS = settings.rules_dir.parent / "datasets" / "demo" / "cisco"
EXPECTED = Path(__file__).parent / "expected"
CASES = ["compliant", "noncompliant", "mixed"]


def run_pipeline(name: str) -> dict[str, object]:
    raw = (DATASETS / f"{name}.cfg").read_text(encoding="utf-8")
    redacted = redact(raw)
    identity = detect(redacted.text)
    tree = parse_cisco(redacted.text)
    normalized = normalize_cisco(tree, identity)
    pack = load_all_packs(settings.rules_dir)[0]
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
    expected = json.loads((EXPECTED / f"{name}.json").read_text(encoding="utf-8"))
    assert actual == expected


def test_compliant_config_passes_every_rule() -> None:
    output = run_pipeline("compliant")
    statuses = set(output["results"].values())  # type: ignore[union-attr]
    assert statuses == {"PASS"}
    assert output["score"] == 100


def test_noncompliant_config_fails_every_rule() -> None:
    """Ruling R3(c): CIS-SSH-001 (ssh.enabled==true) and CIS-SSH-002 (ssh.version==2) cannot
    both FAIL in one configuration -- SSH-002 can only fail against an observed wrong version,
    and a device with no SSH configured at all has no version to observe. noncompliant.cfg
    configures no SSH at all, so SSH-002 is NOT_ASSESSABLE rather than FAIL; every other rule
    still fails and no rule passes."""
    output = run_pipeline("noncompliant")
    statuses: dict[str, str] = output["results"]  # type: ignore[assignment]
    assert "PASS" not in statuses.values()
    not_assessable = [rule_id for rule_id, status in statuses.items() if status == "NOT_ASSESSABLE"]
    assert not_assessable == ["CIS-SSH-002"]
    assert output["score"] == 0


def test_mixed_config_exercises_the_unknown_construct_path() -> None:
    assert run_pipeline("mixed")["unknown_count"] >= 2


def test_no_secret_survives_the_pipeline() -> None:
    for name in CASES:
        raw = (DATASETS / f"{name}.cfg").read_text(encoding="utf-8")
        output = json.dumps(run_pipeline(name))
        for line in raw.splitlines():
            if "password 7 " in line:
                secret = line.split("password 7 ")[1].strip()
                assert secret not in output
