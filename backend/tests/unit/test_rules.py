from pathlib import Path

import pytest

from app.services.compliance.operators import Operator
from app.services.compliance.rules import RulePackError, load_pack

VALID = """
- id: CIS-SSH-002
  framework: CIS
  framework_version: "8.0"
  title: SSH protocol version 2 enforced
  description: SSH version 1 is cryptographically broken.
  impact: An attacker can recover session keys or hijack the session.
  applicability:
    vendor: cisco
    os: [ios, ios-xe]
  parameter: management.ssh.version
  operator: equals
  expected: 2
  severity: HIGH
  evidence_required: true
  remediation_id: REM-SSH-002
  source: "CIS Cisco IOS Benchmark v8.0 1.5.2"
  tests:
    - {given: 1, expect: FAIL}
    - {given: 2, expect: PASS}
    - {given: null, expect: NOT_ASSESSABLE}
"""


def test_load_pack_parses_rules(tmp_path: Path) -> None:
    path = tmp_path / "cis.yaml"
    path.write_text(VALID, encoding="utf-8")

    pack = load_pack(path)

    assert pack.framework == "CIS"
    assert pack.framework_version == "8.0"
    assert len(pack.rules) == 1
    assert pack.rules[0].operator is Operator.EQUALS
    assert pack.rules[0].applicability.os == ["ios", "ios-xe"]


def test_pack_hash_is_stable_and_content_derived(tmp_path: Path) -> None:
    first = tmp_path / "a.yaml"
    second = tmp_path / "b.yaml"
    first.write_text(VALID, encoding="utf-8")
    second.write_text(VALID, encoding="utf-8")

    assert load_pack(first).sha256 == load_pack(second).sha256
    assert len(load_pack(first).sha256) == 64


def test_rule_without_tests_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "cis.yaml"
    stripped = VALID.replace("  tests:", "  ignored:").split("  ignored:")[0]
    path.write_text(stripped, encoding="utf-8")

    with pytest.raises(RulePackError, match="tests"):
        load_pack(path)


def test_unknown_parameter_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "cis.yaml"
    path.write_text(VALID.replace("management.ssh.version", "made.up.key"), encoding="utf-8")

    with pytest.raises(RulePackError, match="made.up.key"):
        load_pack(path)


def test_mixed_frameworks_in_one_pack_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "cis.yaml"
    second_rule = VALID.replace("CIS-SSH-002", "NIST-SSH-002").replace(
        "framework: CIS", "framework: NIST"
    )
    path.write_text(VALID + second_rule, encoding="utf-8")

    with pytest.raises(RulePackError, match="single framework"):
        load_pack(path)
