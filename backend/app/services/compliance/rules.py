import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.domain.controls import CONTROL_KEYS, ControlPrimitive
from app.domain.results import Severity, Status
from app.services.compliance.operators import Operator


class RulePackError(ValueError):
    """Raised when a rule pack is malformed. Startup must fail closed on this."""


class Applicability(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    vendor: str
    os: list[str]

    def matches(self, vendor: str, os: str) -> bool:
        return self.vendor.lower() == vendor.lower() and os.lower() in {
            candidate.lower() for candidate in self.os
        }


class RuleTest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    given: ControlPrimitive = None
    expect: Status


class Rule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    framework: str
    framework_version: str
    title: str
    description: str
    impact: str
    applicability: Applicability
    parameter: str
    operator: Operator
    expected: ControlPrimitive = None
    severity: Severity
    evidence_required: bool = True
    remediation_id: str
    source: str
    tests: list[RuleTest] = Field(min_length=1)


@dataclass(frozen=True)
class RulePack:
    framework: str
    framework_version: str
    rules: tuple[Rule, ...]
    sha256: str
    path: Path

    @property
    def identifier(self) -> str:
        return f"{self.framework}@{self.framework_version}"


def load_pack(path: Path) -> RulePack:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()

    try:
        documents = yaml.safe_load(raw.decode("utf-8"))
    except yaml.YAMLError as exc:
        raise RulePackError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(documents, list) or not documents:
        raise RulePackError(f"{path}: expected a non-empty list of rules")

    rules: list[Rule] = []
    for index, document in enumerate(documents):
        try:
            rules.append(Rule.model_validate(document))
        except ValidationError as exc:
            raise RulePackError(f"{path}: rule #{index}: {exc}") from exc

    unknown = {rule.parameter for rule in rules} - CONTROL_KEYS
    if unknown:
        raise RulePackError(f"{path}: rules reference unknown parameters: {sorted(unknown)}")

    frameworks = {(rule.framework, rule.framework_version) for rule in rules}
    if len(frameworks) != 1:
        raise RulePackError(f"{path}: a pack must declare a single framework and version")

    duplicates = _duplicate_ids(rules)
    if duplicates:
        raise RulePackError(f"{path}: duplicate rule ids: {sorted(duplicates)}")

    framework, framework_version = frameworks.pop()
    return RulePack(
        framework=framework,
        framework_version=framework_version,
        rules=tuple(rules),
        sha256=digest,
        path=path,
    )


def _duplicate_ids(rules: list[Rule]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            duplicates.add(rule.id)
        seen.add(rule.id)
    return duplicates


def load_all_packs(rules_dir: Path) -> list[RulePack]:
    packs = [load_pack(path) for path in sorted(rules_dir.rglob("*.yaml"))]
    if not packs:
        raise RulePackError(f"{rules_dir}: no rule packs found")
    return packs
