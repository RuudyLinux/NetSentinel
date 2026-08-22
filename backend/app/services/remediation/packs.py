from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

REMEDIATION_BANNER = "Review and validate before production deployment."


class RemediationError(ValueError):
    """Raised when a remediation pack is malformed."""


class Remediation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    vendor: str
    os: list[str]
    title: str
    cli: str
    verification: str
    rollback: str
    notes: str = ""

    @property
    def banner(self) -> str:
        return REMEDIATION_BANNER


def load_remediations(mappings_dir: Path) -> dict[str, Remediation]:
    remediations: dict[str, Remediation] = {}
    for path in sorted(mappings_dir.rglob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RemediationError(f"{path}: invalid YAML: {exc}") from exc
        if not isinstance(document, dict):
            raise RemediationError(f"{path}: expected a mapping of remediation ids")
        for key, body in document.items():
            if key in remediations:
                raise RemediationError(f"{path}: duplicate remediation id {key}")
            try:
                remediations[key] = Remediation.model_validate({"id": key} | body)
            except ValidationError as exc:
                raise RemediationError(f"{path}: {key}: {exc}") from exc
    if not remediations:
        raise RemediationError(f"{mappings_dir}: no remediations found")
    return remediations
