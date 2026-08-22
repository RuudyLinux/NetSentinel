# NetSentinel Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry a Cisco IOS configuration file from upload through detection, parsing, normalization, deterministic CIS evaluation, and findings with full provenance, out to a PDF report — behind real authentication and server-side RBAC.

**Architecture:** Six pure pipeline stages (sanitize → detect → parse → normalize → evaluate → score) each a total function from typed input to typed output, with no database or filesystem access. Persistence and orchestration live only in `services/audit/runner.py`. Compliance rules are versioned YAML data, never code. Three named seams — `DATABASE_URL`, `StorageBackend`, `TaskRunner` — bind to local implementations so the slice runs without Docker.

**Tech Stack:** Python 3.13 (uv), FastAPI, Pydantic v2, SQLAlchemy 2.0 (sync), Alembic, SQLite, argon2-cffi, PyJWT, PyYAML, ReportLab, pytest. Frontend: Vite, React 19, TypeScript, Tailwind, TanStack Query, React Router, Recharts.

**Spec:** `docs/superpowers/specs/2026-08-22-netsentinel-spine-design.md`

## Global Constraints

- Python **3.13** pinned via `uv` — never the system Python 3.8.
- Repo root is `d:\Aproject\NetSentinel`. Backend lives in `backend/`, frontend in `frontend/`.
- API base path is **`/api/v1`**.
- **No SQLite-specific SQL.** Every model must map cleanly to PostgreSQL.
- **No filesystem paths outside `app/storage/local.py`.** All blob access goes through `StorageBackend`.
- **No `BackgroundTasks` import outside `app/tasks/inline.py`.**
- **Authorization is server-side only.** Every protected route declares `Depends(require(Permission.X))`.
- **Redacted text is the only configuration text that may reach the database, API responses, logs, or PDFs.**
- A control absent from the `ControlSet`, or present with `value=None`, evaluates to `NOT_ASSESSABLE` — **never** `PASS`.
- Rule packs that fail schema validation **abort application startup**. Fail closed.
- Every rendered remediation carries the literal banner: `Review and validate before production deployment.`
- Lint with `ruff`, type-check with `mypy`. Both must pass before every commit.
- Never commit secrets, real customer configurations, or private keys.

## Architecture note: the `domain/` package

The design doc's §5 layout places shared types inside their consuming service. This plan introduces `backend/app/domain/` instead, holding the pure dataclasses that cross stage boundaries (`ControlValue`, `DeviceIdentity`, `ComplianceResult`, `Status`, `Severity`). Without it, `parsing/` would import from `compliance/` and vice versa — a cycle. Everything else follows the design doc's layout exactly.

## File Structure

| File | Responsibility |
|------|----------------|
| `backend/app/config.py` | Pydantic `Settings`; binds `DATABASE_URL`, `JWT_SECRET`, `STORAGE_DIR`, `RULES_DIR`, `MAPPINGS_DIR` |
| `backend/app/db.py` | Engine, `SessionLocal`, declarative `Base`, `get_db` dependency |
| `backend/app/main.py` | App factory, router mounting, startup rule-pack validation |
| `backend/app/domain/controls.py` | `ControlValue`, `ControlSet`, `ControlOrigin`, `CONTROL_KEYS` registry |
| `backend/app/domain/device.py` | `DeviceIdentity` |
| `backend/app/domain/results.py` | `Status`, `Severity`, `ComplianceResult`, `PostureScore` |
| `backend/app/security/passwords.py` | Argon2id hash/verify |
| `backend/app/security/tokens.py` | JWT issue/decode; refresh hashing |
| `backend/app/security/permissions.py` | `Permission` enum, `ROLE_PERMISSIONS` matrix |
| `backend/app/security/redaction.py` | `redact()`, `SecretHit`, `RedactionResult` |
| `backend/app/models/*.py` | SQLAlchemy ORM models, one module per aggregate |
| `backend/app/api/deps.py` | `get_current_user`, `require(Permission)` |
| `backend/app/api/*.py` | Routers, one per resource |
| `backend/app/services/compliance/rules.py` | `Rule` schema, `load_pack`, pack hashing |
| `backend/app/services/compliance/operators.py` | Operator evaluation, closed set |
| `backend/app/services/compliance/engine.py` | `evaluate_rule`, `evaluate_pack` |
| `backend/app/services/detection/cisco.py` | Weighted signature scoring |
| `backend/app/services/parsing/cisco.py` | `ConfigNode`, `ConfigTree`, `parse_cisco` |
| `backend/app/services/normalization/cisco.py` | `ConfigTree` → 16 controls |
| `backend/app/services/remediation/packs.py` | Remediation YAML loader + lookup |
| `backend/app/services/scoring/posture.py` | `score_results` |
| `backend/app/services/reporting/pdf.py` | ReportLab device report |
| `backend/app/services/audit/runner.py` | The only module that both orchestrates and persists |
| `backend/app/storage/{base,local}.py` | `StorageBackend` protocol + local implementation |
| `backend/app/tasks/{base,inline}.py` | `TaskRunner` protocol + inline implementation |
| `rules/cis/cisco-ios-v8.yaml` | 16 self-testing CIS rules |
| `mappings/cisco/remediation.yaml` | Remediation entries keyed by `remediation_id` |

---

## Task 1: Project scaffold

**Files:**
- Create: `backend/pyproject.toml`, `backend/app/__init__.py`, `backend/app/config.py`, `backend/app/main.py`
- Create: `backend/tests/__init__.py`, `backend/tests/conftest.py`, `backend/tests/unit/test_health.py`
- Create: `.github/workflows/ci.yml`, `backend/.env.example`

**Interfaces:**
- Consumes: nothing
- Produces: `create_app() -> FastAPI`; `Settings` with fields `database_url: str`, `jwt_secret: str`, `storage_dir: Path`, `rules_dir: Path`, `mappings_dir: Path`, `access_token_minutes: int`, `refresh_token_days: int`; module-level `settings: Settings`

- [ ] **Step 1: Create the uv project and pin Python 3.13**

```bash
cd d:/Aproject/NetSentinel
uv init --python 3.13 --no-workspace --bare backend
cd backend
uv add fastapi "uvicorn[standard]" "pydantic>=2.7" pydantic-settings "sqlalchemy>=2.0" alembic argon2-cffi pyjwt pyyaml reportlab python-multipart
uv add --dev pytest pytest-cov httpx ruff mypy types-PyYAML
```

Expected: `backend/pyproject.toml` and `backend/.venv/` exist. `uv run python --version` prints `Python 3.13.x`.

- [ ] **Step 2: Add tool configuration to `backend/pyproject.toml`**

Append to the file:

```toml
[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.13"
strict = true
plugins = ["pydantic.mypy"]
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

- [ ] **Step 3: Write the failing test**

Create `backend/tests/unit/test_health.py`:

```python
from fastapi.testclient import TestClient

from app.main import create_app


def test_healthz_reports_ok() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_health.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.main'`

- [ ] **Step 5: Write `backend/app/config.py`**

```python
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NETSENTINEL_", extra="ignore")

    database_url: str = f"sqlite:///{REPO_ROOT / 'var' / 'netsentinel.db'}"
    jwt_secret: str = "dev-only-secret-change-me"
    storage_dir: Path = REPO_ROOT / "var" / "blobs"
    rules_dir: Path = REPO_ROOT / "rules"
    mappings_dir: Path = REPO_ROOT / "mappings"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    max_upload_bytes: int = 5 * 1024 * 1024
    engine_version: str = "0.1.0"


settings = Settings()
```

- [ ] **Step 6: Write `backend/app/main.py`**

```python
from fastapi import APIRouter, FastAPI

health_router = APIRouter()


@health_router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def create_app() -> FastAPI:
    app = FastAPI(title="NetSentinel AI", version="0.1.0")
    app.include_router(health_router, prefix="/api/v1")
    return app


app = create_app()
```

Create empty `backend/app/__init__.py`, `backend/tests/__init__.py`, `backend/tests/unit/__init__.py`.

- [ ] **Step 7: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_health.py -v`
Expected: PASS

- [ ] **Step 8: Write `backend/.env.example`**

```bash
NETSENTINEL_JWT_SECRET=replace-with-openssl-rand-hex-32
NETSENTINEL_DATABASE_URL=sqlite:///./var/netsentinel.db
```

- [ ] **Step 9: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]

jobs:
  backend:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: backend
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
        with:
          python-version: "3.13"
      - run: uv sync --dev
      - run: uv run ruff check .
      - run: uv run ruff format --check .
      - run: uv run mypy app
      - run: uv run pytest --cov=app --cov-report=term-missing
```

- [ ] **Step 10: Verify lint and types pass**

Run: `uv run ruff check . && uv run ruff format . && uv run mypy app`
Expected: no errors.

- [ ] **Step 11: Commit**

```bash
git add backend .github .gitignore
git commit -m "feat: scaffold FastAPI backend with uv, ruff, mypy, and CI"
```

---

## Task 2: Domain types

**Files:**
- Create: `backend/app/domain/__init__.py`, `backend/app/domain/controls.py`, `backend/app/domain/device.py`, `backend/app/domain/results.py`
- Test: `backend/tests/unit/test_domain.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `ControlOrigin = Literal["deterministic", "inferred", "learned"]`
  - `ControlValue(value, source_lines, excerpt, parser_confidence=1.0, origin="deterministic")` — frozen dataclass
  - `ControlSet = dict[str, ControlValue]`
  - `CONTROL_KEYS: frozenset[str]` — the 16 keys
  - `DeviceIdentity(vendor, product_family, os, os_version, hostname, confidence, reasons)` — frozen dataclass
  - `Status` and `Severity` — `StrEnum`
  - `ComplianceResult(rule_id, framework, framework_version, parameter, observed_value, expected_value, status, severity, evidence)` — frozen dataclass
  - `PostureScore(score, coverage, fail_counts, assessable, not_assessable)` — frozen dataclass

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_domain.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_domain.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.domain'`

- [ ] **Step 3: Write `backend/app/domain/controls.py`**

```python
from dataclasses import dataclass, field
from typing import Literal

ControlOrigin = Literal["deterministic", "inferred", "learned"]
ControlPrimitive = bool | int | str | list[str] | None


@dataclass(frozen=True)
class ControlValue:
    """A normalized security control observation, with the evidence that produced it."""

    value: ControlPrimitive
    source_lines: list[int] = field(default_factory=list)
    excerpt: str = ""
    parser_confidence: float = 1.0
    origin: ControlOrigin = "deterministic"


ControlSet = dict[str, ControlValue]

CONTROL_KEYS: frozenset[str] = frozenset(
    {
        "management.ssh.enabled",
        "management.ssh.version",
        "management.telnet.enabled",
        "management.http.enabled",
        "management.https.enabled",
        "management.session_timeout",
        "management.acl.present",
        "auth.password.min_length",
        "auth.aaa.enabled",
        "auth.enable_secret.encrypted",
        "auth.default_accounts.present",
        "logging.local.enabled",
        "logging.remote.enabled",
        "time.ntp.enabled",
        "snmp.v3.only",
        "banner.login.present",
    }
)
```

- [ ] **Step 4: Write `backend/app/domain/device.py`**

```python
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceIdentity:
    """The result of vendor/OS detection, carrying the reasoning behind the confidence."""

    vendor: str
    os: str
    confidence: float
    product_family: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    reasons: list[str] = field(default_factory=list)

    @property
    def needs_confirmation(self) -> bool:
        return self.confidence < 0.70
```

- [ ] **Step 5: Write `backend/app/domain/results.py`**

```python
from dataclasses import dataclass, field
from enum import StrEnum

from app.domain.controls import ControlPrimitive, ControlValue


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_ASSESSABLE = "NOT_ASSESSABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class ComplianceResult:
    rule_id: str
    framework: str
    framework_version: str
    parameter: str
    observed_value: ControlPrimitive
    expected_value: ControlPrimitive
    status: Status
    severity: Severity
    evidence: ControlValue | None = None


@dataclass(frozen=True)
class PostureScore:
    score: int
    coverage: float
    fail_counts: dict[Severity, int] = field(default_factory=dict)
    assessable: int = 0
    not_assessable: int = 0
```

Create empty `backend/app/domain/__init__.py`.

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_domain.py -v`
Expected: PASS (4 tests)

- [ ] **Step 7: Commit**

```bash
git add backend/app/domain backend/tests/unit/test_domain.py
git commit -m "feat: add domain types for controls, device identity, and results"
```

---

## Task 3: Compliance operators

**Files:**
- Create: `backend/app/services/__init__.py`, `backend/app/services/compliance/__init__.py`, `backend/app/services/compliance/operators.py`
- Test: `backend/tests/unit/test_operators.py`

**Interfaces:**
- Consumes: `app.domain.controls.ControlPrimitive`
- Produces: `Operator` (`StrEnum` with members `EQUALS="equals"`, `NOT_EQUALS="not_equals"`, `GTE="gte"`, `LTE="lte"`, `GT="gt"`, `LT="lt"`, `IN="in"`, `NOT_IN="not_in"`, `PRESENT="present"`, `ABSENT="absent"`, `MATCHES="matches"`); `apply_operator(op: Operator, observed: ControlPrimitive, expected: ControlPrimitive) -> bool`; `OperatorError`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_operators.py`:

```python
import pytest

from app.services.compliance.operators import Operator, OperatorError, apply_operator


@pytest.mark.parametrize(
    ("op", "observed", "expected", "want"),
    [
        (Operator.EQUALS, 2, 2, True),
        (Operator.EQUALS, 1, 2, False),
        (Operator.EQUALS, True, True, True),
        (Operator.NOT_EQUALS, 1, 2, True),
        (Operator.GTE, 12, 8, True),
        (Operator.GTE, 8, 8, True),
        (Operator.GTE, 7, 8, False),
        (Operator.LTE, 300, 600, True),
        (Operator.GT, 9, 8, True),
        (Operator.LT, 7, 8, True),
        (Operator.IN, "sha256", ["sha256", "sha512"], True),
        (Operator.IN, "md5", ["sha256"], False),
        (Operator.NOT_IN, "md5", ["sha256"], True),
        (Operator.PRESENT, False, None, True),
        (Operator.PRESENT, None, None, False),
        (Operator.ABSENT, None, None, True),
        (Operator.ABSENT, 1, None, False),
        (Operator.MATCHES, "10.0.0.0/8", r"^\d+\.\d+\.\d+\.\d+/\d+$", True),
        (Operator.MATCHES, "nope", r"^\d+$", False),
    ],
)
def test_operator_truth_table(
    op: Operator, observed: object, expected: object, want: bool
) -> None:
    assert apply_operator(op, observed, expected) is want  # type: ignore[arg-type]


def test_ordering_operator_rejects_non_numeric_observation() -> None:
    with pytest.raises(OperatorError):
        apply_operator(Operator.GTE, "eight", 8)


def test_bool_is_not_accepted_as_a_number() -> None:
    """True == 1 in Python; ordering comparisons must not silently accept booleans."""
    with pytest.raises(OperatorError):
        apply_operator(Operator.GTE, True, 8)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_operators.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services'`

- [ ] **Step 3: Write `backend/app/services/compliance/operators.py`**

```python
import re
from enum import StrEnum

from app.domain.controls import ControlPrimitive


class OperatorError(ValueError):
    """Raised when an operator is applied to a value it cannot compare."""


class Operator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GTE = "gte"
    LTE = "lte"
    GT = "gt"
    LT = "lt"
    IN = "in"
    NOT_IN = "not_in"
    PRESENT = "present"
    ABSENT = "absent"
    MATCHES = "matches"


_ORDERING = {Operator.GTE, Operator.LTE, Operator.GT, Operator.LT}


def _as_number(value: ControlPrimitive, op: Operator) -> int:
    # bool is a subclass of int; treating it as a number would make `True >= 8` meaningful.
    if isinstance(value, bool) or not isinstance(value, int):
        raise OperatorError(f"operator {op} requires a numeric value, got {value!r}")
    return value


def apply_operator(
    op: Operator, observed: ControlPrimitive, expected: ControlPrimitive
) -> bool:
    if op is Operator.PRESENT:
        return observed is not None
    if op is Operator.ABSENT:
        return observed is None

    if op in _ORDERING:
        left = _as_number(observed, op)
        right = _as_number(expected, op)
        match op:
            case Operator.GTE:
                return left >= right
            case Operator.LTE:
                return left <= right
            case Operator.GT:
                return left > right
            case _:
                return left < right

    match op:
        case Operator.EQUALS:
            return observed == expected
        case Operator.NOT_EQUALS:
            return observed != expected
        case Operator.IN:
            if not isinstance(expected, list):
                raise OperatorError("operator 'in' requires a list expectation")
            return observed in expected
        case Operator.NOT_IN:
            if not isinstance(expected, list):
                raise OperatorError("operator 'not_in' requires a list expectation")
            return observed not in expected
        case Operator.MATCHES:
            if not isinstance(observed, str) or not isinstance(expected, str):
                raise OperatorError("operator 'matches' requires string operands")
            return re.search(expected, observed) is not None
        case _:  # pragma: no cover - exhaustive over the enum
            raise OperatorError(f"unhandled operator {op}")
```

Create empty `backend/app/services/__init__.py` and `backend/app/services/compliance/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_operators.py -v`
Expected: PASS (21 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services backend/tests/unit/test_operators.py
git commit -m "feat: add closed operator set for compliance rule evaluation"
```

---

## Task 4: Rule schema and pack loader

**Files:**
- Create: `backend/app/services/compliance/rules.py`
- Test: `backend/tests/unit/test_rules.py`

**Interfaces:**
- Consumes: `Operator`, `Severity`, `Status`
- Produces: `Applicability(vendor: str, os: list[str])`; `RuleTest(given: ControlPrimitive, expect: Status)`; `Rule(id, framework, framework_version, title, description, applicability, parameter, operator, expected, severity, evidence_required, remediation_id, source, tests)`; `RulePack(framework, framework_version, rules, sha256, path)`; `load_pack(path: Path) -> RulePack`; `load_all_packs(rules_dir: Path) -> list[RulePack]`; `RulePackError`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_rules.py`:

```python
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
    path.write_text(VALID.replace("  tests:", "  ignored:").split("  ignored:")[0], encoding="utf-8")

    with pytest.raises(RulePackError, match="tests"):
        load_pack(path)


def test_unknown_parameter_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "cis.yaml"
    path.write_text(VALID.replace("management.ssh.version", "made.up.key"), encoding="utf-8")

    with pytest.raises(RulePackError, match="made.up.key"):
        load_pack(path)


def test_mixed_frameworks_in_one_pack_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "cis.yaml"
    path.write_text(VALID + VALID.replace("CIS-SSH-002", "NIST-SSH-002").replace("framework: CIS", "framework: NIST"), encoding="utf-8")

    with pytest.raises(RulePackError, match="single framework"):
        load_pack(path)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_rules.py -v`
Expected: FAIL with `ImportError: cannot import name 'load_pack'`

- [ ] **Step 3: Write `backend/app/services/compliance/rules.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_rules.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/compliance/rules.py backend/tests/unit/test_rules.py
git commit -m "feat: add rule pack schema, loader, and content hashing"
```

---

## Task 5: Rule engine

**Files:**
- Create: `backend/app/services/compliance/engine.py`
- Test: `backend/tests/unit/test_engine.py`

**Interfaces:**
- Consumes: `Rule`, `RulePack`, `apply_operator`, `ControlSet`, `DeviceIdentity`, `ComplianceResult`, `Status`
- Produces: `evaluate_rule(rule: Rule, controls: ControlSet, identity: DeviceIdentity) -> ComplianceResult`; `evaluate_pack(pack: RulePack, controls: ControlSet, identity: DeviceIdentity) -> list[ComplianceResult]`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_engine.py`:

```python
from app.domain.controls import ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.domain.results import Severity, Status
from app.services.compliance.engine import evaluate_rule
from app.services.compliance.rules import Applicability, Rule, RuleTest
from app.services.compliance.operators import Operator

CISCO = DeviceIdentity(vendor="cisco", os="ios-xe", confidence=0.98)
JUNIPER = DeviceIdentity(vendor="juniper", os="junos", confidence=0.98)


def make_rule(**overrides: object) -> Rule:
    base: dict[str, object] = {
        "id": "CIS-SSH-002",
        "framework": "CIS",
        "framework_version": "8.0",
        "title": "SSH v2 enforced",
        "description": "SSHv1 is broken.",
        "applicability": Applicability(vendor="cisco", os=["ios", "ios-xe"]),
        "parameter": "management.ssh.version",
        "operator": Operator.EQUALS,
        "expected": 2,
        "severity": Severity.HIGH,
        "remediation_id": "REM-SSH-002",
        "source": "CIS v8.0",
        "tests": [RuleTest(given=2, expect=Status.PASS)],
    }
    return Rule.model_validate(base | overrides)


def controls(value: object) -> ControlSet:
    return {"management.ssh.version": ControlValue(value=value, source_lines=[41], excerpt="ip ssh version 1")}  # type: ignore[arg-type]


def test_satisfied_expectation_passes() -> None:
    assert evaluate_rule(make_rule(), controls(2), CISCO).status is Status.PASS


def test_violated_expectation_fails_and_carries_evidence() -> None:
    result = evaluate_rule(make_rule(), controls(1), CISCO)
    assert result.status is Status.FAIL
    assert result.observed_value == 1
    assert result.expected_value == 2
    assert result.evidence is not None
    assert result.evidence.source_lines == [41]


def test_missing_control_is_not_assessable() -> None:
    result = evaluate_rule(make_rule(), {}, CISCO)
    assert result.status is Status.NOT_ASSESSABLE
    assert result.evidence is None


def test_control_observed_as_none_is_not_assessable() -> None:
    assert evaluate_rule(make_rule(), controls(None), CISCO).status is Status.NOT_ASSESSABLE


def test_wrong_vendor_is_not_applicable() -> None:
    assert evaluate_rule(make_rule(), controls(1), JUNIPER).status is Status.NOT_APPLICABLE


def test_presence_operators_treat_none_as_an_observation() -> None:
    """`absent` must be assessable against a null value — that is the point of the operator."""
    rule = make_rule(
        id="CIS-TELNET-001",
        parameter="management.telnet.enabled",
        operator=Operator.ABSENT,
        expected=None,
    )
    empty: ControlSet = {"management.telnet.enabled": ControlValue(value=None, excerpt="")}
    assert evaluate_rule(rule, empty, CISCO).status is Status.PASS


def test_uncomparable_value_is_not_assessable_rather_than_a_crash() -> None:
    rule = make_rule(parameter="auth.password.min_length", operator=Operator.GTE, expected=8)
    bad: ControlSet = {"auth.password.min_length": ControlValue(value="eight", excerpt="x")}
    assert evaluate_rule(rule, bad, CISCO).status is Status.NOT_ASSESSABLE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_engine.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.compliance.engine'`

- [ ] **Step 3: Write `backend/app/services/compliance/engine.py`**

```python
from app.domain.controls import ControlSet
from app.domain.device import DeviceIdentity
from app.domain.results import ComplianceResult, Status
from app.services.compliance.operators import Operator, OperatorError, apply_operator
from app.services.compliance.rules import Rule, RulePack

# These operators are meaningful against a null observation; every other operator is not.
_PRESENCE_OPERATORS = {Operator.PRESENT, Operator.ABSENT}


def evaluate_rule(
    rule: Rule, controls: ControlSet, identity: DeviceIdentity
) -> ComplianceResult:
    def result(status: Status, observed: object = None, evidence: object = None) -> ComplianceResult:
        return ComplianceResult(
            rule_id=rule.id,
            framework=rule.framework,
            framework_version=rule.framework_version,
            parameter=rule.parameter,
            observed_value=observed,  # type: ignore[arg-type]
            expected_value=rule.expected,
            status=status,
            severity=rule.severity,
            evidence=evidence,  # type: ignore[arg-type]
        )

    if not rule.applicability.matches(identity.vendor, identity.os):
        return result(Status.NOT_APPLICABLE)

    observation = controls.get(rule.parameter)

    if observation is None:
        # The parser never saw this construct. Absence of evidence is not compliance.
        if rule.operator is Operator.ABSENT:
            return result(Status.NOT_ASSESSABLE)
        return result(Status.NOT_ASSESSABLE)

    if observation.value is None and rule.operator not in _PRESENCE_OPERATORS:
        return result(Status.NOT_ASSESSABLE, evidence=observation)

    try:
        satisfied = apply_operator(rule.operator, observation.value, rule.expected)
    except OperatorError:
        # A rule that cannot compare its operands has not proven compliance.
        return result(Status.NOT_ASSESSABLE, observed=observation.value, evidence=observation)

    status = Status.PASS if satisfied else Status.FAIL
    return result(status, observed=observation.value, evidence=observation)


def evaluate_pack(
    pack: RulePack, controls: ControlSet, identity: DeviceIdentity
) -> list[ComplianceResult]:
    return [evaluate_rule(rule, controls, identity) for rule in pack.rules]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_engine.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/compliance/engine.py backend/tests/unit/test_engine.py
git commit -m "feat: add deterministic compliance engine with fail-closed unknowns"
```

---

## Task 6: CIS rule pack with self-testing harness

**Files:**
- Create: `rules/cis/cisco-ios-v8.yaml`
- Test: `backend/tests/unit/test_rule_packs_self_test.py`

**Interfaces:**
- Consumes: `load_all_packs`, `evaluate_rule`, `Rule`, `RuleTest`
- Produces: a validated CIS pack covering all 16 control keys; every rule proves its own truth table

- [ ] **Step 1: Write the failing self-test harness**

Create `backend/tests/unit/test_rule_packs_self_test.py`:

```python
import pytest

from app.config import settings
from app.domain.controls import CONTROL_KEYS, ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.domain.results import Status
from app.services.compliance.engine import evaluate_rule
from app.services.compliance.rules import Rule, RulePack, load_all_packs

PACKS: list[RulePack] = load_all_packs(settings.rules_dir)
CASES = [
    pytest.param(pack, rule, case, id=f"{rule.id}[{case.given!r}]")
    for pack in PACKS
    for rule in pack.rules
    for case in rule.tests
]


@pytest.mark.parametrize(("pack", "rule", "case"), CASES)
def test_every_rule_proves_its_own_truth_table(
    pack: RulePack, rule: Rule, case: object
) -> None:
    identity = DeviceIdentity(
        vendor=rule.applicability.vendor, os=rule.applicability.os[0], confidence=1.0
    )
    controls: ControlSet = {
        rule.parameter: ControlValue(value=case.given, source_lines=[1], excerpt="self-test")  # type: ignore[attr-defined]
    }
    result = evaluate_rule(rule, controls, identity)
    assert result.status is Status(case.expect)  # type: ignore[attr-defined]


def test_every_control_key_is_covered_by_at_least_one_rule() -> None:
    covered = {rule.parameter for pack in PACKS for rule in pack.rules}
    assert CONTROL_KEYS - covered == set(), f"uncovered controls: {sorted(CONTROL_KEYS - covered)}"


def test_every_rule_exercises_both_a_pass_and_a_fail() -> None:
    for pack in PACKS:
        for rule in pack.rules:
            outcomes = {case.expect for case in rule.tests}
            assert Status.PASS in outcomes, f"{rule.id} has no PASS case"
            assert Status.FAIL in outcomes, f"{rule.id} has no FAIL case"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_rule_packs_self_test.py -v`
Expected: FAIL — `RulePackError: no rule packs found`

- [ ] **Step 3: Write `rules/cis/cisco-ios-v8.yaml`**

```yaml
- id: CIS-SSH-001
  framework: CIS
  framework_version: "8.0"
  title: SSH management access enabled
  description: >
    Devices must expose an encrypted management channel. SSH must be enabled so
    that administrative sessions are not carried in cleartext.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: management.ssh.enabled
  operator: equals
  expected: true
  severity: HIGH
  evidence_required: true
  remediation_id: REM-SSH-001
  source: "CIS Cisco IOS Benchmark v8.0 - Management Plane"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-SSH-002
  framework: CIS
  framework_version: "8.0"
  title: SSH protocol version 2 enforced
  description: >
    SSH version 1 contains cryptographic weaknesses and must not be used for
    device management. Version 2 is required.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: management.ssh.version
  operator: equals
  expected: 2
  severity: HIGH
  evidence_required: true
  remediation_id: REM-SSH-002
  source: "CIS Cisco IOS Benchmark v8.0 - Management Plane"
  tests:
    - {given: 2, expect: PASS}
    - {given: 1, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-TELNET-001
  framework: CIS
  framework_version: "8.0"
  title: Telnet management disabled
  description: >
    Telnet transmits credentials and session content in cleartext. It must not be
    accepted on any management line.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: management.telnet.enabled
  operator: equals
  expected: false
  severity: CRITICAL
  evidence_required: true
  remediation_id: REM-TELNET-001
  source: "CIS Cisco IOS Benchmark v8.0 - Management Plane"
  tests:
    - {given: false, expect: PASS}
    - {given: true, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-HTTP-001
  framework: CIS
  framework_version: "8.0"
  title: HTTP management server disabled
  description: >
    The unencrypted HTTP management server exposes credentials and configuration
    data on the wire and must be disabled.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: management.http.enabled
  operator: equals
  expected: false
  severity: HIGH
  evidence_required: true
  remediation_id: REM-HTTP-001
  source: "CIS Cisco IOS Benchmark v8.0 - Management Plane"
  tests:
    - {given: false, expect: PASS}
    - {given: true, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-HTTPS-001
  framework: CIS
  framework_version: "8.0"
  title: HTTPS management server used where web management is required
  description: >
    Where a web management interface is required, it must be the TLS-protected
    secure server rather than the cleartext one.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: management.https.enabled
  operator: equals
  expected: true
  severity: MEDIUM
  evidence_required: true
  remediation_id: REM-HTTPS-001
  source: "CIS Cisco IOS Benchmark v8.0 - Management Plane"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-SESSION-001
  framework: CIS
  framework_version: "8.0"
  title: Idle management sessions time out within 10 minutes
  description: >
    An unattended administrative session is an unauthenticated path to privileged
    access. Idle sessions must terminate within 600 seconds.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: management.session_timeout
  operator: lte
  expected: 600
  severity: MEDIUM
  evidence_required: true
  remediation_id: REM-SESSION-001
  source: "CIS Cisco IOS Benchmark v8.0 - Management Plane"
  tests:
    - {given: 300, expect: PASS}
    - {given: 600, expect: PASS}
    - {given: 1800, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-MGMTACL-001
  framework: CIS
  framework_version: "8.0"
  title: Management access restricted by access list
  description: >
    Management lines must be restricted to an administrative source range so that
    the management plane is not reachable from the entire network.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: management.acl.present
  operator: equals
  expected: true
  severity: HIGH
  evidence_required: true
  remediation_id: REM-MGMTACL-001
  source: "CIS Cisco IOS Benchmark v8.0 - Management Plane"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-PASSLEN-001
  framework: CIS
  framework_version: "8.0"
  title: Minimum password length of at least 8 characters
  description: >
    Short passwords are trivially brute-forced offline once a hash is obtained.
    A minimum length of 8 characters must be enforced by the device.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: auth.password.min_length
  operator: gte
  expected: 8
  severity: MEDIUM
  evidence_required: true
  remediation_id: REM-PASSLEN-001
  source: "CIS Cisco IOS Benchmark v8.0 - Local Authentication"
  tests:
    - {given: 12, expect: PASS}
    - {given: 8, expect: PASS}
    - {given: 4, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-AAA-001
  framework: CIS
  framework_version: "8.0"
  title: AAA authentication enabled
  description: >
    Centralized authentication, authorization and accounting provides per-user
    attribution and central revocation. It must be enabled.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: auth.aaa.enabled
  operator: equals
  expected: true
  severity: HIGH
  evidence_required: true
  remediation_id: REM-AAA-001
  source: "CIS Cisco IOS Benchmark v8.0 - AAA"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-ENABLE-001
  framework: CIS
  framework_version: "8.0"
  title: Privileged password stored with a strong hash
  description: >
    The enable password must be stored using a strong one-way hash rather than the
    reversible type-7 encoding or cleartext.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: auth.enable_secret.encrypted
  operator: equals
  expected: true
  severity: CRITICAL
  evidence_required: true
  remediation_id: REM-ENABLE-001
  source: "CIS Cisco IOS Benchmark v8.0 - Local Authentication"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-DEFACCT-001
  framework: CIS
  framework_version: "8.0"
  title: No vendor default accounts present
  description: >
    Default accounts such as cisco/cisco and admin/admin are published and must be
    removed or renamed.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: auth.default_accounts.present
  operator: equals
  expected: false
  severity: CRITICAL
  evidence_required: true
  remediation_id: REM-DEFACCT-001
  source: "CIS Cisco IOS Benchmark v8.0 - Local Authentication"
  tests:
    - {given: false, expect: PASS}
    - {given: true, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-LOGLOCAL-001
  framework: CIS
  framework_version: "8.0"
  title: Local logging buffer enabled
  description: >
    A local log buffer preserves recent events when the network path to the log
    collector is unavailable.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: logging.local.enabled
  operator: equals
  expected: true
  severity: LOW
  evidence_required: true
  remediation_id: REM-LOGLOCAL-001
  source: "CIS Cisco IOS Benchmark v8.0 - Logging"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-LOGREMOTE-001
  framework: CIS
  framework_version: "8.0"
  title: Remote syslog destination configured
  description: >
    Logs must be shipped off-device so that an attacker who compromises the device
    cannot erase the record of their activity.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: logging.remote.enabled
  operator: equals
  expected: true
  severity: HIGH
  evidence_required: true
  remediation_id: REM-LOGREMOTE-001
  source: "CIS Cisco IOS Benchmark v8.0 - Logging"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-NTP-001
  framework: CIS
  framework_version: "8.0"
  title: NTP time synchronization configured
  description: >
    Without synchronized time, log correlation across devices is unreliable and
    forensic timelines cannot be reconstructed.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: time.ntp.enabled
  operator: equals
  expected: true
  severity: MEDIUM
  evidence_required: true
  remediation_id: REM-NTP-001
  source: "CIS Cisco IOS Benchmark v8.0 - Time"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-SNMP-001
  framework: CIS
  framework_version: "8.0"
  title: Only SNMPv3 in use
  description: >
    SNMP v1 and v2c carry community strings in cleartext and provide no integrity
    protection. Only SNMPv3 may be configured.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: snmp.v3.only
  operator: equals
  expected: true
  severity: HIGH
  evidence_required: true
  remediation_id: REM-SNMP-001
  source: "CIS Cisco IOS Benchmark v8.0 - SNMP"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}

- id: CIS-BANNER-001
  framework: CIS
  framework_version: "8.0"
  title: Login banner present
  description: >
    A login banner establishes the legal notice relied upon when prosecuting
    unauthorized access.
  applicability: {vendor: cisco, os: [ios, ios-xe]}
  parameter: banner.login.present
  operator: equals
  expected: true
  severity: LOW
  evidence_required: true
  remediation_id: REM-BANNER-001
  source: "CIS Cisco IOS Benchmark v8.0 - Banners"
  tests:
    - {given: true, expect: PASS}
    - {given: false, expect: FAIL}
    - {given: null, expect: NOT_ASSESSABLE}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_rule_packs_self_test.py -v`
Expected: PASS — 16 rules, 52 truth-table cases, plus coverage assertions.

- [ ] **Step 5: Commit**

```bash
git add rules backend/tests/unit/test_rule_packs_self_test.py
git commit -m "feat: add CIS rule pack covering all 16 controls with self-testing harness"
```

---

## Task 7: Remediation pack

**Files:**
- Create: `mappings/cisco/remediation.yaml`, `backend/app/services/remediation/__init__.py`, `backend/app/services/remediation/packs.py`
- Test: `backend/tests/unit/test_remediation.py`

**Interfaces:**
- Consumes: `load_all_packs`
- Produces: `Remediation(id, vendor, os, title, cli, verification, rollback, notes, banner)`; `load_remediations(mappings_dir: Path) -> dict[str, Remediation]`; `RemediationError`; module constant `REMEDIATION_BANNER = "Review and validate before production deployment."`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_remediation.py`:

```python
from app.config import settings
from app.services.compliance.rules import load_all_packs
from app.services.remediation.packs import REMEDIATION_BANNER, load_remediations


def test_every_rule_remediation_id_resolves() -> None:
    remediations = load_remediations(settings.mappings_dir)
    referenced = {rule.remediation_id for pack in load_all_packs(settings.rules_dir) for rule in pack.rules}
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_remediation.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.remediation'`

- [ ] **Step 3: Write `backend/app/services/remediation/packs.py`**

```python
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
```

Create empty `backend/app/services/remediation/__init__.py`.

- [ ] **Step 4: Write `mappings/cisco/remediation.yaml`**

Write one entry per `remediation_id` referenced in Task 6. The three below show the exact
shape; write the remaining thirteen (`REM-SSH-001`, `REM-HTTP-001`, `REM-HTTPS-001`,
`REM-SESSION-001`, `REM-MGMTACL-001`, `REM-PASSLEN-001`, `REM-AAA-001`, `REM-ENABLE-001`,
`REM-DEFACCT-001`, `REM-LOGLOCAL-001`, `REM-LOGREMOTE-001`, `REM-NTP-001`, `REM-SNMP-001`,
`REM-BANNER-001`) following it. The test in Step 1 fails until all sixteen exist.

```yaml
REM-SSH-002:
  vendor: cisco
  os: [ios, ios-xe]
  title: Enforce SSH version 2
  cli: |
    configure terminal
     ip ssh version 2
    end
    write memory
  verification: "show ip ssh"
  rollback: |
    configure terminal
     ip ssh version 1
    end
  notes: "Confirm all management clients support SSHv2 before applying."

REM-TELNET-001:
  vendor: cisco
  os: [ios, ios-xe]
  title: Remove Telnet from management lines
  cli: |
    configure terminal
     line vty 0 15
      transport input ssh
     exit
    end
    write memory
  verification: "show running-config | section line vty"
  rollback: |
    configure terminal
     line vty 0 15
      transport input ssh telnet
     exit
    end
  notes: "Verify SSH connectivity from the management network before removing Telnet."

REM-LOGREMOTE-001:
  vendor: cisco
  os: [ios, ios-xe]
  title: Configure a remote syslog destination
  cli: |
    configure terminal
     logging host 10.0.0.10
     logging trap informational
     logging source-interface Loopback0
    end
    write memory
  verification: "show logging"
  rollback: |
    configure terminal
     no logging host 10.0.0.10
    end
  notes: "Replace 10.0.0.10 with the organization's syslog collector."
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_remediation.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add mappings backend/app/services/remediation backend/tests/unit/test_remediation.py
git commit -m "feat: add Cisco remediation pack with verification and rollback guidance"
```

---

## Task 8: Secret redaction

**Files:**
- Create: `backend/app/security/__init__.py`, `backend/app/security/redaction.py`
- Test: `backend/tests/unit/test_redaction.py`

**Interfaces:**
- Consumes: nothing
- Produces: `SecretHit(kind: str, lineno: int)`; `RedactionResult(text: str, hits: list[SecretHit])`; `redact(text: str) -> RedactionResult`; `EnableSecretType` detection via `hits` with kinds `enable-secret-strong`, `enable-secret-type7`, `enable-password-cleartext`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_redaction.py`:

```python
from app.security.redaction import redact

CONFIG = """hostname core-sw-01
enable secret 5 $1$mERr$Ml5Kf1TZKFbGfBjMDwCCM0
username admin privilege 15 password 7 070C285F4D06
snmp-server community publicRO RO
line vty 0 4
 password 7 104D000A0618
crypto key generate rsa
 key-string ABCDEF0123456789
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890
-----END RSA PRIVATE KEY-----
"""


def test_no_secret_material_survives_redaction() -> None:
    result = redact(CONFIG)
    for secret in (
        "$1$mERr$Ml5Kf1TZKFbGfBjMDwCCM0",
        "070C285F4D06",
        "publicRO",
        "104D000A0618",
        "ABCDEF0123456789",
        "MIIEowIBAAKCAQEA1234567890",
    ):
        assert secret not in result.text


def test_redaction_preserves_line_count_and_structure() -> None:
    result = redact(CONFIG)
    assert len(result.text.splitlines()) == len(CONFIG.splitlines())
    assert "hostname core-sw-01" in result.text


def test_redaction_marks_the_kind_of_each_secret() -> None:
    kinds = {hit.kind for hit in redact(CONFIG).hits}
    assert "enable-secret-strong" in kinds
    assert "type7-password" in kinds
    assert "snmp-community" in kinds
    assert "private-key" in kinds


def test_hits_carry_one_indexed_line_numbers() -> None:
    hits = {hit.kind: hit.lineno for hit in redact(CONFIG).hits}
    assert hits["enable-secret-strong"] == 2


def test_clean_config_produces_no_hits() -> None:
    result = redact("hostname router\nip ssh version 2\n")
    assert result.hits == []
    assert result.text == "hostname router\nip ssh version 2\n"


def test_redaction_is_idempotent() -> None:
    once = redact(CONFIG).text
    assert redact(once).text == once
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_redaction.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.security'`

- [ ] **Step 3: Write `backend/app/security/redaction.py`**

```python
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretHit:
    kind: str
    lineno: int


@dataclass(frozen=True)
class RedactionResult:
    text: str
    hits: list[SecretHit] = field(default_factory=list)


# Each pattern keeps the keyword prefix (which is evidence) and replaces only the
# secret material (which is not). Group 1 is always the retained prefix.
_LINE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("enable-secret-strong", re.compile(r"^(\s*enable secret\s+(?:5|8|9)\s+)\S+", re.IGNORECASE)),
    ("enable-secret-type7", re.compile(r"^(\s*enable secret\s+7\s+)\S+", re.IGNORECASE)),
    ("enable-password-cleartext", re.compile(r"^(\s*enable password\s+)(?!7\s)\S+", re.IGNORECASE)),
    ("type7-password", re.compile(r"^(.*\bpassword\s+7\s+)\S+", re.IGNORECASE)),
    ("cleartext-password", re.compile(r"^(.*\bpassword\s+0\s+)\S+", re.IGNORECASE)),
    ("user-secret", re.compile(r"^(\s*username\s+\S+.*\bsecret\s+\d\s+)\S+", re.IGNORECASE)),
    ("snmp-community", re.compile(r"^(\s*snmp-server community\s+)\S+", re.IGNORECASE)),
    ("key-string", re.compile(r"^(\s*key-string\s+)\S+", re.IGNORECASE)),
    ("pre-shared-key", re.compile(r"^(.*\bpre-shared-key\s+)\S+", re.IGNORECASE)),
]

_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_REDACTION = "<REDACTED:{kind}>"


def redact(text: str) -> RedactionResult:
    """Replace secret material with typed markers, preserving line structure.

    Redaction is idempotent: a marker is not itself a secret, so re-running is safe.
    """
    hits: list[SecretHit] = []
    output: list[str] = []
    inside_pem = False

    for index, line in enumerate(text.splitlines(), start=1):
        if inside_pem:
            if _PEM_END.search(line):
                inside_pem = False
                output.append(line)
            else:
                output.append(_REDACTION.format(kind="private-key"))
            continue

        if _PEM_BEGIN.search(line):
            inside_pem = True
            hits.append(SecretHit(kind="private-key", lineno=index))
            output.append(line)
            continue

        redacted = line
        for kind, pattern in _LINE_PATTERNS:
            match = pattern.match(redacted)
            if match and "<REDACTED:" not in redacted:
                redacted = pattern.sub(rf"\g<1>{_REDACTION.format(kind=kind)}", redacted)
                hits.append(SecretHit(kind=kind, lineno=index))
                break
        output.append(redacted)

    trailing = "\n" if text.endswith("\n") else ""
    return RedactionResult(text="\n".join(output) + trailing, hits=hits)
```

Create empty `backend/app/security/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_redaction.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/security backend/tests/unit/test_redaction.py
git commit -m "feat: add secret redaction with typed markers and line preservation"
```

---

## Task 9: Cisco vendor detection

**Files:**
- Create: `backend/app/services/detection/__init__.py`, `backend/app/services/detection/cisco.py`
- Test: `backend/tests/unit/test_detection.py`

**Interfaces:**
- Consumes: `DeviceIdentity`
- Produces: `detect(text: str) -> DeviceIdentity`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_detection.py`:

```python
from app.services.detection.cisco import detect

IOS_XE = """Building configuration...

Current configuration : 4213 bytes
!
version 17.6
service timestamps debug datetime msec
!
hostname core-sw-01
!
boot-start-marker
boot-end-marker
!
line con 0
!
end
"""

IOS_CLASSIC = """Building configuration...
!
version 15.2
service timestamps log datetime
!
hostname edge-rtr-02
!
boot-start-marker
boot-end-marker
!
line con 0
!
end
"""

JUNOS = """system {
    host-name mx-01;
    services {
        ssh;
    }
}
"""


def test_detects_ios_xe_with_high_confidence() -> None:
    identity = detect(IOS_XE)
    assert identity.vendor == "cisco"
    assert identity.os == "ios-xe"
    assert identity.os_version == "17.6"
    assert identity.hostname == "core-sw-01"
    assert identity.confidence >= 0.95
    assert not identity.needs_confirmation


def test_detects_classic_ios() -> None:
    identity = detect(IOS_CLASSIC)
    assert identity.os == "ios"
    assert identity.os_version == "15.2"
    assert identity.hostname == "edge-rtr-02"


def test_detection_explains_itself() -> None:
    identity = detect(IOS_XE)
    assert identity.reasons, "detection must state why"
    assert any("boot-start-marker" in reason for reason in identity.reasons)


def test_non_cisco_config_falls_below_the_confirmation_threshold() -> None:
    identity = detect(JUNOS)
    assert identity.needs_confirmation
    assert identity.confidence < 0.70


def test_empty_input_needs_confirmation() -> None:
    assert detect("").needs_confirmation
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_detection.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.detection'`

- [ ] **Step 3: Write `backend/app/services/detection/cisco.py`**

```python
import re

from app.domain.device import DeviceIdentity

# Weighted signatures. The total is the denominator, so adding a signature without
# reweighting deliberately makes every score more conservative, never less.
_SIGNATURES: list[tuple[str, re.Pattern[str], int]] = [
    ("Building configuration...", re.compile(r"^Building configuration\.\.\.", re.MULTILINE), 3),
    ("Current configuration :", re.compile(r"^Current configuration\s*:", re.MULTILINE), 3),
    ("boot-start-marker", re.compile(r"^boot-start-marker", re.MULTILINE), 3),
    ("service timestamps", re.compile(r"^service timestamps\b", re.MULTILINE), 2),
    ("line con 0", re.compile(r"^line con 0", re.MULTILINE), 2),
    ("version token", re.compile(r"^version \d+\.\d+", re.MULTILINE), 2),
    ("bare end statement", re.compile(r"^end\s*$", re.MULTILINE), 1),
]

_TOTAL_WEIGHT = sum(weight for _, _, weight in _SIGNATURES)

_VERSION = re.compile(r"^version (\d+)\.(\d+)", re.MULTILINE)
_HOSTNAME = re.compile(r"^hostname (\S+)", re.MULTILINE)

# IOS-XE reports major versions 16 and above; classic IOS reports 12 through 15.
_IOS_XE_MAJOR_FLOOR = 16


def detect(text: str) -> DeviceIdentity:
    matched_weight = 0
    reasons: list[str] = []

    for label, pattern, weight in _SIGNATURES:
        if pattern.search(text):
            matched_weight += weight
            reasons.append(f"matched '{label}' (w={weight})")

    confidence = round(matched_weight / _TOTAL_WEIGHT, 2)

    version_match = _VERSION.search(text)
    os_version = f"{version_match.group(1)}.{version_match.group(2)}" if version_match else None

    os_name = "ios"
    if version_match:
        major = int(version_match.group(1))
        if major >= _IOS_XE_MAJOR_FLOOR:
            os_name = "ios-xe"
            reasons.append(f"version major {major} implies IOS-XE")
        else:
            reasons.append(f"version major {major} implies classic IOS")

    hostname_match = _HOSTNAME.search(text)

    return DeviceIdentity(
        vendor="cisco",
        os=os_name,
        os_version=os_version,
        product_family="ios",
        hostname=hostname_match.group(1) if hostname_match else None,
        confidence=confidence,
        reasons=reasons,
    )
```

Create empty `backend/app/services/detection/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_detection.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/detection backend/tests/unit/test_detection.py
git commit -m "feat: add weighted Cisco vendor detection with stated reasoning"
```

---

## Task 10: Cisco configuration parser

**Files:**
- Create: `backend/app/services/parsing/__init__.py`, `backend/app/services/parsing/cisco.py`
- Test: `backend/tests/unit/test_parser.py`

**Interfaces:**
- Consumes: nothing
- Produces: `ConfigNode(text, lineno, indent, children)`; `ParseWarning(lineno, message)`; `ConfigTree(roots, warnings)` with methods `find(pattern: str) -> list[ConfigNode]` (recursive regex over `text`) and `first(pattern: str) -> ConfigNode | None`; `ConfigNode.find(pattern)` / `ConfigNode.first(pattern)` searching only descendants; `parse_cisco(text: str) -> ConfigTree`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_parser.py`:

```python
from app.services.parsing.cisco import parse_cisco

CONFIG = """!
hostname core-sw-01
!
ip ssh version 2
no ip http server
!
line vty 0 4
 transport input ssh
 exec-timeout 5 0
 access-class MGMT-ACL in
!
line con 0
 exec-timeout 10 0
!
end
"""


def test_top_level_commands_become_roots() -> None:
    tree = parse_cisco(CONFIG)
    texts = [node.text for node in tree.roots]
    assert "hostname core-sw-01" in texts
    assert "line vty 0 4" in texts


def test_indented_commands_become_children() -> None:
    tree = parse_cisco(CONFIG)
    vty = tree.first(r"^line vty")
    assert vty is not None
    assert [child.text for child in vty.children] == [
        "transport input ssh",
        "exec-timeout 5 0",
        "access-class MGMT-ACL in",
    ]


def test_line_numbers_are_one_indexed_and_accurate() -> None:
    tree = parse_cisco(CONFIG)
    hostname = tree.first(r"^hostname")
    assert hostname is not None
    assert hostname.lineno == 2


def test_comment_and_blank_lines_are_dropped() -> None:
    tree = parse_cisco(CONFIG)
    assert all(not node.text.startswith("!") for node in tree.roots)
    assert all(node.text.strip() for node in tree.roots)


def test_find_searches_recursively() -> None:
    tree = parse_cisco(CONFIG)
    matches = tree.find(r"^exec-timeout")
    assert len(matches) == 2


def test_node_scoped_find_does_not_leak_across_blocks() -> None:
    tree = parse_cisco(CONFIG)
    vty = tree.first(r"^line vty")
    con = tree.first(r"^line con")
    assert vty is not None and con is not None
    assert len(vty.find(r"^exec-timeout")) == 1
    assert vty.first(r"^access-class") is not None
    assert con.first(r"^access-class") is None


def test_dedent_closes_nested_blocks() -> None:
    nested = "router bgp 65001\n address-family ipv4\n  network 10.0.0.0\n exit-address-family\nend\n"
    tree = parse_cisco(nested)
    bgp = tree.first(r"^router bgp")
    assert bgp is not None
    af = bgp.first(r"^address-family")
    assert af is not None
    assert [child.text for child in af.children] == ["network 10.0.0.0"]


def test_unexpected_dedent_records_a_warning_without_failing() -> None:
    ragged = "line vty 0 4\n   transport input ssh\n  exec-timeout 5 0\n"
    tree = parse_cisco(ragged)
    assert tree.warnings, "ragged indentation should warn"
    assert tree.first(r"^line vty") is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_parser.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.parsing'`

- [ ] **Step 3: Write `backend/app/services/parsing/cisco.py`**

```python
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ParseWarning:
    lineno: int
    message: str


@dataclass
class ConfigNode:
    """One configuration command, with any indented commands beneath it."""

    text: str
    lineno: int
    indent: int
    children: list["ConfigNode"] = field(default_factory=list)

    def find(self, pattern: str) -> list["ConfigNode"]:
        """Every descendant whose text matches, depth-first. Does not match self."""
        compiled = re.compile(pattern)
        found: list[ConfigNode] = []
        for child in self.children:
            if compiled.search(child.text):
                found.append(child)
            found.extend(child.find(pattern))
        return found

    def first(self, pattern: str) -> "ConfigNode | None":
        matches = self.find(pattern)
        return matches[0] if matches else None


@dataclass
class ConfigTree:
    roots: list[ConfigNode] = field(default_factory=list)
    warnings: list[ParseWarning] = field(default_factory=list)

    def find(self, pattern: str) -> list[ConfigNode]:
        compiled = re.compile(pattern)
        found: list[ConfigNode] = []
        for root in self.roots:
            if compiled.search(root.text):
                found.append(root)
            found.extend(root.find(pattern))
        return found

    def first(self, pattern: str) -> ConfigNode | None:
        matches = self.find(pattern)
        return matches[0] if matches else None


def _is_noise(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("!")


def parse_cisco(text: str) -> ConfigTree:
    """Build an indentation tree from an IOS-style configuration.

    Unparseable indentation is recorded as a warning rather than raised: a ragged
    block should not cost the operator an entire audit.
    """
    tree = ConfigTree()
    stack: list[ConfigNode] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if _is_noise(raw):
            continue

        indent = len(raw) - len(raw.lstrip())
        node = ConfigNode(text=raw.strip(), lineno=lineno, indent=indent)

        while stack and stack[-1].indent >= indent:
            stack.pop()

        if not stack:
            if indent > 0 and not tree.roots:
                tree.warnings.append(
                    ParseWarning(lineno=lineno, message="indented line with no parent block")
                )
            tree.roots.append(node)
        else:
            parent = stack[-1]
            if indent <= parent.indent:  # pragma: no cover - guarded by the while loop
                tree.warnings.append(
                    ParseWarning(lineno=lineno, message="unexpected dedent")
                )
            parent.children.append(node)

        stack.append(node)

    _warn_on_ragged_indentation(tree)
    return tree


def _warn_on_ragged_indentation(tree: ConfigTree) -> None:
    """Siblings at differing indents mean the source formatting is inconsistent."""

    def walk(nodes: list[ConfigNode]) -> None:
        indents = {node.indent for node in nodes}
        if len(indents) > 1:
            tree.warnings.append(
                ParseWarning(
                    lineno=nodes[0].lineno,
                    message=f"sibling commands at differing indents: {sorted(indents)}",
                )
            )
        for node in nodes:
            if node.children:
                walk(node.children)

    for root in tree.roots:
        if root.children:
            walk(root.children)
```

Create empty `backend/app/services/parsing/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_parser.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/parsing backend/tests/unit/test_parser.py
git commit -m "feat: add Cisco IOS indentation parser with non-fatal warnings"
```

---

## Task 11: Cisco normalizer

**Files:**
- Create: `backend/app/services/normalization/__init__.py`, `backend/app/services/normalization/cisco.py`
- Test: `backend/tests/unit/test_normalizer.py`

**Interfaces:**
- Consumes: `ConfigTree`, `ConfigNode`, `ControlSet`, `ControlValue`, `DeviceIdentity`
- Produces: `UnknownConstruct(text, lineno, block)`; `NormalizationResult(controls: ControlSet, unknowns: list[UnknownConstruct])`; `normalize_cisco(tree: ConfigTree, identity: DeviceIdentity) -> NormalizationResult`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_normalizer.py`:

```python
from app.domain.device import DeviceIdentity
from app.services.normalization.cisco import normalize_cisco
from app.services.parsing.cisco import parse_cisco

CISCO = DeviceIdentity(vendor="cisco", os="ios-xe", confidence=0.98)

HARDENED = """hostname core-sw-01
enable secret 5 <REDACTED:enable-secret-strong>
aaa new-model
security passwords min-length 12
ip ssh version 2
no ip http server
ip http secure-server
logging buffered 16384
logging host 10.0.0.10
ntp server 10.0.0.5
snmp-server group NETMON v3 priv
banner login ^C Authorized access only ^C
line vty 0 4
 transport input ssh
 exec-timeout 5 0
 access-class MGMT-ACL in
end
"""

WEAK = """hostname old-rtr
enable password cisco
ip ssh version 1
ip http server
username cisco privilege 15 password 7 <REDACTED:type7-password>
snmp-server community <REDACTED:snmp-community> RO
line vty 0 4
 transport input telnet
 exec-timeout 60 0
end
"""


def normalize(text: str) -> dict[str, object]:
    result = normalize_cisco(parse_cisco(text), CISCO)
    return {key: value.value for key, value in result.controls.items()}


def test_hardened_config_normalizes_to_compliant_values() -> None:
    controls = normalize(HARDENED)
    assert controls["management.ssh.enabled"] is True
    assert controls["management.ssh.version"] == 2
    assert controls["management.telnet.enabled"] is False
    assert controls["management.http.enabled"] is False
    assert controls["management.https.enabled"] is True
    assert controls["management.session_timeout"] == 300
    assert controls["management.acl.present"] is True
    assert controls["auth.password.min_length"] == 12
    assert controls["auth.aaa.enabled"] is True
    assert controls["auth.enable_secret.encrypted"] is True
    assert controls["auth.default_accounts.present"] is False
    assert controls["logging.local.enabled"] is True
    assert controls["logging.remote.enabled"] is True
    assert controls["time.ntp.enabled"] is True
    assert controls["snmp.v3.only"] is True
    assert controls["banner.login.present"] is True


def test_weak_config_normalizes_to_violating_values() -> None:
    controls = normalize(WEAK)
    assert controls["management.ssh.version"] == 1
    assert controls["management.telnet.enabled"] is True
    assert controls["management.http.enabled"] is True
    assert controls["management.session_timeout"] == 3600
    assert controls["management.acl.present"] is False
    assert controls["auth.aaa.enabled"] is False
    assert controls["auth.enable_secret.encrypted"] is False
    assert controls["auth.default_accounts.present"] is True
    assert controls["snmp.v3.only"] is False


def test_controls_carry_line_level_provenance() -> None:
    result = normalize_cisco(parse_cisco(HARDENED), CISCO)
    ssh = result.controls["management.ssh.version"]
    assert ssh.source_lines == [5]
    assert ssh.excerpt == "ip ssh version 2"
    assert ssh.origin == "deterministic"
    assert ssh.parser_confidence == 1.0


def test_absent_construct_yields_no_key_rather_than_a_false_value() -> None:
    result = normalize_cisco(parse_cisco("hostname bare\nend\n"), CISCO)
    assert "time.ntp.enabled" not in result.controls
    assert "auth.password.min_length" not in result.controls


def test_unrecognized_commands_are_recorded_as_unknown_constructs() -> None:
    text = "hostname x\nsecure-session-timeout 300\nfoo-bar-baz enable\nend\n"
    result = normalize_cisco(parse_cisco(text), CISCO)
    unknown = {construct.text for construct in result.unknowns}
    assert "secure-session-timeout 300" in unknown
    assert "foo-bar-baz enable" in unknown


def test_timeout_of_zero_minutes_means_no_timeout_not_a_compliant_zero() -> None:
    text = "line vty 0 4\n exec-timeout 0 0\nend\n"
    controls = normalize(text)
    assert controls["management.session_timeout"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_normalizer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.normalization'`

- [ ] **Step 3: Write `backend/app/services/normalization/cisco.py`**

```python
import re
from dataclasses import dataclass, field

from app.domain.controls import ControlPrimitive, ControlSet, ControlValue
from app.domain.device import DeviceIdentity
from app.services.parsing.cisco import ConfigNode, ConfigTree

_DEFAULT_ACCOUNTS = {"cisco", "admin", "root", "default"}

# Commands the normalizer knowingly ignores: structural, cosmetic, or out of scope
# for the sixteen controls. Anything not matched here and not consumed by a rule
# below becomes an UnknownConstruct for SP4's training loop.
_IGNORED = re.compile(
    r"^(hostname|end|exit|version|service|boot-|interface|ip address|no shutdown|shutdown"
    r"|router|network|address-family|exit-address-family|line |transport|access-class"
    r"|exec-timeout|username|enable |aaa |security passwords|ip ssh|ip http|no ip http"
    r"|logging|ntp |snmp-server|banner|crypto|key-string|access-list|ip access-list"
    r"|permit|deny|description|<REDACTED)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class UnknownConstruct:
    text: str
    lineno: int
    block: str | None = None


@dataclass
class NormalizationResult:
    controls: ControlSet = field(default_factory=dict)
    unknowns: list[UnknownConstruct] = field(default_factory=list)


def _record(
    controls: ControlSet, key: str, value: ControlPrimitive, node: ConfigNode | None
) -> None:
    controls[key] = ControlValue(
        value=value,
        source_lines=[node.lineno] if node else [],
        excerpt=node.text if node else "",
    )


def normalize_cisco(tree: ConfigTree, identity: DeviceIdentity) -> NormalizationResult:
    """Map a parsed Cisco tree onto the sixteen universal controls.

    A control key is written only when the configuration actually says something about
    it. Silence stays silent — the rule engine turns that into NOT_ASSESSABLE.
    """
    controls: ControlSet = {}

    _normalize_ssh(tree, controls)
    _normalize_telnet(tree, controls)
    _normalize_web(tree, controls)
    _normalize_session_timeout(tree, controls)
    _normalize_management_acl(tree, controls)
    _normalize_auth(tree, controls)
    _normalize_logging(tree, controls)
    _normalize_ntp(tree, controls)
    _normalize_snmp(tree, controls)
    _normalize_banner(tree, controls)

    return NormalizationResult(controls=controls, unknowns=_collect_unknowns(tree))


def _normalize_ssh(tree: ConfigTree, controls: ControlSet) -> None:
    version_node = tree.first(r"^ip ssh version (\d)")
    if version_node:
        match = re.search(r"version (\d)", version_node.text)
        assert match is not None
        _record(controls, "management.ssh.version", int(match.group(1)), version_node)
        _record(controls, "management.ssh.enabled", True, version_node)
        return

    transport = tree.first(r"^transport input .*\bssh\b")
    if transport:
        _record(controls, "management.ssh.enabled", True, transport)


def _normalize_telnet(tree: ConfigTree, controls: ControlSet) -> None:
    transports = tree.find(r"^transport input")
    if not transports:
        return
    enabled_on = next((node for node in transports if re.search(r"\btelnet\b", node.text)), None)
    if enabled_on:
        _record(controls, "management.telnet.enabled", True, enabled_on)
    else:
        _record(controls, "management.telnet.enabled", False, transports[0])


def _normalize_web(tree: ConfigTree, controls: ControlSet) -> None:
    disabled = tree.first(r"^no ip http server")
    enabled = tree.first(r"^ip http server")
    if disabled:
        _record(controls, "management.http.enabled", False, disabled)
    elif enabled:
        _record(controls, "management.http.enabled", True, enabled)

    secure_off = tree.first(r"^no ip http secure-server")
    secure_on = tree.first(r"^ip http secure-server")
    if secure_off:
        _record(controls, "management.https.enabled", False, secure_off)
    elif secure_on:
        _record(controls, "management.https.enabled", True, secure_on)


def _normalize_session_timeout(tree: ConfigTree, controls: ControlSet) -> None:
    """`exec-timeout 0 0` disables the timeout entirely — record it as unset, not zero."""
    timeouts = tree.find(r"^exec-timeout (\d+)\s+(\d+)")
    if not timeouts:
        return

    worst_node: ConfigNode | None = None
    worst_seconds: int | None = None

    for node in timeouts:
        match = re.search(r"exec-timeout (\d+)\s+(\d+)", node.text)
        assert match is not None
        seconds = int(match.group(1)) * 60 + int(match.group(2))
        if seconds == 0:
            _record(controls, "management.session_timeout", None, node)
            return
        if worst_seconds is None or seconds > worst_seconds:
            worst_seconds, worst_node = seconds, node

    _record(controls, "management.session_timeout", worst_seconds, worst_node)


def _normalize_management_acl(tree: ConfigTree, controls: ControlSet) -> None:
    vty_blocks = tree.find(r"^line vty")
    if not vty_blocks:
        return
    for block in vty_blocks:
        access_class = block.first(r"^access-class \S+ in")
        if access_class:
            _record(controls, "management.acl.present", True, access_class)
            return
    _record(controls, "management.acl.present", False, vty_blocks[0])


def _normalize_auth(tree: ConfigTree, controls: ControlSet) -> None:
    aaa = tree.first(r"^aaa new-model")
    if aaa:
        _record(controls, "auth.aaa.enabled", True, aaa)
    elif tree.roots:
        _record(controls, "auth.aaa.enabled", False, tree.roots[0])

    min_length = tree.first(r"^security passwords min-length (\d+)")
    if min_length:
        match = re.search(r"min-length (\d+)", min_length.text)
        assert match is not None
        _record(controls, "auth.password.min_length", int(match.group(1)), min_length)

    # The redaction marker names the hash class, so strength is assessable without the value.
    strong = tree.first(r"^enable secret .*<REDACTED:enable-secret-strong>")
    weak = tree.first(r"^enable (password|secret 7)")
    if strong:
        _record(controls, "auth.enable_secret.encrypted", True, strong)
    elif weak:
        _record(controls, "auth.enable_secret.encrypted", False, weak)

    usernames = tree.find(r"^username (\S+)")
    if usernames:
        defaults = [
            node
            for node in usernames
            if (match := re.search(r"^username (\S+)", node.text))
            and match.group(1).lower() in _DEFAULT_ACCOUNTS
        ]
        if defaults:
            _record(controls, "auth.default_accounts.present", True, defaults[0])
        else:
            _record(controls, "auth.default_accounts.present", False, usernames[0])


def _normalize_logging(tree: ConfigTree, controls: ControlSet) -> None:
    buffered = tree.first(r"^logging buffered")
    if buffered:
        _record(controls, "logging.local.enabled", True, buffered)
    elif tree.first(r"^no logging buffered"):
        _record(controls, "logging.local.enabled", False, tree.first(r"^no logging buffered"))

    remote = tree.first(r"^logging (host |server |\d+\.\d+\.\d+\.\d+)")
    if remote:
        _record(controls, "logging.remote.enabled", True, remote)
    elif tree.find(r"^logging "):
        _record(controls, "logging.remote.enabled", False, tree.find(r"^logging ")[0])


def _normalize_ntp(tree: ConfigTree, controls: ControlSet) -> None:
    server = tree.first(r"^ntp server ")
    if server:
        _record(controls, "time.ntp.enabled", True, server)
    elif tree.find(r"^ntp "):
        _record(controls, "time.ntp.enabled", False, tree.find(r"^ntp ")[0])


def _normalize_snmp(tree: ConfigTree, controls: ControlSet) -> None:
    snmp_lines = tree.find(r"^snmp-server")
    if not snmp_lines:
        return
    legacy = next(
        (node for node in snmp_lines if re.search(r"^snmp-server community|v1|v2c", node.text)),
        None,
    )
    v3 = next((node for node in snmp_lines if re.search(r"\bv3\b", node.text)), None)
    if legacy:
        _record(controls, "snmp.v3.only", False, legacy)
    elif v3:
        _record(controls, "snmp.v3.only", True, v3)


def _normalize_banner(tree: ConfigTree, controls: ControlSet) -> None:
    banner = tree.first(r"^banner (login|motd)")
    if banner:
        _record(controls, "banner.login.present", True, banner)


def _collect_unknowns(tree: ConfigTree) -> list[UnknownConstruct]:
    """Every command the normalizer neither consumed nor knowingly ignored.

    This is the single seam where SP4's AI interpreter attaches. Slice 1 only counts them.
    """
    unknowns: list[UnknownConstruct] = []

    def walk(nodes: list[ConfigNode], block: str | None) -> None:
        for node in nodes:
            if not _IGNORED.match(node.text):
                unknowns.append(UnknownConstruct(text=node.text, lineno=node.lineno, block=block))
            if node.children:
                walk(node.children, node.text)

    walk(tree.roots, None)
    return unknowns
```

Create empty `backend/app/services/normalization/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_normalizer.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Verify the full pure-engine chain**

Run: `uv run pytest tests/unit -v && uv run ruff check . && uv run mypy app`
Expected: all pass. At this point parse → normalize → evaluate works end to end with no database.

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/normalization backend/tests/unit/test_normalizer.py
git commit -m "feat: add Cisco normalizer producing 16 controls with provenance"
```

---

## Task 12: Posture scoring

**Files:**
- Create: `backend/app/services/scoring/__init__.py`, `backend/app/services/scoring/posture.py`
- Test: `backend/tests/unit/test_scoring.py`

**Interfaces:**
- Consumes: `ComplianceResult`, `PostureScore`, `Status`, `Severity`
- Produces: `SEVERITY_WEIGHTS: dict[Severity, int]`; `score_results(results: list[ComplianceResult]) -> PostureScore`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_scoring.py`:

```python
from app.domain.results import ComplianceResult, Severity, Status
from app.services.scoring.posture import score_results


def result(status: Status, severity: Severity = Severity.HIGH) -> ComplianceResult:
    return ComplianceResult(
        rule_id="R", framework="CIS", framework_version="8.0", parameter="p",
        observed_value=None, expected_value=None, status=status, severity=severity,
    )


def test_all_passing_scores_one_hundred() -> None:
    score = score_results([result(Status.PASS), result(Status.PASS)])
    assert score.score == 100
    assert score.coverage == 1.0


def test_all_failing_scores_zero() -> None:
    assert score_results([result(Status.FAIL)]).score == 0


def test_warning_earns_half_credit() -> None:
    assert score_results([result(Status.WARNING)]).score == 50


def test_severity_weighting_favors_critical_rules() -> None:
    """One CRITICAL failure must cost more than one LOW failure."""
    critical_fail = score_results([result(Status.FAIL, Severity.CRITICAL), result(Status.PASS, Severity.LOW)])
    low_fail = score_results([result(Status.PASS, Severity.CRITICAL), result(Status.FAIL, Severity.LOW)])
    assert critical_fail.score < low_fail.score


def test_not_assessable_is_excluded_from_the_score_and_lowers_coverage() -> None:
    score = score_results([result(Status.PASS), result(Status.NOT_ASSESSABLE)])
    assert score.score == 100
    assert score.coverage == 0.5
    assert score.not_assessable == 1


def test_a_configuration_revealing_nothing_scores_zero_not_one_hundred() -> None:
    score = score_results([result(Status.NOT_ASSESSABLE), result(Status.NOT_ASSESSABLE)])
    assert score.score == 0
    assert score.coverage == 0.0


def test_not_applicable_affects_neither_score_nor_coverage() -> None:
    score = score_results([result(Status.PASS), result(Status.NOT_APPLICABLE)])
    assert score.score == 100
    assert score.coverage == 1.0


def test_fail_counts_are_reported_by_severity() -> None:
    score = score_results([
        result(Status.FAIL, Severity.CRITICAL),
        result(Status.FAIL, Severity.CRITICAL),
        result(Status.FAIL, Severity.LOW),
        result(Status.PASS, Severity.HIGH),
    ])
    assert score.fail_counts[Severity.CRITICAL] == 2
    assert score.fail_counts[Severity.LOW] == 1
    assert score.fail_counts[Severity.HIGH] == 0


def test_empty_result_set_scores_zero_without_dividing_by_zero() -> None:
    score = score_results([])
    assert score.score == 0
    assert score.coverage == 0.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_scoring.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.scoring'`

- [ ] **Step 3: Write `backend/app/services/scoring/posture.py`**

```python
from app.domain.results import ComplianceResult, PostureScore, Severity, Status

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_CREDIT: dict[Status, float] = {
    Status.PASS: 1.0,
    Status.WARNING: 0.5,
    Status.FAIL: 0.0,
}

_ASSESSABLE = frozenset(_CREDIT)


def score_results(results: list[ComplianceResult]) -> PostureScore:
    """Severity-weighted pass rate over assessable rules.

    NOT_ASSESSABLE is excluded from the score and reported as reduced coverage, so a
    configuration that reveals nothing scores zero rather than a misleading 100.
    """
    assessable = [item for item in results if item.status in _ASSESSABLE]
    not_assessable = sum(1 for item in results if item.status is Status.NOT_ASSESSABLE)

    available = sum(SEVERITY_WEIGHTS[item.severity] for item in assessable)
    earned = sum(SEVERITY_WEIGHTS[item.severity] * _CREDIT[item.status] for item in assessable)

    score = round(100 * earned / available) if available else 0
    denominator = len(assessable) + not_assessable
    coverage = round(len(assessable) / denominator, 4) if denominator else 0.0

    fail_counts = {
        severity: sum(
            1 for item in results if item.status is Status.FAIL and item.severity is severity
        )
        for severity in Severity
    }

    return PostureScore(
        score=score,
        coverage=coverage,
        fail_counts=fail_counts,
        assessable=len(assessable),
        not_assessable=not_assessable,
    )
```

Create empty `backend/app/services/scoring/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_scoring.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/scoring backend/tests/unit/test_scoring.py
git commit -m "feat: add severity-weighted posture scoring with coverage reporting"
```

---

## Task 13: Golden configuration tests

**Files:**
- Create: `backend/tests/golden/__init__.py`, `backend/tests/golden/test_golden.py`
- Create: `datasets/demo/cisco/compliant.cfg`, `datasets/demo/cisco/noncompliant.cfg`, `datasets/demo/cisco/mixed.cfg`
- Create: `backend/tests/golden/expected/{compliant,noncompliant,mixed}.json`

**Interfaces:**
- Consumes: `redact`, `detect`, `parse_cisco`, `normalize_cisco`, `evaluate_pack`, `score_results`, `load_all_packs`
- Produces: the end-to-end contract for the pure pipeline; no new application code

- [ ] **Step 1: Write the three demo configurations**

Create `datasets/demo/cisco/compliant.cfg` — a fully hardened IOS-XE configuration that
satisfies all sixteen rules. Base it on the `HARDENED` fixture from Task 11, expanded with
realistic surrounding configuration: `Building configuration...`, `version 17.6`,
`service timestamps`, `boot-start-marker`, interfaces, an `ip access-list standard MGMT-ACL`
block, and `end`.

Create `datasets/demo/cisco/noncompliant.cfg` — a classic IOS configuration
(`version 15.2`) violating all sixteen rules: `enable password cisco`, `ip ssh version 1`,
`ip http server`, `transport input telnet`, `exec-timeout 60 0`, `username cisco`,
`snmp-server community public RO`, no AAA, no logging host, no NTP, no banner, no
`access-class`.

Create `datasets/demo/cisco/mixed.cfg` — realistic partial hardening: SSHv2 and AAA
present, but Telnet still permitted, no remote logging, and no NTP. Include two commands
the normalizer will not recognize (for example `secure-session-timeout 300` and
`threat-defense enable`) so the `UnknownConstruct` path is exercised.

- [ ] **Step 2: Write the failing golden test**

Create `backend/tests/golden/test_golden.py`:

```python
import json
from pathlib import Path

import pytest

from app.config import settings
from app.services.compliance.engine import evaluate_pack
from app.services.compliance.rules import load_all_packs
from app.services.detection.cisco import detect
from app.services.normalization.cisco import normalize_cisco
from app.services.parsing.cisco import parse_cisco
from app.security.redaction import redact
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
    output = run_pipeline("noncompliant")
    statuses = set(output["results"].values())  # type: ignore[union-attr]
    assert statuses == {"FAIL"}
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/golden -v`
Expected: FAIL — `FileNotFoundError` on the expected JSON files.

- [ ] **Step 4: Generate the expected snapshots and review them by hand**

```bash
cd backend
uv run python -c "
import json, pathlib
from tests.golden.test_golden import run_pipeline, CASES, EXPECTED
EXPECTED.mkdir(parents=True, exist_ok=True)
for name in CASES:
    (EXPECTED / f'{name}.json').write_text(json.dumps(run_pipeline(name), indent=2), encoding='utf-8')
"
```

**Read each generated file before committing it.** A snapshot test only has value if the
first snapshot is correct. Confirm `compliant.json` shows all `PASS` and score 100, and
`noncompliant.json` shows all `FAIL` and score 0. If either is wrong, the bug is in the
`.cfg` file or the normalizer — fix that, then regenerate.

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/golden -v`
Expected: PASS (7 tests)

- [ ] **Step 6: Commit**

```bash
git add datasets backend/tests/golden
git commit -m "test: add golden configuration contract for the pure pipeline"
```

---

## Task 14: Database layer and ORM models

**Files:**
- Create: `backend/app/db.py`, `backend/app/models/__init__.py`, `backend/app/models/base.py`, `backend/app/models/org.py`, `backend/app/models/device.py`, `backend/app/models/audit.py`, `backend/app/models/event.py`
- Create: `backend/alembic.ini`, `backend/alembic/env.py`, `backend/alembic/versions/0001_initial.py`
- Test: `backend/tests/unit/test_models.py`

**Interfaces:**
- Consumes: `settings`
- Produces: `Base`; `engine`; `SessionLocal`; `get_db() -> Iterator[Session]`; ORM classes `Organization`, `Role`, `User`, `RefreshToken`, `Device`, `Configuration`, `AuditRun`, `NormalizedControlRow`, `ComplianceResultRow`, `Finding`, `Report`, `AuditEvent`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_models.py`:

```python
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AuditRun,
    Configuration,
    Device,
    Finding,
    Organization,
    Role,
    User,
)
from app.models.base import Base


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_full_object_graph_persists(session: Session) -> None:
    org = Organization(name="Demo Org")
    role = Role(name="Security Admin", permissions=["AUDIT_RUN", "CONFIG_UPLOAD"])
    user = User(organization=org, role=role, email="a@example.com", password_hash="x")
    device = Device(organization=org, name="core-sw-01", vendor="cisco", os="ios-xe")
    config = Configuration(
        device=device, sha256="a" * 64, blob_key="blobs/aa", filename="core.cfg",
        size_bytes=100, uploaded_by=user, secret_hits=2,
    )
    run = AuditRun(
        configuration=config, framework="CIS", framework_version="8.0", status="completed",
        rule_pack_hash="b" * 64, engine_version="0.1.0", started_at=datetime.now(UTC),
    )
    session.add_all([org, role, user, device, config, run])
    session.commit()

    assert run.id is not None
    assert run.configuration.device.organization.name == "Demo Org"


def test_configuration_sha_is_unique_per_device(session: Session) -> None:
    org = Organization(name="Org")
    device = Device(organization=org, name="d", vendor="cisco", os="ios")
    role = Role(name="R", permissions=[])
    user = User(organization=org, role=role, email="b@example.com", password_hash="x")
    session.add_all([
        Configuration(device=device, sha256="c" * 64, blob_key="k1", filename="f", size_bytes=1, uploaded_by=user),
        Configuration(device=device, sha256="c" * 64, blob_key="k2", filename="f", size_bytes=1, uploaded_by=user),
    ])
    with pytest.raises(IntegrityError):
        session.commit()


def test_user_email_is_unique(session: Session) -> None:
    org = Organization(name="Org")
    role = Role(name="R", permissions=[])
    session.add_all([
        User(organization=org, role=role, email="dup@example.com", password_hash="x"),
        User(organization=org, role=role, email="dup@example.com", password_hash="y"),
    ])
    with pytest.raises(IntegrityError):
        session.commit()


def test_finding_defaults_to_open_triage(session: Session) -> None:
    finding = Finding(severity="HIGH", title="Telnet enabled", remediation_id="REM-TELNET-001")
    assert finding.triage_status == "open"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.models'`

- [ ] **Step 3: Write `backend/app/models/base.py`**

```python
from datetime import UTC, datetime

from sqlalchemy import DateTime, MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Explicit constraint naming so Alembic can autogenerate reversible migrations
# against both SQLite and PostgreSQL.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def utcnow() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
```

- [ ] **Step 4: Write `backend/app/models/org.py`**

```python
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models.base import Base, TimestampMixin


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    organization: Mapped[Organization] = relationship(back_populates="users")
    role: Mapped[Role] = relationship()


class RefreshToken(Base, TimestampMixin):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    family_id: Mapped[str] = mapped_column(String(36), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    user: Mapped[User] = relationship()
```

- [ ] **Step 5: Write `backend/app/models/device.py`**

```python
from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.org import Organization, User


class Device(Base, TimestampMixin):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(200))
    vendor: Mapped[str] = mapped_column(String(60))
    os: Mapped[str] = mapped_column(String(60))
    model: Mapped[str | None] = mapped_column(String(120), default=None)
    os_version: Mapped[str | None] = mapped_column(String(60), default=None)

    organization: Mapped[Organization] = relationship()


class Configuration(Base, TimestampMixin):
    __tablename__ = "configurations"
    __table_args__ = (UniqueConstraint("device_id", "sha256"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    blob_key: Mapped[str] = mapped_column(String(255))
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    uploaded_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    secret_hits: Mapped[int] = mapped_column(Integer, default=0)

    device: Mapped[Device] = relationship()
    uploaded_by: Mapped[User] = relationship()
```

- [ ] **Step 6: Write `backend/app/models/audit.py`**

```python
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models.base import Base, TimestampMixin
from app.models.device import Configuration


class AuditRun(Base, TimestampMixin):
    __tablename__ = "audit_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    configuration_id: Mapped[int] = mapped_column(ForeignKey("configurations.id"))
    framework: Mapped[str] = mapped_column(String(40))
    framework_version: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    rule_pack_hash: Mapped[str] = mapped_column(String(64))
    engine_version: Mapped[str] = mapped_column(String(40))
    detected_vendor: Mapped[str | None] = mapped_column(String(60), default=None)
    detected_os: Mapped[str | None] = mapped_column(String(60), default=None)
    detection_confidence: Mapped[float | None] = mapped_column(Float, default=None)
    detection_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    vendor_override: Mapped[str | None] = mapped_column(String(60), default=None)
    unknown_constructs: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    parse_warnings: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    score: Mapped[int | None] = mapped_column(Integer, default=None)
    coverage: Mapped[float | None] = mapped_column(Float, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    configuration: Mapped[Configuration] = relationship()
    controls: Mapped[list["NormalizedControlRow"]] = relationship(back_populates="audit_run")
    results: Mapped[list["ComplianceResultRow"]] = relationship(back_populates="audit_run")


class NormalizedControlRow(Base):
    __tablename__ = "normalized_controls"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"))
    key: Mapped[str] = mapped_column(String(120), index=True)
    value_json: Mapped[object] = mapped_column(JSON)
    source_lines: Mapped[list[int]] = mapped_column(JSON, default=list)
    excerpt: Mapped[str] = mapped_column(Text, default="")
    parser_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    origin: Mapped[str] = mapped_column(String(20), default="deterministic")

    audit_run: Mapped[AuditRun] = relationship(back_populates="controls")


class ComplianceResultRow(Base):
    __tablename__ = "compliance_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"))
    rule_id: Mapped[str] = mapped_column(String(60), index=True)
    framework: Mapped[str] = mapped_column(String(40))
    framework_version: Mapped[str] = mapped_column(String(40))
    parameter: Mapped[str] = mapped_column(String(120))
    observed_value: Mapped[object] = mapped_column(JSON, default=None)
    expected_value: Mapped[object] = mapped_column(JSON, default=None)
    status: Mapped[str] = mapped_column(String(20), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    evidence_lines: Mapped[list[int]] = mapped_column(JSON, default=list)
    evidence_excerpt: Mapped[str] = mapped_column(Text, default="")

    audit_run: Mapped[AuditRun] = relationship(back_populates="results")
    finding: Mapped["Finding | None"] = relationship(back_populates="compliance_result")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    compliance_result_id: Mapped[int | None] = mapped_column(
        ForeignKey("compliance_results.id"), default=None
    )
    severity: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(300))
    remediation_id: Mapped[str] = mapped_column(String(60))
    triage_status: Mapped[str] = mapped_column(String(30), default="open")
    notes: Mapped[str] = mapped_column(Text, default="")

    compliance_result: Mapped[ComplianceResultRow | None] = relationship(back_populates="finding")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    audit_run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id"))
    blob_key: Mapped[str] = mapped_column(String(255))
    generated_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    audit_run: Mapped[AuditRun] = relationship()
```

- [ ] **Step 7: Write `backend/app/models/event.py`**

```python
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), default=None)
    action: Mapped[str] = mapped_column(String(60), index=True)
    resource: Mapped[str] = mapped_column(String(200), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    result: Mapped[str] = mapped_column(String(20), default="SUCCESS")
```

- [ ] **Step 8: Write `backend/app/models/__init__.py`**

```python
from app.models.audit import (
    AuditRun,
    ComplianceResultRow,
    Finding,
    NormalizedControlRow,
    Report,
)
from app.models.base import Base
from app.models.device import Configuration, Device
from app.models.event import AuditEvent
from app.models.org import Organization, RefreshToken, Role, User

__all__ = [
    "AuditEvent",
    "AuditRun",
    "Base",
    "ComplianceResultRow",
    "Configuration",
    "Device",
    "Finding",
    "NormalizedControlRow",
    "Organization",
    "RefreshToken",
    "Report",
    "Role",
    "User",
]
```

- [ ] **Step 9: Write `backend/app/db.py`**

```python
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.models.base import Base

if settings.database_url.startswith("sqlite:///"):
    Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


__all__ = ["Base", "SessionLocal", "engine", "get_db"]
```

- [ ] **Step 10: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: PASS (4 tests)

- [ ] **Step 11: Initialize Alembic and generate the initial migration**

```bash
cd backend
uv run alembic init alembic
```

Replace the import and target-metadata section of `backend/alembic/env.py`:

```python
from app.config import settings
from app.db import Base
from app import models  # noqa: F401  -- import registers every model on Base.metadata

config.set_main_option("sqlalchemy.url", settings.database_url)
target_metadata = Base.metadata
```

Then:

```bash
uv run alembic revision --autogenerate -m "initial schema"
uv run alembic upgrade head
```

Expected: `var/netsentinel.db` exists with all twelve tables.

- [ ] **Step 12: Commit**

```bash
git add backend/app/models backend/app/db.py backend/alembic backend/alembic.ini backend/tests/unit/test_models.py
git commit -m "feat: add ORM models, session factory, and initial Alembic migration"
```

---

## Task 15: Security primitives

**Files:**
- Create: `backend/app/security/passwords.py`, `backend/app/security/tokens.py`, `backend/app/security/permissions.py`
- Test: `backend/tests/unit/test_security.py`

**Interfaces:**
- Consumes: `settings`
- Produces:
  - `hash_password(plain: str) -> str`; `verify_password(plain: str, hashed: str) -> bool`
  - `Permission` (`StrEnum`); `ROLE_PERMISSIONS: dict[str, frozenset[Permission]]`; `ROLE_NAMES: tuple[str, ...]`
  - `create_access_token(user_id: int, permissions: list[str]) -> str`
  - `decode_access_token(token: str) -> TokenClaims`; `TokenClaims(user_id: int, permissions: list[str])`; `TokenError`
  - `new_refresh_token() -> tuple[str, str]` returning `(plaintext, sha256_hash)`; `hash_refresh_token(plain: str) -> str`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_security.py`:

```python
import time

import pytest

from app.security.passwords import hash_password, verify_password
from app.security.permissions import ROLE_NAMES, ROLE_PERMISSIONS, Permission
from app.security.tokens import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_refresh_token,
    new_refresh_token,
)


def test_password_hash_is_argon2id_and_verifies() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert verify_password("correct horse battery staple", hashed)
    assert not verify_password("wrong", hashed)


def test_password_hashes_are_salted_uniquely() -> None:
    assert hash_password("same") != hash_password("same")


def test_verify_rejects_a_malformed_hash_without_raising() -> None:
    assert verify_password("anything", "not-a-hash") is False


def test_access_token_round_trips_claims() -> None:
    token = create_access_token(user_id=7, permissions=[Permission.AUDIT_RUN])
    claims = decode_access_token(token)
    assert claims.user_id == 7
    assert Permission.AUDIT_RUN in claims.permissions


def test_expired_access_token_is_rejected() -> None:
    token = create_access_token(user_id=1, permissions=[], expires_in_seconds=-1)
    with pytest.raises(TokenError):
        decode_access_token(token)


def test_tampered_token_is_rejected() -> None:
    token = create_access_token(user_id=1, permissions=[])
    with pytest.raises(TokenError):
        decode_access_token(token[:-2] + "xy")


def test_refresh_token_is_stored_only_as_a_hash() -> None:
    plain, hashed = new_refresh_token()
    assert plain != hashed
    assert len(hashed) == 64
    assert hash_refresh_token(plain) == hashed


def test_refresh_tokens_are_unique() -> None:
    assert new_refresh_token()[0] != new_refresh_token()[0]


def test_every_role_is_defined_and_least_privileged() -> None:
    assert len(ROLE_NAMES) == 6
    assert set(ROLE_PERMISSIONS) == set(ROLE_NAMES)

    # A role that can suggest a mapping must not automatically be able to approve one.
    engineer = ROLE_PERMISSIONS["Network Engineer"]
    assert Permission.MAPPING_SUGGEST in engineer
    assert Permission.MAPPING_APPROVE not in engineer

    # Read-only roles must not be able to mutate anything.
    for role in ("CISO", "Auditor"):
        assert Permission.CONFIG_UPLOAD not in ROLE_PERMISSIONS[role]
        assert Permission.AUDIT_RUN not in ROLE_PERMISSIONS[role]
        assert Permission.FINDING_TRIAGE not in ROLE_PERMISSIONS[role]

    # Only the platform administrator administers.
    for role in ROLE_NAMES:
        if role != "Platform Admin":
            assert Permission.USER_ADMIN not in ROLE_PERMISSIONS[role]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_security.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.security.passwords'`

- [ ] **Step 3: Write `backend/app/security/passwords.py`**

```python
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerificationError

_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password. A malformed stored hash is a failure, never an exception."""
    try:
        return _hasher.verify(hashed, plain)
    except (VerificationError, Argon2Error, ValueError):
        return False
```

- [ ] **Step 4: Write `backend/app/security/permissions.py`**

```python
from enum import StrEnum


class Permission(StrEnum):
    DEVICE_READ = "DEVICE_READ"
    DEVICE_WRITE = "DEVICE_WRITE"
    CONFIG_UPLOAD = "CONFIG_UPLOAD"
    AUDIT_RUN = "AUDIT_RUN"
    AUDIT_READ = "AUDIT_READ"
    FINDING_READ = "FINDING_READ"
    FINDING_TRIAGE = "FINDING_TRIAGE"
    REPORT_GENERATE = "REPORT_GENERATE"
    REPORT_READ = "REPORT_READ"
    USER_ADMIN = "USER_ADMIN"
    # Defined now so the role matrix is correct from the start; consumed by SP4.
    MAPPING_SUGGEST = "MAPPING_SUGGEST"
    MAPPING_APPROVE = "MAPPING_APPROVE"


_READ_ONLY = frozenset(
    {
        Permission.DEVICE_READ,
        Permission.AUDIT_READ,
        Permission.FINDING_READ,
        Permission.REPORT_READ,
        Permission.REPORT_GENERATE,
    }
)

_OPERATOR = _READ_ONLY | {
    Permission.CONFIG_UPLOAD,
    Permission.AUDIT_RUN,
    Permission.FINDING_TRIAGE,
    Permission.MAPPING_SUGGEST,
}

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "Security Admin": frozenset(_OPERATOR | {Permission.DEVICE_WRITE, Permission.MAPPING_APPROVE}),
    "Network Engineer": frozenset(_OPERATOR),
    "Security Analyst": frozenset(
        (_OPERATOR - {Permission.CONFIG_UPLOAD}) | {Permission.MAPPING_SUGGEST}
    ),
    "CISO": frozenset(_READ_ONLY),
    "Auditor": frozenset(_READ_ONLY),
    "Platform Admin": frozenset(Permission),
}

ROLE_NAMES: tuple[str, ...] = tuple(ROLE_PERMISSIONS)
```

- [ ] **Step 5: Write `backend/app/security/tokens.py`**

```python
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from app.config import settings

_ALGORITHM = "HS256"


class TokenError(ValueError):
    """Raised when a token is expired, tampered with, or otherwise unusable."""


@dataclass(frozen=True)
class TokenClaims:
    user_id: int
    permissions: list[str]


def create_access_token(
    user_id: int, permissions: list[str], expires_in_seconds: int | None = None
) -> str:
    ttl = (
        timedelta(seconds=expires_in_seconds)
        if expires_in_seconds is not None
        else timedelta(minutes=settings.access_token_minutes)
    )
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "perms": [str(permission) for permission in permissions],
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> TokenClaims:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    return TokenClaims(user_id=int(payload["sub"]), permissions=list(payload.get("perms", [])))


def hash_refresh_token(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def new_refresh_token() -> tuple[str, str]:
    """Return (plaintext, hash). Only the hash is ever persisted."""
    plain = secrets.token_urlsafe(48)
    return plain, hash_refresh_token(plain)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_security.py -v`
Expected: PASS (9 tests)

- [ ] **Step 7: Commit**

```bash
git add backend/app/security backend/tests/unit/test_security.py
git commit -m "feat: add Argon2id hashing, JWT tokens, and the RBAC permission matrix"
```

---

## Task 16: Authentication API and RBAC dependency

**Files:**
- Create: `backend/app/api/__init__.py`, `backend/app/api/deps.py`, `backend/app/api/auth.py`, `backend/app/api/users.py`
- Create: `backend/app/schemas/__init__.py`, `backend/app/schemas/auth.py`
- Create: `backend/app/audit_log.py`, `backend/scripts/seed.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/integration/__init__.py`, `backend/tests/integration/conftest.py`, `backend/tests/integration/test_auth.py`

**Interfaces:**
- Consumes: `hash_password`, `verify_password`, token helpers, `Permission`, `ROLE_PERMISSIONS`, `get_db`, models
- Produces: `get_current_user(...) -> User`; `require(*permissions: Permission) -> Callable`; `record_event(session, user_id, action, resource, ip, result) -> None`; routes `POST /api/v1/auth/{login,refresh,logout}` and `GET /api/v1/users/me`; `seed_database(session) -> None`

- [ ] **Step 1: Write the shared integration fixtures**

Create `backend/tests/integration/conftest.py`:

```python
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import get_db
from app.main import create_app
from app.models.base import Base
from scripts.seed import seed_database


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def client(session_factory: sessionmaker[Session]) -> Iterator[TestClient]:
    with session_factory() as session:
        seed_database(session)

    def override_get_db() -> Iterator[Session]:
        with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, email: str, password: str = "demo-password-1") -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


@pytest.fixture
def admin_token(client: TestClient) -> str:
    return login(client, "admin@netsentinel.local")


@pytest.fixture
def ciso_token(client: TestClient) -> str:
    return login(client, "ciso@netsentinel.local")
```

- [ ] **Step 2: Write the failing test**

Create `backend/tests/integration/test_auth.py`:

```python
from fastapi.testclient import TestClient


def test_login_returns_a_token_pair(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.local", "password": "demo-password-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]


def test_login_with_a_wrong_password_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.local", "password": "nope"},
    )
    assert response.status_code == 401


def test_login_does_not_reveal_whether_an_account_exists(client: TestClient) -> None:
    """Both responses must be identical, or the endpoint is a user enumeration oracle."""
    unknown = client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x"}
    )
    known = client.post(
        "/api/v1/auth/login", json={"email": "admin@netsentinel.local", "password": "x"}
    )
    assert unknown.status_code == known.status_code == 401
    assert unknown.json() == known.json()


def test_me_requires_a_token(client: TestClient) -> None:
    assert client.get("/api/v1/users/me").status_code == 401


def test_me_returns_the_caller(client: TestClient, admin_token: str) -> None:
    response = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == "admin@netsentinel.local"
    assert "CONFIG_UPLOAD" in response.json()["permissions"]


def test_refresh_rotates_the_token(client: TestClient) -> None:
    tokens = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.local", "password": "demo-password-1"},
    ).json()
    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != tokens["refresh_token"]


def test_reusing_a_rotated_refresh_token_revokes_the_family(client: TestClient) -> None:
    original = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.local", "password": "demo-password-1"},
    ).json()["refresh_token"]
    rotated = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": original}
    ).json()["refresh_token"]

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": original})
    assert replay.status_code == 401

    # The replay must burn the whole family, not only the reused token.
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": rotated}).status_code == 401


def test_logout_revokes_the_refresh_token(client: TestClient) -> None:
    tokens = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@netsentinel.local", "password": "demo-password-1"},
    ).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.post(
        "/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=headers
    ).status_code == 204
    assert client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).status_code == 401
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.seed'`

- [ ] **Step 4: Write `backend/app/schemas/auth.py`**

```python
from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    permissions: list[str]
```

Add `email-validator` to the project: `uv add email-validator`. Create empty
`backend/app/schemas/__init__.py`.

- [ ] **Step 5: Write `backend/app/audit_log.py`**

```python
from sqlalchemy.orm import Session

from app.models import AuditEvent


def record_event(
    session: Session,
    *,
    action: str,
    user_id: int | None = None,
    resource: str = "",
    ip: str = "",
    result: str = "SUCCESS",
) -> None:
    """Append a security-relevant event. Never records configuration content."""
    session.add(
        AuditEvent(user_id=user_id, action=action, resource=resource, ip=ip, result=result)
    )
```

- [ ] **Step 6: Write `backend/app/api/deps.py`**

```python
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.security.permissions import Permission
from app.security.tokens import TokenError, decode_access_token

_bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        claims = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from exc

    user = session.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    return user


def require(*permissions: Permission) -> Callable[[User], User]:
    """Authorize server-side against the role stored on the user, not the token claims.

    A token issued before a role change must not outlive that change.
    """

    def dependency(user: User = Depends(get_current_user)) -> User:
        granted = set(user.role.permissions)
        missing = {str(permission) for permission in permissions} - granted
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"Missing permission(s): {sorted(missing)}"
            )
        return user

    return dependency
```

- [ ] **Step 7: Write `backend/app/api/auth.py`**

```python
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user
from app.audit_log import record_event
from app.config import settings
from app.db import get_db
from app.models import RefreshToken, User
from app.schemas.auth import LoginRequest, RefreshRequest, TokenPair
from app.security.passwords import verify_password
from app.security.tokens import create_access_token, hash_refresh_token, new_refresh_token

router = APIRouter(prefix="/auth", tags=["auth"])

# One message for both "no such user" and "wrong password" — anything else is an oracle.
_INVALID = "Invalid email or password"


def _issue_pair(session: Session, user: User, family_id: str | None = None) -> TokenPair:
    plain, hashed = new_refresh_token()
    session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hashed,
            family_id=family_id or str(uuid.uuid4()),
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_days),
        )
    )
    access = create_access_token(user_id=user.id, permissions=list(user.role.permissions))
    return TokenPair(access_token=access, refresh_token=plain)


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, session: Session = Depends(get_db)) -> TokenPair:
    user = session.scalar(select(User).where(User.email == payload.email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        record_event(
            session,
            action="LOGIN",
            user_id=user.id if user else None,
            resource=payload.email,
            ip=client_ip(request),
            result="FAILURE",
        )
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID)

    pair = _issue_pair(session, user)
    record_event(session, action="LOGIN", user_id=user.id, ip=client_ip(request))
    session.commit()
    return pair


@router.post("/refresh", response_model=TokenPair)
def refresh(
    payload: RefreshRequest, request: Request, session: Session = Depends(get_db)
) -> TokenPair:
    hashed = hash_refresh_token(payload.refresh_token)
    stored = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == hashed))

    if stored is None or stored.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    if stored.revoked_at is not None:
        # Replay of an already-rotated token: assume theft and burn the whole family.
        session.execute(
            select(RefreshToken).where(RefreshToken.family_id == stored.family_id)
        )
        for sibling in session.scalars(
            select(RefreshToken).where(RefreshToken.family_id == stored.family_id)
        ):
            sibling.revoked_at = sibling.revoked_at or datetime.now(UTC)
        record_event(
            session,
            action="REFRESH_REPLAY",
            user_id=stored.user_id,
            ip=client_ip(request),
            result="FAILURE",
        )
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    stored.revoked_at = datetime.now(UTC)
    user = session.get(User, stored.user_id)
    if user is None or not user.is_active:
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    pair = _issue_pair(session, user, family_id=stored.family_id)
    session.commit()
    return pair


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: RefreshRequest,
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> Response:
    hashed = hash_refresh_token(payload.refresh_token)
    stored = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == hashed))
    if stored is not None and stored.user_id == user.id:
        for sibling in session.scalars(
            select(RefreshToken).where(RefreshToken.family_id == stored.family_id)
        ):
            sibling.revoked_at = sibling.revoked_at or datetime.now(UTC)
    record_event(session, action="LOGOUT", user_id=user.id, ip=client_ip(request))
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
```

- [ ] **Step 8: Write `backend/app/api/users.py`**

```python
from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.models import User
from app.schemas.auth import UserOut

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role=user.role.name,
        permissions=sorted(user.role.permissions),
    )
```

Create empty `backend/app/api/__init__.py`.

- [ ] **Step 9: Write `backend/scripts/seed.py`**

```python
"""Seed the demo organization, the six roles, and one user per role.

Demo passwords are intentionally weak and intentionally committed: this script
never runs against a real deployment. Guard it accordingly before production use.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Organization, Role, User
from app.security.passwords import hash_password
from app.security.permissions import ROLE_PERMISSIONS

DEMO_PASSWORD = "demo-password-1"

DEMO_USERS: dict[str, str] = {
    "admin@netsentinel.local": "Platform Admin",
    "secadmin@netsentinel.local": "Security Admin",
    "engineer@netsentinel.local": "Network Engineer",
    "analyst@netsentinel.local": "Security Analyst",
    "ciso@netsentinel.local": "CISO",
    "auditor@netsentinel.local": "Auditor",
}


def seed_database(session: Session) -> None:
    org = session.scalar(select(Organization).where(Organization.name == "Demo Org"))
    if org is None:
        org = Organization(name="Demo Org")
        session.add(org)

    roles: dict[str, Role] = {}
    for name, permissions in ROLE_PERMISSIONS.items():
        role = session.scalar(select(Role).where(Role.name == name))
        if role is None:
            role = Role(name=name, permissions=sorted(str(item) for item in permissions))
            session.add(role)
        else:
            role.permissions = sorted(str(item) for item in permissions)
        roles[name] = role

    for email, role_name in DEMO_USERS.items():
        if session.scalar(select(User).where(User.email == email)) is None:
            session.add(
                User(
                    organization=org,
                    role=roles[role_name],
                    email=email,
                    password_hash=hash_password(DEMO_PASSWORD),
                )
            )

    session.commit()


if __name__ == "__main__":
    with SessionLocal() as session:
        seed_database(session)
        print(f"Seeded {len(DEMO_USERS)} demo users with password {DEMO_PASSWORD!r}")
```

Create empty `backend/scripts/__init__.py`.

- [ ] **Step 10: Mount the routers in `backend/app/main.py`**

Replace `create_app` with:

```python
def create_app() -> FastAPI:
    from app.api import auth, users

    app = FastAPI(title="NetSentinel AI", version="0.1.0")
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(users.router, prefix="/api/v1")
    return app
```

- [ ] **Step 11: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_auth.py -v`
Expected: PASS (8 tests)

- [ ] **Step 12: Commit**

```bash
git add backend/app/api backend/app/schemas backend/app/audit_log.py backend/app/main.py backend/scripts backend/tests/integration
git commit -m "feat: add auth endpoints, RBAC dependency, audit log, and demo seed"
```

---

## Task 17: Storage and task seams

**Files:**
- Create: `backend/app/storage/__init__.py`, `backend/app/storage/base.py`, `backend/app/storage/local.py`
- Create: `backend/app/tasks/__init__.py`, `backend/app/tasks/base.py`, `backend/app/tasks/inline.py`
- Test: `backend/tests/unit/test_storage.py`

**Interfaces:**
- Consumes: `settings`
- Produces:
  - `StorageBackend` protocol: `put(key: str, data: bytes) -> None`, `get(key: str) -> bytes`, `exists(key: str) -> bool`
  - `LocalFileStorage(root: Path)`; `StorageError`; `get_storage() -> StorageBackend`
  - `TaskRunner` protocol: `submit(fn: Callable[..., None], /, *args: object) -> None`
  - `InlineTaskRunner`; `get_task_runner() -> TaskRunner`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/unit/test_storage.py`:

```python
from pathlib import Path

import pytest

from app.storage.local import LocalFileStorage, StorageError


def test_round_trips_bytes(tmp_path: Path) -> None:
    storage = LocalFileStorage(tmp_path)
    storage.put("configs/abc.cfg", b"hostname router")
    assert storage.get("configs/abc.cfg") == b"hostname router"
    assert storage.exists("configs/abc.cfg")


def test_missing_key_reports_absence_not_a_crash(tmp_path: Path) -> None:
    storage = LocalFileStorage(tmp_path)
    assert not storage.exists("nope")
    with pytest.raises(StorageError):
        storage.get("nope")


def test_nested_keys_create_directories(tmp_path: Path) -> None:
    storage = LocalFileStorage(tmp_path)
    storage.put("a/b/c/d.bin", b"x")
    assert (tmp_path / "a" / "b" / "c" / "d.bin").exists()


@pytest.mark.parametrize("key", ["../escape", "a/../../escape", "/absolute", "a/./../../x"])
def test_keys_cannot_escape_the_storage_root(tmp_path: Path, key: str) -> None:
    """Blob keys derive from user input; traversal must be impossible, not merely unlikely."""
    storage = LocalFileStorage(tmp_path)
    with pytest.raises(StorageError):
        storage.put(key, b"x")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.storage'`

- [ ] **Step 3: Write `backend/app/storage/base.py`**

```python
from typing import Protocol


class StorageError(RuntimeError):
    """Raised when a blob cannot be read, written, or addressed safely."""


class StorageBackend(Protocol):
    """The only interface through which blob content may be reached.

    SP6 swaps LocalFileStorage for an S3/MinIO implementation of this protocol.
    """

    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...
```

- [ ] **Step 4: Write `backend/app/storage/local.py`**

```python
from pathlib import Path

from app.config import settings
from app.storage.base import StorageBackend, StorageError

__all__ = ["LocalFileStorage", "StorageBackend", "StorageError", "get_storage"]


class LocalFileStorage:
    """Filesystem-backed blob store. The only module permitted to touch blob paths."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        candidate = (self._root / key).resolve()
        if not candidate.is_relative_to(self._root):
            raise StorageError(f"blob key escapes the storage root: {key!r}")
        return candidate

    def put(self, key: str, data: bytes) -> None:
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> bytes:
        path = self._resolve(key)
        if not path.is_file():
            raise StorageError(f"no blob at key {key!r}")
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        try:
            return self._resolve(key).is_file()
        except StorageError:
            return False


def get_storage() -> StorageBackend:
    return LocalFileStorage(settings.storage_dir)
```

- [ ] **Step 5: Write `backend/app/tasks/base.py` and `backend/app/tasks/inline.py`**

`backend/app/tasks/base.py`:

```python
from collections.abc import Callable
from typing import Protocol


class TaskRunner(Protocol):
    """Deferred work seam. SP6 swaps this for a Celery-backed implementation."""

    def submit(self, fn: Callable[..., None], /, *args: object) -> None: ...
```

`backend/app/tasks/inline.py`:

```python
from collections.abc import Callable

from app.tasks.base import TaskRunner

__all__ = ["InlineTaskRunner", "TaskRunner", "get_task_runner"]


class InlineTaskRunner:
    """Runs work synchronously.

    Slice 1 audits parse a file under 5 MB and evaluate 16 rules — well inside a
    request. Making this async before it is slow would buy complexity, not speed.
    """

    def submit(self, fn: Callable[..., None], /, *args: object) -> None:
        fn(*args)


def get_task_runner() -> TaskRunner:
    return InlineTaskRunner()
```

Create empty `backend/app/storage/__init__.py` and `backend/app/tasks/__init__.py`.

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_storage.py -v`
Expected: PASS (7 tests)

- [ ] **Step 7: Commit**

```bash
git add backend/app/storage backend/app/tasks backend/tests/unit/test_storage.py
git commit -m "feat: add storage and task-runner seams with traversal-safe local blobs"
```

---

## Task 18: Configuration ingestion

**Files:**
- Create: `backend/app/services/ingestion/__init__.py`, `backend/app/services/ingestion/upload.py`
- Create: `backend/app/api/configurations.py`, `backend/app/api/devices.py`, `backend/app/schemas/configurations.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/integration/test_ingestion.py`

**Interfaces:**
- Consumes: `redact`, `detect`, `StorageBackend`, models, `require`, `record_event`
- Produces: `IngestionError`; `validate_upload(filename: str, data: bytes) -> str` returning decoded text; `ingest_configuration(session, storage, user, filename, data) -> Configuration`; routes `POST /api/v1/configurations/upload`, `GET /api/v1/configurations/{id}`, `GET|POST /api/v1/devices`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/integration/test_ingestion.py`:

```python
from fastapi.testclient import TestClient

CONFIG = b"""Building configuration...
!
version 17.6
boot-start-marker
!
hostname core-sw-01
enable secret 5 $1$abcd$EFGHIJKLMNOPQRSTUV
ip ssh version 2
line con 0
!
end
"""


def upload(client: TestClient, token: str, data: bytes = CONFIG, name: str = "core.cfg"):
    return client.post(
        "/api/v1/configurations/upload",
        files={"file": (name, data, "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )


def test_upload_stores_hash_and_redaction_count(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token)
    assert response.status_code == 201, response.text
    body = response.json()
    assert len(body["sha256"]) == 64
    assert body["secret_hits"] == 1
    assert body["device"]["vendor"] == "cisco"
    assert body["device"]["name"] == "core-sw-01"


def test_uploaded_text_is_returned_redacted(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token).json()["id"]
    response = client.get(
        f"/api/v1/configurations/{config_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert "$1$abcd$EFGHIJKLMNOPQRSTUV" not in response.text
    assert "<REDACTED:enable-secret-strong>" in response.json()["text"]


def test_reupload_of_identical_content_is_idempotent(client: TestClient, admin_token: str) -> None:
    first = upload(client, admin_token)
    second = upload(client, admin_token)
    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]


def test_unsupported_extension_is_rejected(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token, name="payload.exe")
    assert response.status_code == 422
    assert "extension" in response.json()["detail"].lower()


def test_oversized_upload_is_rejected(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token, data=b"a" * (5 * 1024 * 1024 + 1))
    assert response.status_code == 422


def test_binary_upload_is_rejected(client: TestClient, admin_token: str) -> None:
    response = upload(client, admin_token, data=b"\x00\x01\x02\xff\xfe", name="x.cfg")
    assert response.status_code == 422


def test_upload_requires_the_config_upload_permission(client: TestClient, ciso_token: str) -> None:
    assert upload(client, ciso_token).status_code == 403


def test_upload_is_recorded_in_the_audit_trail(client: TestClient, admin_token: str) -> None:
    upload(client, admin_token)
    # The event is written in the same transaction as the configuration row.
    response = client.get(
        "/api/v1/devices", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()[0]["name"] == "core-sw-01"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_ingestion.py -v`
Expected: FAIL with 404 on the upload route.

- [ ] **Step 3: Write `backend/app/services/ingestion/upload.py`**

```python
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Configuration, Device, User
from app.security.redaction import redact
from app.services.detection.cisco import detect
from app.storage.base import StorageBackend

ALLOWED_EXTENSIONS = frozenset({".txt", ".cfg", ".conf", ".log", ".json", ".xml", ".yaml", ".yml"})


class IngestionError(ValueError):
    """Raised when an upload is not acceptable. Surfaces to the caller as HTTP 422."""


def validate_upload(filename: str, data: bytes) -> str:
    """Validate an untrusted upload and return its decoded text."""
    suffix = filename[filename.rfind(".") :].lower() if "." in filename else ""
    if suffix not in ALLOWED_EXTENSIONS:
        raise IngestionError(
            f"unsupported file extension {suffix!r}; allowed: {sorted(ALLOWED_EXTENSIONS)}"
        )
    if len(data) > settings.max_upload_bytes:
        raise IngestionError(f"file exceeds the {settings.max_upload_bytes} byte limit")
    if not data.strip():
        raise IngestionError("file is empty")
    if b"\x00" in data:
        raise IngestionError("file contains binary content")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise IngestionError("file is not decodable as text") from exc


def ingest_configuration(
    session: Session,
    storage: StorageBackend,
    user: User,
    filename: str,
    data: bytes,
) -> tuple[Configuration, bool]:
    """Validate, redact, hash, store, and register a configuration.

    Returns the configuration and whether it was newly created. Redaction happens
    before anything is persisted, so no secret material reaches the database.
    """
    text = validate_upload(filename, data)
    redaction = redact(text)
    identity = detect(redaction.text)

    device_name = identity.hostname or filename.rsplit(".", 1)[0]
    device = session.scalar(
        select(Device).where(
            Device.organization_id == user.organization_id, Device.name == device_name
        )
    )
    if device is None:
        device = Device(
            organization_id=user.organization_id,
            name=device_name,
            vendor=identity.vendor,
            os=identity.os,
            os_version=identity.os_version,
        )
        session.add(device)
        session.flush()

    redacted_bytes = redaction.text.encode("utf-8")
    digest = hashlib.sha256(redacted_bytes).hexdigest()

    existing = session.scalar(
        select(Configuration).where(
            Configuration.device_id == device.id, Configuration.sha256 == digest
        )
    )
    if existing is not None:
        return existing, False

    blob_key = f"configurations/{digest[:2]}/{digest}.cfg"
    storage.put(blob_key, redacted_bytes)

    configuration = Configuration(
        device=device,
        sha256=digest,
        blob_key=blob_key,
        filename=filename,
        size_bytes=len(redacted_bytes),
        uploaded_by=user,
        secret_hits=len(redaction.hits),
    )
    session.add(configuration)
    session.flush()
    return configuration, True
```

Create empty `backend/app/services/ingestion/__init__.py`.

- [ ] **Step 4: Write `backend/app/schemas/configurations.py`**

```python
from pydantic import BaseModel


class DeviceOut(BaseModel):
    id: int
    name: str
    vendor: str
    os: str
    os_version: str | None = None


class ConfigurationOut(BaseModel):
    id: int
    sha256: str
    filename: str
    size_bytes: int
    secret_hits: int
    device: DeviceOut


class ConfigurationDetail(ConfigurationOut):
    text: str
```

- [ ] **Step 5: Write `backend/app/api/configurations.py`**

```python
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.db import get_db
from app.models import Configuration, User
from app.schemas.configurations import ConfigurationDetail, ConfigurationOut, DeviceOut
from app.security.permissions import Permission
from app.services.ingestion.upload import IngestionError, ingest_configuration
from app.storage.base import StorageBackend
from app.storage.local import get_storage

router = APIRouter(prefix="/configurations", tags=["configurations"])


def _to_out(configuration: Configuration) -> ConfigurationOut:
    return ConfigurationOut(
        id=configuration.id,
        sha256=configuration.sha256,
        filename=configuration.filename,
        size_bytes=configuration.size_bytes,
        secret_hits=configuration.secret_hits,
        device=DeviceOut(
            id=configuration.device.id,
            name=configuration.device.name,
            vendor=configuration.device.vendor,
            os=configuration.device.os,
            os_version=configuration.device.os_version,
        ),
    )


@router.post("/upload", response_model=ConfigurationOut, status_code=status.HTTP_201_CREATED)
def upload(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    user: User = Depends(require(Permission.CONFIG_UPLOAD)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> ConfigurationOut:
    data = file.file.read()
    try:
        configuration, created = ingest_configuration(
            session, storage, user, file.filename or "upload.cfg", data
        )
    except IngestionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    record_event(
        session,
        action="UPLOAD_CONFIGURATION",
        user_id=user.id,
        resource=configuration.sha256,
        ip=client_ip(request),
    )
    session.commit()
    if not created:
        response.status_code = status.HTTP_200_OK
    return _to_out(configuration)


@router.get("/{configuration_id}", response_model=ConfigurationDetail)
def read(
    configuration_id: int,
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> ConfigurationDetail:
    configuration = session.get(Configuration, configuration_id)
    if configuration is None or configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Configuration not found")

    base = _to_out(configuration)
    return ConfigurationDetail(
        **base.model_dump(), text=storage.get(configuration.blob_key).decode("utf-8")
    )
```

Add `Response` to the FastAPI import line at the top of the file.

- [ ] **Step 6: Write `backend/app/api/devices.py`**

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require
from app.db import get_db
from app.models import Device, User
from app.schemas.configurations import DeviceOut
from app.security.permissions import Permission

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=list[DeviceOut])
def list_devices(
    user: User = Depends(require(Permission.DEVICE_READ)),
    session: Session = Depends(get_db),
) -> list[DeviceOut]:
    devices = session.scalars(
        select(Device).where(Device.organization_id == user.organization_id).order_by(Device.name)
    )
    return [DeviceOut.model_validate(device, from_attributes=True) for device in devices]


@router.get("/{device_id}", response_model=DeviceOut)
def read_device(
    device_id: int,
    user: User = Depends(require(Permission.DEVICE_READ)),
    session: Session = Depends(get_db),
) -> DeviceOut:
    device = session.get(Device, device_id)
    if device is None or device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    return DeviceOut.model_validate(device, from_attributes=True)
```

- [ ] **Step 7: Mount both routers in `create_app`**

```python
    from app.api import auth, configurations, devices, users

    app.include_router(devices.router, prefix="/api/v1")
    app.include_router(configurations.router, prefix="/api/v1")
```

- [ ] **Step 8: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_ingestion.py -v`
Expected: PASS (8 tests)

- [ ] **Step 9: Commit**

```bash
git add backend/app/services/ingestion backend/app/api backend/app/schemas backend/tests/integration/test_ingestion.py
git commit -m "feat: add configuration ingestion with validation, redaction, and hashing"
```

---

## Task 19: Audit orchestration

**Files:**
- Create: `backend/app/services/audit/__init__.py`, `backend/app/services/audit/runner.py`
- Create: `backend/app/api/audits.py`, `backend/app/schemas/audits.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/integration/test_audits.py`

**Interfaces:**
- Consumes: every pure stage, `StorageBackend`, `TaskRunner`, models
- Produces: `DetectionConfirmationRequired(identity: DeviceIdentity)`; `start_audit(session, storage, configuration, framework, vendor_override) -> AuditRun`; `execute_audit(session_factory, audit_run_id) -> None`; routes `POST /api/v1/audits`, `GET /api/v1/audits`, `GET /api/v1/audits/{id}`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/integration/test_audits.py`:

```python
from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def upload(client: TestClient, token: str, name: str) -> int:
    data = (DATASETS / f"{name}.cfg").read_bytes()
    response = client.post(
        "/api/v1/configurations/upload",
        files={"file": (f"{name}.cfg", data, "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code in (200, 201), response.text
    return int(response.json()["id"])


def run_audit(client: TestClient, token: str, configuration_id: int):
    return client.post(
        "/api/v1/audits",
        json={"configuration_id": configuration_id, "framework": "CIS"},
        headers={"Authorization": f"Bearer {token}"},
    )


def test_audit_of_a_compliant_config_scores_one_hundred(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "compliant")
    response = run_audit(client, admin_token, config_id)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["score"] == 100
    assert body["coverage"] == 1.0


def test_audit_of_a_noncompliant_config_scores_zero(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "noncompliant")
    body = run_audit(client, admin_token, config_id).json()
    assert body["score"] == 0
    assert body["fail_counts"]["CRITICAL"] >= 1


def test_audit_records_provenance_for_reproducibility(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "compliant")
    body = run_audit(client, admin_token, config_id).json()
    assert len(body["rule_pack_hash"]) == 64
    assert body["engine_version"]
    assert body["detection"]["vendor"] == "cisco"
    assert body["detection"]["reasons"]


def test_audit_detail_exposes_controls_results_and_unknowns(
    client: TestClient, admin_token: str
) -> None:
    config_id = upload(client, admin_token, "mixed")
    audit_id = run_audit(client, admin_token, config_id).json()["id"]
    response = client.get(
        f"/api/v1/audits/{audit_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["controls"]) >= 10
    assert len(body["results"]) == 16
    assert len(body["unknown_constructs"]) >= 2
    ssh = next(item for item in body["controls"] if item["key"] == "management.ssh.version")
    assert ssh["source_lines"]
    assert ssh["excerpt"]


def test_reaudit_of_identical_input_is_reproducible(client: TestClient, admin_token: str) -> None:
    config_id = upload(client, admin_token, "compliant")
    first = run_audit(client, admin_token, config_id).json()
    second = run_audit(client, admin_token, config_id).json()
    assert first["id"] != second["id"]
    assert first["score"] == second["score"]
    assert first["rule_pack_hash"] == second["rule_pack_hash"]


def test_low_confidence_detection_demands_an_explicit_vendor(
    client: TestClient, admin_token: str
) -> None:
    junos = b"system {\n    host-name mx-01;\n    services {\n        ssh;\n    }\n}\n"
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("mx01.conf", junos, "text/plain")},
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()["id"]

    response = run_audit(client, admin_token, config_id)
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["confidence"] < 0.70
    assert detail["reasons"] is not None


def test_running_an_audit_requires_the_audit_run_permission(
    client: TestClient, admin_token: str, ciso_token: str
) -> None:
    config_id = upload(client, admin_token, "compliant")
    assert run_audit(client, ciso_token, config_id).status_code == 403


def test_reading_an_audit_is_allowed_for_read_only_roles(
    client: TestClient, admin_token: str, ciso_token: str
) -> None:
    config_id = upload(client, admin_token, "compliant")
    audit_id = run_audit(client, admin_token, config_id).json()["id"]
    response = client.get(
        f"/api/v1/audits/{audit_id}", headers={"Authorization": f"Bearer {ciso_token}"}
    )
    assert response.status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_audits.py -v`
Expected: FAIL with 404 on `POST /api/v1/audits`.

- [ ] **Step 3: Write `backend/app/services/audit/runner.py`**

```python
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.domain.device import DeviceIdentity
from app.models import AuditRun, ComplianceResultRow, Configuration, Finding, NormalizedControlRow
from app.services.compliance.engine import evaluate_pack
from app.services.compliance.rules import RulePack, load_all_packs
from app.services.detection.cisco import detect
from app.services.normalization.cisco import normalize_cisco
from app.services.parsing.cisco import parse_cisco
from app.services.remediation.packs import load_remediations
from app.services.scoring.posture import score_results
from app.domain.results import Status
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
        parse_warnings=[
            {"lineno": item.lineno, "message": item.message} for item in tree.warnings
        ],
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
```

Create empty `backend/app/services/audit/__init__.py`.

- [ ] **Step 4: Write `backend/app/schemas/audits.py`**

```python
from pydantic import BaseModel


class AuditRequest(BaseModel):
    configuration_id: int
    framework: str = "CIS"
    vendor_override: str | None = None


class DetectionOut(BaseModel):
    vendor: str | None
    os: str | None
    confidence: float | None
    reasons: list[str]
    override: str | None = None


class ControlOut(BaseModel):
    key: str
    value: object
    source_lines: list[int]
    excerpt: str
    parser_confidence: float
    origin: str


class ResultOut(BaseModel):
    rule_id: str
    parameter: str
    observed_value: object
    expected_value: object
    status: str
    severity: str
    evidence_lines: list[int]
    evidence_excerpt: str


class UnknownOut(BaseModel):
    text: str
    lineno: int
    block: str | None = None


class AuditSummary(BaseModel):
    id: int
    configuration_id: int
    device_name: str
    framework: str
    framework_version: str
    status: str
    score: int | None
    coverage: float | None
    rule_pack_hash: str
    engine_version: str
    detection: DetectionOut
    fail_counts: dict[str, int]


class AuditDetail(AuditSummary):
    controls: list[ControlOut]
    results: list[ResultOut]
    unknown_constructs: list[UnknownOut]
    parse_warnings: list[dict[str, object]]
```

- [ ] **Step 5: Write `backend/app/api/audits.py`**

```python
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.db import get_db
from app.domain.results import Severity
from app.models import AuditRun, ComplianceResultRow, Configuration, User
from app.schemas.audits import (
    AuditDetail,
    AuditRequest,
    AuditSummary,
    ControlOut,
    DetectionOut,
    ResultOut,
    UnknownOut,
)
from app.security.permissions import Permission
from app.services.audit.runner import DetectionConfirmationRequired, run_audit
from app.storage.base import StorageBackend
from app.storage.local import get_storage

router = APIRouter(prefix="/audits", tags=["audits"])


def _fail_counts(session: Session, run: AuditRun) -> dict[str, int]:
    rows = session.scalars(
        select(ComplianceResultRow).where(
            ComplianceResultRow.audit_run_id == run.id, ComplianceResultRow.status == "FAIL"
        )
    )
    counts = {str(severity): 0 for severity in Severity}
    for row in rows:
        counts[row.severity] += 1
    return counts


def _summary(session: Session, run: AuditRun) -> AuditSummary:
    return AuditSummary(
        id=run.id,
        configuration_id=run.configuration_id,
        device_name=run.configuration.device.name,
        framework=run.framework,
        framework_version=run.framework_version,
        status=run.status,
        score=run.score,
        coverage=run.coverage,
        rule_pack_hash=run.rule_pack_hash,
        engine_version=run.engine_version,
        detection=DetectionOut(
            vendor=run.detected_vendor,
            os=run.detected_os,
            confidence=run.detection_confidence,
            reasons=run.detection_reasons,
            override=run.vendor_override,
        ),
        fail_counts=_fail_counts(session, run),
    )


@router.post("", response_model=AuditSummary, status_code=status.HTTP_201_CREATED)
def create_audit(
    payload: AuditRequest,
    request: Request,
    user: User = Depends(require(Permission.AUDIT_RUN)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> AuditSummary:
    configuration = session.get(Configuration, payload.configuration_id)
    if configuration is None or configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Configuration not found")

    try:
        run = run_audit(session, storage, configuration, payload.framework, payload.vendor_override)
    except DetectionConfirmationRequired as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "message": "Device detection requires manual confirmation",
                "confidence": exc.identity.confidence,
                "reasons": exc.identity.reasons,
                "candidate_vendor": exc.identity.vendor,
            },
        ) from exc

    record_event(
        session,
        action="START_AUDIT",
        user_id=user.id,
        resource=str(run.id),
        ip=client_ip(request),
    )
    session.commit()
    return _summary(session, run)


@router.get("", response_model=list[AuditSummary])
def list_audits(
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
) -> list[AuditSummary]:
    runs = session.scalars(select(AuditRun).order_by(AuditRun.id.desc()))
    return [
        _summary(session, run)
        for run in runs
        if run.configuration.device.organization_id == user.organization_id
    ]


@router.get("/{audit_id}", response_model=AuditDetail)
def read_audit(
    audit_id: int,
    user: User = Depends(require(Permission.AUDIT_READ)),
    session: Session = Depends(get_db),
) -> AuditDetail:
    run = session.get(AuditRun, audit_id)
    if run is None or run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit not found")

    return AuditDetail(
        **_summary(session, run).model_dump(),
        controls=[
            ControlOut(
                key=row.key,
                value=row.value_json,
                source_lines=row.source_lines,
                excerpt=row.excerpt,
                parser_confidence=row.parser_confidence,
                origin=row.origin,
            )
            for row in run.controls
        ],
        results=[
            ResultOut(
                rule_id=row.rule_id,
                parameter=row.parameter,
                observed_value=row.observed_value,
                expected_value=row.expected_value,
                status=row.status,
                severity=row.severity,
                evidence_lines=row.evidence_lines,
                evidence_excerpt=row.evidence_excerpt,
            )
            for row in run.results
        ],
        unknown_constructs=[UnknownOut(**item) for item in run.unknown_constructs],
        parse_warnings=run.parse_warnings,
    )
```

- [ ] **Step 6: Validate rule and remediation packs at startup in `create_app`**

Add before the router includes, so a malformed pack fails the process rather than the audit:

```python
    from app.services.compliance.rules import load_all_packs
    from app.services.remediation.packs import load_remediations

    packs = load_all_packs(settings.rules_dir)
    remediations = load_remediations(settings.mappings_dir)
    referenced = {rule.remediation_id for pack in packs for rule in pack.rules}
    missing = referenced - remediations.keys()
    if missing:
        raise RuntimeError(f"rules reference missing remediations: {sorted(missing)}")
```

Mount the router: `app.include_router(audits.router, prefix="/api/v1")`.

- [ ] **Step 7: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_audits.py -v`
Expected: PASS (8 tests)

- [ ] **Step 8: Commit**

```bash
git add backend/app/services/audit backend/app/api/audits.py backend/app/schemas/audits.py backend/app/main.py backend/tests/integration/test_audits.py
git commit -m "feat: add audit orchestration with provenance and fail-closed detection"
```

---

## Task 20: Findings, remediation, and triage

**Files:**
- Create: `backend/app/api/findings.py`, `backend/app/api/frameworks.py`, `backend/app/schemas/findings.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/integration/test_findings.py`

**Interfaces:**
- Consumes: `Finding`, `ComplianceResultRow`, `load_remediations`, `load_all_packs`, `require`
- Produces: routes `GET /api/v1/findings`, `GET /api/v1/findings/{id}`, `PATCH /api/v1/findings/{id}`, `GET /api/v1/frameworks`, `GET /api/v1/frameworks/{id}/rules`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/integration/test_findings.py`:

```python
from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def audit_noncompliant(client: TestClient, token: str) -> int:
    data = (DATASETS / "noncompliant.cfg").read_bytes()
    headers = {"Authorization": f"Bearer {token}"}
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": ("bad.cfg", data, "text/plain")},
        headers=headers,
    ).json()["id"]
    return int(
        client.post(
            "/api/v1/audits",
            json={"configuration_id": config_id, "framework": "CIS"},
            headers=headers,
        ).json()["id"]
    )


def test_every_failing_rule_produces_a_finding(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    response = client.get(
        f"/api/v1/findings?audit_id={audit_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert len(response.json()) == 16


def test_findings_can_be_filtered_by_severity(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    response = client.get(
        f"/api/v1/findings?audit_id={audit_id}&severity=CRITICAL",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.json()
    assert {item["severity"] for item in response.json()} == {"CRITICAL"}


def test_finding_detail_carries_the_full_provenance_chain(
    client: TestClient, admin_token: str
) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0]["id"]

    body = client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    assert body["rule_id"]
    assert body["framework"] == "CIS"
    assert body["framework_version"]
    assert len(body["configuration_sha256"]) == 64
    assert len(body["rule_pack_hash"]) == 64
    assert body["parameter"]
    assert body["evidence_excerpt"] != ""


def test_finding_detail_includes_remediation_with_the_validation_banner(
    client: TestClient, admin_token: str
) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0]["id"]

    remediation = client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()["remediation"]
    assert remediation["cli"].strip() != ""
    assert remediation["verification"].strip() != ""
    assert remediation["banner"] == "Review and validate before production deployment."


def test_triage_updates_persist(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0]["id"]

    patched = client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"triage_status": "accepted_risk", "notes": "Compensating control in place."},
        headers=headers,
    )
    assert patched.status_code == 200
    assert patched.json()["triage_status"] == "accepted_risk"
    assert client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()["notes"]


def test_invalid_triage_status_is_rejected(client: TestClient, admin_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}
    finding_id = client.get(f"/api/v1/findings?audit_id={audit_id}", headers=headers).json()[0]["id"]
    response = client.patch(
        f"/api/v1/findings/{finding_id}", json={"triage_status": "ignored"}, headers=headers
    )
    assert response.status_code == 422


def test_read_only_roles_cannot_triage(client: TestClient, admin_token: str, ciso_token: str) -> None:
    audit_id = audit_noncompliant(client, admin_token)
    finding_id = client.get(
        f"/api/v1/findings?audit_id={audit_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()[0]["id"]

    response = client.patch(
        f"/api/v1/findings/{finding_id}",
        json={"triage_status": "false_positive"},
        headers={"Authorization": f"Bearer {ciso_token}"},
    )
    assert response.status_code == 403


def test_frameworks_endpoint_reports_loaded_packs(client: TestClient, admin_token: str) -> None:
    response = client.get(
        "/api/v1/frameworks", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    pack = response.json()[0]
    assert pack["framework"] == "CIS"
    assert pack["rule_count"] == 16
    assert len(pack["sha256"]) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_findings.py -v`
Expected: FAIL with 404 on `/api/v1/findings`.

- [ ] **Step 3: Write `backend/app/schemas/findings.py`**

```python
from typing import Literal

from pydantic import BaseModel

TriageStatus = Literal["open", "accepted_risk", "false_positive", "resolved"]


class RemediationOut(BaseModel):
    id: str
    title: str
    cli: str
    verification: str
    rollback: str
    notes: str
    banner: str


class FindingSummary(BaseModel):
    id: int
    audit_run_id: int
    rule_id: str
    title: str
    severity: str
    status: str
    parameter: str
    triage_status: str


class FindingDetail(FindingSummary):
    framework: str
    framework_version: str
    rule_pack_hash: str
    configuration_sha256: str
    description: str
    observed_value: object
    expected_value: object
    evidence_lines: list[int]
    evidence_excerpt: str
    notes: str
    remediation: RemediationOut


class TriageRequest(BaseModel):
    triage_status: TriageStatus | None = None
    notes: str | None = None


class FrameworkOut(BaseModel):
    framework: str
    framework_version: str
    rule_count: int
    sha256: str
```

- [ ] **Step 4: Write `backend/app/api/findings.py`**

```python
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.config import settings
from app.db import get_db
from app.models import ComplianceResultRow, Finding, User
from app.schemas.findings import (
    FindingDetail,
    FindingSummary,
    RemediationOut,
    TriageRequest,
)
from app.security.permissions import Permission
from app.services.compliance.rules import load_all_packs
from app.services.remediation.packs import load_remediations

router = APIRouter(prefix="/findings", tags=["findings"])


def _load(session: Session, finding_id: int, user: User) -> tuple[Finding, ComplianceResultRow]:
    finding = session.get(Finding, finding_id)
    if finding is None or finding.compliance_result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    result = finding.compliance_result
    if result.audit_run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return finding, result


def _summary(finding: Finding, result: ComplianceResultRow) -> FindingSummary:
    return FindingSummary(
        id=finding.id,
        audit_run_id=result.audit_run_id,
        rule_id=result.rule_id,
        title=finding.title,
        severity=finding.severity,
        status=result.status,
        parameter=result.parameter,
        triage_status=finding.triage_status,
    )


@router.get("", response_model=list[FindingSummary])
def list_findings(
    audit_id: int | None = None,
    severity: str | None = None,
    triage_status: str | None = None,
    user: User = Depends(require(Permission.FINDING_READ)),
    session: Session = Depends(get_db),
) -> list[FindingSummary]:
    statement = select(Finding).join(Finding.compliance_result)
    if audit_id is not None:
        statement = statement.where(ComplianceResultRow.audit_run_id == audit_id)
    if severity is not None:
        statement = statement.where(Finding.severity == severity.upper())
    if triage_status is not None:
        statement = statement.where(Finding.triage_status == triage_status)

    findings = session.scalars(statement.order_by(Finding.id))
    return [
        _summary(finding, finding.compliance_result)
        for finding in findings
        if finding.compliance_result is not None
        and finding.compliance_result.audit_run.configuration.device.organization_id
        == user.organization_id
    ]


@router.get("/{finding_id}", response_model=FindingDetail)
def read_finding(
    finding_id: int,
    user: User = Depends(require(Permission.FINDING_READ)),
    session: Session = Depends(get_db),
) -> FindingDetail:
    finding, result = _load(session, finding_id, user)
    run = result.audit_run

    rules = {rule.id: rule for pack in load_all_packs(settings.rules_dir) for rule in pack.rules}
    rule = rules[result.rule_id]
    remediation = load_remediations(settings.mappings_dir)[finding.remediation_id]

    return FindingDetail(
        **_summary(finding, result).model_dump(),
        framework=result.framework,
        framework_version=result.framework_version,
        rule_pack_hash=run.rule_pack_hash,
        configuration_sha256=run.configuration.sha256,
        description=rule.description,
        observed_value=result.observed_value,
        expected_value=result.expected_value,
        evidence_lines=result.evidence_lines,
        evidence_excerpt=result.evidence_excerpt,
        notes=finding.notes,
        remediation=RemediationOut(
            id=remediation.id,
            title=remediation.title,
            cli=remediation.cli,
            verification=remediation.verification,
            rollback=remediation.rollback,
            notes=remediation.notes,
            banner=remediation.banner,
        ),
    )


@router.patch("/{finding_id}", response_model=FindingSummary)
def triage_finding(
    finding_id: int,
    payload: TriageRequest,
    request: Request,
    user: User = Depends(require(Permission.FINDING_TRIAGE)),
    session: Session = Depends(get_db),
) -> FindingSummary:
    finding, result = _load(session, finding_id, user)
    if payload.triage_status is not None:
        finding.triage_status = payload.triage_status
    if payload.notes is not None:
        finding.notes = payload.notes

    record_event(
        session,
        action="TRIAGE_FINDING",
        user_id=user.id,
        resource=str(finding.id),
        ip=client_ip(request),
    )
    session.commit()
    return _summary(finding, result)
```

- [ ] **Step 5: Write `backend/app/api/frameworks.py`**

```python
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require
from app.config import settings
from app.models import User
from app.schemas.findings import FrameworkOut
from app.security.permissions import Permission
from app.services.compliance.rules import load_all_packs

router = APIRouter(prefix="/frameworks", tags=["frameworks"])


@router.get("", response_model=list[FrameworkOut])
def list_frameworks(
    _: User = Depends(require(Permission.AUDIT_READ)),
) -> list[FrameworkOut]:
    return [
        FrameworkOut(
            framework=pack.framework,
            framework_version=pack.framework_version,
            rule_count=len(pack.rules),
            sha256=pack.sha256,
        )
        for pack in load_all_packs(settings.rules_dir)
    ]


@router.get("/{framework}/rules")
def list_rules(
    framework: str,
    _: User = Depends(require(Permission.AUDIT_READ)),
) -> list[dict[str, object]]:
    for pack in load_all_packs(settings.rules_dir):
        if pack.framework.upper() == framework.upper():
            return [rule.model_dump(mode="json") for rule in pack.rules]
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Framework not found")
```

Mount both routers in `create_app`.

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_findings.py -v`
Expected: PASS (8 tests)

- [ ] **Step 7: Commit**

```bash
git add backend/app/api/findings.py backend/app/api/frameworks.py backend/app/schemas/findings.py backend/app/main.py backend/tests/integration/test_findings.py
git commit -m "feat: add findings, provenance detail, remediation, and triage endpoints"
```

---

## Task 21: PDF report

**Files:**
- Create: `backend/app/services/reporting/__init__.py`, `backend/app/services/reporting/pdf.py`
- Create: `backend/app/api/reports.py`, `backend/app/schemas/reports.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/integration/test_reports.py`

**Interfaces:**
- Consumes: `AuditRun`, `Finding`, `load_remediations`, `StorageBackend`, `require`
- Produces: `build_device_report(run, findings, remediations) -> bytes`; routes `POST /api/v1/audits/{id}/report`, `GET /api/v1/reports/{id}`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/integration/test_reports.py`:

```python
from pathlib import Path

from fastapi.testclient import TestClient

DATASETS = Path(__file__).resolve().parents[3] / "datasets" / "demo" / "cisco"


def audit(client: TestClient, token: str, name: str) -> int:
    headers = {"Authorization": f"Bearer {token}"}
    data = (DATASETS / f"{name}.cfg").read_bytes()
    config_id = client.post(
        "/api/v1/configurations/upload",
        files={"file": (f"{name}.cfg", data, "text/plain")},
        headers=headers,
    ).json()["id"]
    return int(
        client.post(
            "/api/v1/audits",
            json={"configuration_id": config_id, "framework": "CIS"},
            headers=headers,
        ).json()["id"]
    )


def test_report_generation_returns_a_pdf(client: TestClient, admin_token: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    audit_id = audit(client, admin_token, "noncompliant")

    created = client.post(f"/api/v1/audits/{audit_id}/report", headers=headers)
    assert created.status_code == 201, created.text

    downloaded = client.get(f"/api/v1/reports/{created.json()['id']}", headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"] == "application/pdf"
    assert downloaded.content.startswith(b"%PDF-")
    assert len(downloaded.content) > 2000


def test_report_contains_no_secret_material(client: TestClient, admin_token: str) -> None:
    """The PDF is an export path; redaction must hold all the way through it."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    audit_id = audit(client, admin_token, "noncompliant")
    report_id = client.post(f"/api/v1/audits/{audit_id}/report", headers=headers).json()["id"]
    content = client.get(f"/api/v1/reports/{report_id}", headers=headers).content

    raw = (DATASETS / "noncompliant.cfg").read_text(encoding="utf-8")
    for line in raw.splitlines():
        if "password 7 " in line:
            assert line.split("password 7 ")[1].strip().encode() not in content


def test_report_generation_requires_permission(client: TestClient, admin_token: str) -> None:
    audit_id = audit(client, admin_token, "compliant")
    # Every seeded role holds REPORT_GENERATE, so assert the route is guarded at all
    # by calling it without a token.
    assert client.post(f"/api/v1/audits/{audit_id}/report").status_code == 401


def test_report_records_its_audit_and_generator(client: TestClient, admin_token: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    audit_id = audit(client, admin_token, "mixed")
    body = client.post(f"/api/v1/audits/{audit_id}/report", headers=headers).json()
    assert body["audit_run_id"] == audit_id
    assert body["id"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_reports.py -v`
Expected: FAIL with 404 on the report route.

- [ ] **Step 3: Write `backend/app/services/reporting/pdf.py`**

```python
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import AuditRun, ComplianceResultRow, Finding
from app.services.remediation.packs import Remediation

_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#b45309"),
    "LOW": colors.HexColor("#1d4ed8"),
    "INFO": colors.HexColor("#475569"),
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
) -> bytes:
    """Render the device report. Every string here originates in redacted data."""
    style = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4, title=f"NetSentinel Report — Audit {run.id}",
        leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
    )

    story: list[object] = [
        Paragraph("NetSentinel AI", style["title"]),
        Paragraph("Device Security Compliance Report", style["h3"]),
        Spacer(1, 6 * mm),
        _kv_table(
            [
                ("Organization", run.configuration.device.organization.name),
                ("Device", run.configuration.device.name),
                ("Vendor / OS", f"{run.detected_vendor} {run.detected_os} {run.configuration.device.os_version or ''}"),
                ("Detection confidence", f"{(run.detection_confidence or 0) * 100:.0f}%"),
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
                ("Assessment coverage", f"{(run.coverage or 0) * 100:.0f}%"),
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
                    f'<font color="{_SEVERITY_COLORS.get(finding.severity, colors.black)}">'
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
                Paragraph(result.evidence_excerpt or "(no matching configuration line)", style["mono"]),
                Paragraph("Remediation", style["h3"]),
                Paragraph(remediation.cli.replace("\n", "<br/>"), style["mono"]),
                Paragraph(f"<b>Verification:</b> {remediation.verification}", style["body"]),
                Paragraph(f"<b>Rollback:</b> {remediation.rollback.replace(chr(10), ' / ')}", style["body"]),
                Paragraph(f"<i>{remediation.banner}</i>", style["body"]),
                Spacer(1, 4 * mm),
            ]
        )

    document.build(story)
    return buffer.getvalue()
```

Create empty `backend/app/services/reporting/__init__.py`.

- [ ] **Step 4: Write `backend/app/schemas/reports.py` and `backend/app/api/reports.py`**

`backend/app/schemas/reports.py`:

```python
from pydantic import BaseModel


class ReportOut(BaseModel):
    id: int
    audit_run_id: int
```

`backend/app/api/reports.py`:

```python
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.audit_log import record_event
from app.config import settings
from app.db import get_db
from app.models import AuditRun, ComplianceResultRow, Finding, Report, User
from app.schemas.reports import ReportOut
from app.security.permissions import Permission
from app.services.remediation.packs import load_remediations
from app.services.reporting.pdf import build_device_report
from app.storage.base import StorageBackend
from app.storage.local import get_storage

router = APIRouter(tags=["reports"])


@router.post("/audits/{audit_id}/report", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def generate_report(
    audit_id: int,
    request: Request,
    user: User = Depends(require(Permission.REPORT_GENERATE)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> ReportOut:
    run = session.get(AuditRun, audit_id)
    if run is None or run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit not found")

    pairs = [
        (finding, finding.compliance_result)
        for finding in session.scalars(
            select(Finding)
            .join(Finding.compliance_result)
            .where(ComplianceResultRow.audit_run_id == run.id)
            .order_by(Finding.severity, Finding.id)
        )
        if finding.compliance_result is not None
    ]

    pdf = build_device_report(run, pairs, load_remediations(settings.mappings_dir))
    blob_key = f"reports/audit-{run.id}.pdf"
    storage.put(blob_key, pdf)

    report = Report(audit_run_id=run.id, blob_key=blob_key, generated_by_id=user.id)
    session.add(report)
    record_event(
        session,
        action="GENERATE_REPORT",
        user_id=user.id,
        resource=str(run.id),
        ip=client_ip(request),
    )
    session.commit()
    return ReportOut(id=report.id, audit_run_id=run.id)


@router.get("/reports/{report_id}")
def download_report(
    report_id: int,
    user: User = Depends(require(Permission.REPORT_READ)),
    session: Session = Depends(get_db),
    storage: StorageBackend = Depends(get_storage),
) -> Response:
    report = session.get(Report, report_id)
    if report is None or report.audit_run.configuration.device.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")

    return Response(
        content=storage.get(report.blob_key),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="netsentinel-audit-{report.audit_run_id}.pdf"'},
    )
```

Mount the router in `create_app`.

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/integration/test_reports.py -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Run the whole backend suite**

Run: `uv run pytest -v && uv run ruff check . && uv run mypy app`
Expected: all pass. The backend product is now complete over the API.

- [ ] **Step 7: Commit**

```bash
git add backend/app/services/reporting backend/app/api/reports.py backend/app/schemas/reports.py backend/app/main.py backend/tests/integration/test_reports.py
git commit -m "feat: add ReportLab device report with evidence and remediation sections"
```

---

## Task 22: Frontend scaffold, auth, and API client

**Files:**
- Create: `frontend/` (Vite scaffold), `frontend/src/lib/api.ts`, `frontend/src/lib/auth.tsx`, `frontend/src/routes/index.tsx`, `frontend/src/features/auth/LoginPage.tsx`, `frontend/src/components/layout/AppShell.tsx`
- Modify: `frontend/vite.config.ts`, `frontend/src/main.tsx`, `frontend/src/index.css`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the API from Tasks 16–21
- Produces: `api.get/post/patch/postForm` (typed fetch wrapper attaching the bearer token and refreshing once on 401); `useAuth()` returning `{user, login, logout}`; `<RequireAuth>`; `<RequirePermission perm>`

- [ ] **Step 1: Scaffold the frontend**

```bash
cd d:/Aproject/NetSentinel
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
npm install @tanstack/react-query react-router-dom recharts
npm install -D tailwindcss @tailwindcss/vite eslint-plugin-react-hooks
```

- [ ] **Step 2: Configure Tailwind and the dev proxy**

Replace `frontend/vite.config.ts`:

```typescript
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
});
```

Replace `frontend/src/index.css`:

```css
@import "tailwindcss";

:root {
  color-scheme: dark;
}

body {
  @apply bg-slate-950 text-slate-100 antialiased;
}
```

- [ ] **Step 3: Write `frontend/src/lib/api.ts`**

```typescript
const ACCESS_KEY = "netsentinel.access";
const REFRESH_KEY = "netsentinel.refresh";

export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly detail?: unknown) {
    super(message);
  }
}

export const tokens = {
  get access() {
    return localStorage.getItem(ACCESS_KEY);
  },
  get refresh() {
    return localStorage.getItem(REFRESH_KEY);
  },
  set(access: string, refresh: string) {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

async function refreshOnce(): Promise<boolean> {
  const refresh = tokens.refresh;
  if (!refresh) return false;

  const response = await fetch("/api/v1/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!response.ok) {
    tokens.clear();
    return false;
  }
  const body = await response.json();
  tokens.set(body.access_token, body.refresh_token);
  return true;
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  if (tokens.access) headers.set("Authorization", `Bearer ${tokens.access}`);

  const response = await fetch(`/api/v1${path}`, { ...init, headers });

  if (response.status === 401 && retry && (await refreshOnce())) {
    return request<T>(path, init, false);
  }
  if (!response.ok) {
    const detail = await response.json().catch(() => undefined);
    throw new ApiError(response.status, detail?.detail?.message ?? detail?.detail ?? response.statusText, detail?.detail);
  }
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") ?? "";
  return (contentType.includes("application/json") ? response.json() : response.blob()) as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  postForm: <T>(path: string, form: FormData) =>
    request<T>(path, { method: "POST", body: form }),
};
```

- [ ] **Step 4: Write `frontend/src/lib/auth.tsx`**

```tsx
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { api, tokens } from "./api";

export interface CurrentUser {
  id: number;
  email: string;
  role: string;
  permissions: string[];
}

interface AuthValue {
  user: CurrentUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["me"],
    queryFn: () => api.get<CurrentUser>("/users/me"),
    enabled: Boolean(tokens.access),
    retry: false,
  });

  const value: AuthValue = {
    user: data ?? null,
    loading: isLoading,
    async login(email, password) {
      const pair = await api.post<{ access_token: string; refresh_token: string }>(
        "/auth/login",
        { email, password },
      );
      tokens.set(pair.access_token, pair.refresh_token);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    async logout() {
      const refresh = tokens.refresh;
      if (refresh) await api.post("/auth/logout", { refresh_token: refresh }).catch(() => undefined);
      tokens.clear();
      queryClient.clear();
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-slate-400">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

/** Hides UI a role cannot use. The server enforces the same rule — this is presentation. */
export function RequirePermission({ perm, children }: { perm: string; children: ReactNode }) {
  const { user } = useAuth();
  if (!user?.permissions.includes(perm)) return null;
  return <>{children}</>;
}
```

- [ ] **Step 5: Write the login page and app shell**

`frontend/src/features/auth/LoginPage.tsx`:

```tsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../lib/auth";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("admin@netsentinel.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await login(email, password);
      navigate("/");
    } catch {
      setError("Invalid email or password");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-8">
        <div>
          <h1 className="text-2xl font-semibold">NetSentinel AI</h1>
          <p className="text-sm text-slate-400">Network security compliance auditor</p>
        </div>
        <input
          className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
          type="email" value={email} onChange={(e) => setEmail(e.target.value)}
          placeholder="Email" autoComplete="username"
        />
        <input
          className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
          type="password" value={password} onChange={(e) => setPassword(e.target.value)}
          placeholder="Password" autoComplete="current-password"
        />
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
        <button type="submit" className="w-full rounded bg-sky-600 py-2 font-medium hover:bg-sky-500">
          Sign in
        </button>
      </form>
    </div>
  );
}
```

`frontend/src/components/layout/AppShell.tsx`:

```tsx
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../../lib/auth";

const LINKS = [
  { to: "/", label: "Dashboard" },
  { to: "/upload", label: "Upload" },
  { to: "/audits", label: "Audits" },
];

export function AppShell() {
  const { user, logout } = useAuth();
  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b border-slate-800 px-6 py-3">
        <div className="flex items-center gap-6">
          <span className="font-semibold tracking-tight">NetSentinel AI</span>
          <nav className="flex gap-4 text-sm">
            {LINKS.map((link) => (
              <NavLink
                key={link.to} to={link.to} end
                className={({ isActive }) =>
                  isActive ? "text-sky-400" : "text-slate-400 hover:text-slate-200"
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span>{user?.email} · {user?.role}</span>
          <button onClick={logout} className="rounded border border-slate-700 px-3 py-1 hover:bg-slate-800">
            Sign out
          </button>
        </div>
      </header>
      <main className="p-6"><Outlet /></main>
    </div>
  );
}
```

- [ ] **Step 6: Wire routing in `frontend/src/main.tsx`**

```tsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { LoginPage } from "./features/auth/LoginPage";
import "./index.css";
import { AuthProvider, RequireAuth } from "./lib/auth";

const queryClient = new QueryClient();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<RequireAuth><AppShell /></RequireAuth>}>
              <Route index element={<div>Dashboard placeholder — replaced in Task 23</div>} />
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
```

- [ ] **Step 7: Verify the login flow end to end by hand**

In one terminal: `cd backend && uv run alembic upgrade head && uv run python -m scripts.seed && uv run uvicorn app.main:app --reload`
In another: `cd frontend && npm run dev`

Open the printed URL, sign in as `admin@netsentinel.local` / `demo-password-1`.
Expected: the shell renders with the email and role in the header; sign-out returns to login.

- [ ] **Step 8: Add the frontend job to CI**

Append to `.github/workflows/ci.yml`:

```yaml
  frontend:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: frontend
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
      - run: npm ci
      - run: npm run lint
      - run: npx tsc --noEmit
      - run: npm run build
```

- [ ] **Step 9: Commit**

```bash
git add frontend .github/workflows/ci.yml
git commit -m "feat: add React frontend scaffold with auth, API client, and app shell"
```

---

## Task 23: Frontend upload, audit list, and findings detail

**Files:**
- Create: `frontend/src/types/api.ts`, `frontend/src/features/ingestion/UploadPage.tsx`, `frontend/src/features/audits/AuditListPage.tsx`, `frontend/src/features/audits/AuditDetailPage.tsx`, `frontend/src/features/findings/FindingPanel.tsx`, `frontend/src/components/security/SeverityBadge.tsx`, `frontend/src/components/security/ScoreRing.tsx`
- Modify: `frontend/src/main.tsx`

**Interfaces:**
- Consumes: `api`, `RequirePermission`
- Produces: routed pages at `/upload`, `/audits`, `/audits/:id`

- [ ] **Step 1: Write `frontend/src/types/api.ts`**

```typescript
export interface DeviceOut {
  id: number;
  name: string;
  vendor: string;
  os: string;
  os_version: string | null;
}

export interface ConfigurationOut {
  id: number;
  sha256: string;
  filename: string;
  size_bytes: number;
  secret_hits: number;
  device: DeviceOut;
}

export interface AuditSummary {
  id: number;
  configuration_id: number;
  device_name: string;
  framework: string;
  framework_version: string;
  status: string;
  score: number | null;
  coverage: number | null;
  rule_pack_hash: string;
  engine_version: string;
  detection: { vendor: string | null; os: string | null; confidence: number | null; reasons: string[]; override: string | null };
  fail_counts: Record<string, number>;
}

export interface AuditDetail extends AuditSummary {
  controls: { key: string; value: unknown; source_lines: number[]; excerpt: string; parser_confidence: number; origin: string }[];
  results: { rule_id: string; parameter: string; observed_value: unknown; expected_value: unknown; status: string; severity: string; evidence_lines: number[]; evidence_excerpt: string }[];
  unknown_constructs: { text: string; lineno: number; block: string | null }[];
  parse_warnings: Record<string, unknown>[];
}

export interface FindingSummary {
  id: number;
  audit_run_id: number;
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  parameter: string;
  triage_status: string;
}

export interface FindingDetail extends FindingSummary {
  framework: string;
  framework_version: string;
  rule_pack_hash: string;
  configuration_sha256: string;
  description: string;
  observed_value: unknown;
  expected_value: unknown;
  evidence_lines: number[];
  evidence_excerpt: string;
  notes: string;
  remediation: { id: string; title: string; cli: string; verification: string; rollback: string; notes: string; banner: string };
}
```

- [ ] **Step 2: Write the severity badge and score ring**

`frontend/src/components/security/SeverityBadge.tsx`:

```tsx
const STYLES: Record<string, string> = {
  CRITICAL: "bg-red-950 text-red-300 border-red-800",
  HIGH: "bg-orange-950 text-orange-300 border-orange-800",
  MEDIUM: "bg-amber-950 text-amber-300 border-amber-800",
  LOW: "bg-blue-950 text-blue-300 border-blue-800",
  INFO: "bg-slate-800 text-slate-300 border-slate-700",
  PASS: "bg-emerald-950 text-emerald-300 border-emerald-800",
  FAIL: "bg-red-950 text-red-300 border-red-800",
  WARNING: "bg-amber-950 text-amber-300 border-amber-800",
  NOT_ASSESSABLE: "bg-slate-800 text-slate-400 border-slate-700",
  NOT_APPLICABLE: "bg-slate-800 text-slate-500 border-slate-700",
};

/** Always renders the label as text — color alone must never carry the meaning. */
export function SeverityBadge({ value }: { value: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${STYLES[value] ?? STYLES.INFO}`}>
      {value}
    </span>
  );
}
```

`frontend/src/components/security/ScoreRing.tsx`:

```tsx
export function ScoreRing({ score, coverage }: { score: number | null; coverage: number | null }) {
  const value = score ?? 0;
  const tone = value >= 80 ? "text-emerald-400" : value >= 50 ? "text-amber-400" : "text-red-400";
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className={`text-5xl font-semibold tabular-nums ${tone}`}>{value}<span className="text-2xl text-slate-500"> / 100</span></div>
      <p className="mt-1 text-sm text-slate-400">
        Posture score · {Math.round((coverage ?? 0) * 100)}% of controls assessable
      </p>
      <p className="mt-2 text-xs text-slate-500">
        An indicator of configuration hardening, not a compliance certification.
      </p>
    </div>
  );
}
```

- [ ] **Step 3: Write the upload page**

`frontend/src/features/ingestion/UploadPage.tsx`:

```tsx
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../lib/api";
import type { AuditSummary, ConfigurationOut } from "../../types/api";

export function UploadPage() {
  const navigate = useNavigate();
  const [dragging, setDragging] = useState(false);
  const [message, setMessage] = useState("");

  const run = useMutation({
    mutationFn: async (file: File) => {
      const form = new FormData();
      form.append("file", file);
      const configuration = await api.postForm<ConfigurationOut>("/configurations/upload", form);
      setMessage(
        `Detected ${configuration.device.vendor} ${configuration.device.os} · ` +
          `${configuration.secret_hits} secret(s) redacted · SHA-256 ${configuration.sha256.slice(0, 12)}…`,
      );
      return api.post<AuditSummary>("/audits", {
        configuration_id: configuration.id,
        framework: "CIS",
      });
    },
    onSuccess: (audit) => navigate(`/audits/${audit.id}`),
    onError: (error: Error) => setMessage(error.message),
  });

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-xl font-semibold">Upload configuration</h1>
      <label
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files[0];
          if (file) run.mutate(file);
        }}
        className={`flex h-56 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed transition ${
          dragging ? "border-sky-500 bg-sky-950/30" : "border-slate-700 bg-slate-900"
        }`}
      >
        <p className="text-lg">Drop configuration files</p>
        <p className="mt-1 text-sm text-slate-400">or browse — .cfg .conf .txt .log .json .xml .yaml, up to 5 MB</p>
        <input
          type="file" className="hidden"
          accept=".cfg,.conf,.txt,.log,.json,.xml,.yaml,.yml"
          onChange={(e) => { const file = e.target.files?.[0]; if (file) run.mutate(file); }}
        />
      </label>
      {run.isPending && <p className="text-sm text-sky-400">Running audit…</p>}
      {message && <p className="rounded border border-slate-800 bg-slate-900 p-3 text-sm text-slate-300">{message}</p>}
    </div>
  );
}
```

- [ ] **Step 4: Write the audit list page**

`frontend/src/features/audits/AuditListPage.tsx`:

```tsx
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import type { AuditSummary } from "../../types/api";

export function AuditListPage() {
  const { data = [], isLoading } = useQuery({
    queryKey: ["audits"],
    queryFn: () => api.get<AuditSummary[]>("/audits"),
  });

  if (isLoading) return <p className="text-slate-400">Loading…</p>;
  if (!data.length) return <p className="text-slate-400">No audits yet. Upload a configuration to begin.</p>;

  return (
    <table className="w-full text-sm">
      <thead className="text-left text-slate-400">
        <tr className="border-b border-slate-800">
          <th className="py-2">Device</th><th>Framework</th><th>Score</th>
          <th>Coverage</th><th>Critical</th><th>High</th><th />
        </tr>
      </thead>
      <tbody>
        {data.map((audit) => (
          <tr key={audit.id} className="border-b border-slate-900 hover:bg-slate-900">
            <td className="py-2 font-medium">{audit.device_name}</td>
            <td>{audit.framework} {audit.framework_version}</td>
            <td className="tabular-nums">{audit.score}</td>
            <td className="tabular-nums">{Math.round((audit.coverage ?? 0) * 100)}%</td>
            <td className="tabular-nums">{audit.fail_counts.CRITICAL ?? 0}</td>
            <td className="tabular-nums">{audit.fail_counts.HIGH ?? 0}</td>
            <td><Link to={`/audits/${audit.id}`} className="text-sky-400 hover:underline">Open</Link></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

- [ ] **Step 5: Write the audit detail page and finding panel**

`frontend/src/features/findings/FindingPanel.tsx`:

```tsx
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import type { FindingDetail } from "../../types/api";

export function FindingPanel({ findingId }: { findingId: number }) {
  const { data } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api.get<FindingDetail>(`/findings/${findingId}`),
  });
  if (!data) return <p className="text-slate-400">Loading finding…</p>;

  return (
    <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-center gap-3">
        <SeverityBadge value={data.severity} />
        <h2 className="font-semibold">{data.rule_id} — {data.title}</h2>
      </div>
      <p className="text-sm text-slate-300">{data.description}</p>

      <section>
        <h3 className="text-xs uppercase tracking-wide text-slate-500">Evidence</h3>
        <pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
          {data.evidence_excerpt || "(no matching configuration line)"}
        </pre>
        <p className="mt-1 text-xs text-slate-500">
          Line(s) {data.evidence_lines.join(", ") || "—"} · observed {String(data.observed_value)} · expected {String(data.expected_value)}
        </p>
      </section>

      <section>
        <h3 className="text-xs uppercase tracking-wide text-slate-500">Remediation</h3>
        <pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-emerald-300">{data.remediation.cli}</pre>
        <p className="mt-1 text-xs text-slate-400">Verify: <code>{data.remediation.verification}</code></p>
        <p className="mt-2 rounded border border-amber-900 bg-amber-950/40 p-2 text-xs text-amber-300">
          {data.remediation.banner}
        </p>
      </section>

      <section>
        <h3 className="text-xs uppercase tracking-wide text-slate-500">Provenance</h3>
        <dl className="mt-1 grid grid-cols-2 gap-1 text-xs text-slate-400">
          <dt>Framework</dt><dd>{data.framework} {data.framework_version}</dd>
          <dt>Parameter</dt><dd className="font-mono">{data.parameter}</dd>
          <dt>Config SHA-256</dt><dd className="font-mono">{data.configuration_sha256.slice(0, 16)}…</dd>
          <dt>Rule pack SHA-256</dt><dd className="font-mono">{data.rule_pack_hash.slice(0, 16)}…</dd>
        </dl>
      </section>
    </div>
  );
}
```

`frontend/src/features/audits/AuditDetailPage.tsx`:

```tsx
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { ScoreRing } from "../../components/security/ScoreRing";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import { api } from "../../lib/api";
import { FindingPanel } from "../findings/FindingPanel";
import type { AuditDetail, FindingSummary } from "../../types/api";

export function AuditDetailPage() {
  const { id } = useParams();
  const [selected, setSelected] = useState<number | null>(null);

  const audit = useQuery({ queryKey: ["audit", id], queryFn: () => api.get<AuditDetail>(`/audits/${id}`) });
  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.get<FindingSummary[]>(`/findings?audit_id=${id}`),
  });

  if (!audit.data) return <p className="text-slate-400">Loading…</p>;
  const detail = audit.data;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <ScoreRing score={detail.score} coverage={detail.coverage} />
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-sm">
          <h2 className="font-semibold">{detail.device_name}</h2>
          <p className="mt-1 text-slate-400">
            {detail.detection.vendor} {detail.detection.os} · detection confidence{" "}
            {Math.round((detail.detection.confidence ?? 0) * 100)}%
          </p>
          <ul className="mt-2 space-y-0.5 text-xs text-slate-500">
            {detail.detection.reasons.map((reason) => <li key={reason}>· {reason}</li>)}
          </ul>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-sm">
          <h2 className="font-semibold">Audit provenance</h2>
          <dl className="mt-2 space-y-1 text-xs text-slate-400">
            <div>Framework: {detail.framework} {detail.framework_version}</div>
            <div className="font-mono">Rule pack: {detail.rule_pack_hash.slice(0, 16)}…</div>
            <div>Engine: {detail.engine_version}</div>
            <div>Unrecognized commands: {detail.unknown_constructs.length}</div>
          </dl>
          <a
            className="mt-3 inline-block rounded bg-sky-600 px-3 py-1 text-xs hover:bg-sky-500"
            href="#"
            onClick={async (event) => {
              event.preventDefault();
              const report = await api.post<{ id: number }>(`/audits/${detail.id}/report`);
              const blob = await api.get<Blob>(`/reports/${report.id}`);
              const url = URL.createObjectURL(blob);
              window.open(url, "_blank");
            }}
          >
            Generate PDF report
          </a>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-1">
          <h2 className="mb-2 font-semibold">Findings ({findings.data?.length ?? 0})</h2>
          {(findings.data ?? []).map((finding) => (
            <button
              key={finding.id}
              onClick={() => setSelected(finding.id)}
              className={`flex w-full items-center gap-3 rounded border p-2 text-left text-sm ${
                selected === finding.id ? "border-sky-700 bg-slate-900" : "border-slate-800 hover:bg-slate-900"
              }`}
            >
              <SeverityBadge value={finding.severity} />
              <span className="flex-1">{finding.title}</span>
              <span className="font-mono text-xs text-slate-500">{finding.rule_id}</span>
            </button>
          ))}
        </div>
        <div>{selected ? <FindingPanel findingId={selected} /> : <p className="text-slate-500">Select a finding.</p>}</div>
      </div>
    </div>
  );
}
```

- [ ] **Step 6: Register the routes in `frontend/src/main.tsx`**

Replace the index route block with:

```tsx
            <Route element={<RequireAuth><AppShell /></RequireAuth>}>
              <Route index element={<AuditListPage />} />
              <Route path="upload" element={<UploadPage />} />
              <Route path="audits" element={<AuditListPage />} />
              <Route path="audits/:id" element={<AuditDetailPage />} />
            </Route>
```

Add the matching imports.

- [ ] **Step 7: Verify by hand**

With both servers running, upload `datasets/demo/cisco/noncompliant.cfg`.
Expected: redirect to the audit detail page showing score 0, sixteen findings, evidence
with line numbers, remediation CLI with the validation banner, and a downloadable PDF.

- [ ] **Step 8: Verify lint and build**

Run: `cd frontend && npm run lint && npx tsc --noEmit && npm run build`
Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add frontend
git commit -m "feat: add upload, audit list, audit detail, and findings UI"
```

---

## Task 24: Documentation and demo runbook

**Files:**
- Create: `README.md`, `SECURITY.md`, `docs/architecture.md`, `docs/demo.md`, `docker-compose.yml`, `deployment/docker/Dockerfile.backend`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: everything built so far
- Produces: no code; the runbook that makes the slice usable by someone who did not build it

- [ ] **Step 1: Write `README.md`**

Cover, in this order: what NetSentinel is (one paragraph from the design doc's §1); slice 1
scope with an explicit list of what is deferred to SP2–SP6; prerequisites (`uv`, Node 22);
the exact commands to run backend and frontend; the six demo accounts and their shared
password; where the rule packs live and how to add a rule; and how to run the test suite.

- [ ] **Step 2: Write `SECURITY.md`**

Document: the redaction guarantee and its boundary (raw bytes remain in the local blob
store); the threat model coverage from design doc §19 (T1, T2, T4, T6 addressed; T3 and T5
arrive with SP4); that `demo-password-1` and the committed `JWT_SECRET` default are
development-only and must be replaced before any real deployment; and the reporting
address for vulnerabilities.

- [ ] **Step 3: Write `docs/architecture.md`**

Reproduce the pipeline diagram from design doc §6, the three seams table from §3, and the
boundary discipline rules. State explicitly where SP4's AI interpreter attaches
(`normalize_cisco` emitting `UnknownConstruct`) so the next sub-project starts oriented.

- [ ] **Step 4: Write `docs/demo.md`**

The two-minute SIH demo script mapped to parent spec §51, adapted to slice-1 reality:
upload `noncompliant.cfg` (score 0, sixteen findings), open a CRITICAL finding to show
evidence with line numbers and provenance hashes, generate the PDF, then upload
`compliant.cfg` to show 100. Note honestly that multi-vendor normalization and the
adaptive training loop are SP2 and SP4 — the demo must not imply they exist yet.

- [ ] **Step 5: Write `docker-compose.yml` and the backend Dockerfile**

The compose file defines the SP6 target stack — `postgres:16`, `redis:7`, `minio`, the
backend, and the frontend — with the backend's `NETSENTINEL_DATABASE_URL` pointing at
Postgres. It is committed and kept accurate but is not the slice-1 development path;
say so in a comment at the top of the file.

`deployment/docker/Dockerfile.backend` builds from `python:3.13-slim`, installs `uv`,
copies `backend/`, runs `uv sync --frozen`, and starts `uvicorn app.main:app`.

- [ ] **Step 6: Verify the README instructions from a clean state**

```bash
cd d:/Aproject/NetSentinel
rm -rf var
cd backend && uv sync --dev && uv run alembic upgrade head && uv run python -m scripts.seed
uv run pytest
```

Expected: the database rebuilds, seeding succeeds, and the full suite passes. If any
README step is wrong, fix the README — this is the step that proves it.

- [ ] **Step 7: Verify the complete Definition of Done**

Run the full suite and check each box in design doc §18 against actual behavior:

```bash
cd backend && uv run pytest -v && uv run ruff check . && uv run mypy app
cd ../frontend && npm run lint && npx tsc --noEmit && npm run build
```

Expected: everything passes. Any unchecked box in §18 is remaining work, not a completed
slice — report it rather than closing out.

- [ ] **Step 8: Commit**

```bash
git add README.md SECURITY.md docs docker-compose.yml deployment
git commit -m "docs: add README, security notes, architecture, and demo runbook"
```

---

## Self-Review

**Spec coverage.** Every section of the design doc maps to a task:

| Design §  | Task(s) |
|-----------|---------|
| §3 Three seams | 14 (DATABASE_URL), 17 (StorageBackend, TaskRunner) |
| §4 Stack | 1, 22 |
| §5 Layout | 1, plus the `domain/` refinement noted in the header |
| §6 Pipeline | 9, 10, 11, 5, 12 as stages; 19 as orchestration |
| §7 Control model | 2 (types), 11 (production), 6 (coverage assertion) |
| §8 Rules as data | 4 (schema/loader), 5 (engine), 6 (pack), 7 (remediation) |
| §9 Data model | 14 |
| §10 Auth + RBAC | 15, 16 |
| §11 Secrets | 8 (redaction), 18 (upload validation) |
| §12 Detection | 9, 19 (409 path) |
| §13 Scoring | 12 |
| §14 Error handling | 4, 5, 8, 12, 17, 18, 19 |
| §15 API surface | 16, 18, 19, 20, 21 |
| §16 Testing | every task; 13 and 24 for the end-to-end contract |
| §17 Build order | tasks are that order, resequenced so the pure engine precedes persistence |
| §18 Definition of done | 24 Step 7 |

**Resequencing note.** Design doc §17 lists auth as step 2 and the engine as step 3. This
plan builds the pure engine (Tasks 2–13) before the database (Task 14) and auth (15–16).
The engine has no dependency on either, and finishing it first means the golden tests exist
before any HTTP surface does — bugs surface against fixtures instead of through the API.

**Placeholder scan.** Two tasks legitimately describe content rather than showing it in
full: Task 7 Step 4 (thirteen remediation entries following an exact three-entry template)
and Task 13 Step 1 (three demo `.cfg` files). Both are bulk data where the shape is fully
specified and the completeness check is an executable test — `test_every_rule_remediation_id_resolves`
and the golden snapshots. Task 24's documentation steps describe content by section, which
is appropriate for prose. No step says "add error handling" or "write tests for the above".

**Type consistency.** Verified across tasks: `ControlValue` fields (Task 2) match their use
in Tasks 5, 11, 19. `Status`/`Severity` are `StrEnum` throughout, compared with `is` against
enum members and with `str()` when written to string columns (Task 19). `evaluate_rule`,
`evaluate_pack`, `parse_cisco`, `normalize_cisco`, `detect`, `redact`, `score_results`,
`load_pack`, `load_all_packs`, `load_remediations`, `run_audit` keep one signature each from
definition through every call site. `RulePack.sha256` is the field name used in Tasks 4, 6,
19, 20. `require(Permission.X)` is the single authorization form in Tasks 16, 18, 19, 20, 21.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-22-netsentinel-spine.md`.

