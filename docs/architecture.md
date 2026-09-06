# Architecture

## Pipeline

```text
POST /configurations/upload
        │
        ▼
   Sanitizer ────────► validate ext/size · detect secrets · redact · SHA-256 · store blob
        │
        ▼  RedactedConfig(text, sha256, blob_key, secret_hits)
        │
POST /audits
        │
        ▼
   Detector ─────────► DeviceIdentity(vendor, os, version, confidence, reasons)
        │              pluggable — services/detection/registry.py
        ▼
   Parser ───────────► ConfigTree(nodes with line numbers) + ParseWarning[]
        │              pluggable — services/parsing/registry.py
        ▼
   Normalizer ───────► ControlSet{key: ControlValue} + UnknownConstruct[]
        │              pluggable — services/normalization/registry.py
        ▼
   RuleEngine ───────► ComplianceResult[] (rules loaded from versioned YAML packs;
        │               vendor-agnostic — never branches on vendor, only on
        │               Rule.applicability)
        ▼
   FindingBuilder ───► Finding[] (FAIL/WARNING only, + remediation lookup)
        │
        ▼
   Scorer ───────────► PostureScore(score, coverage, severity counts)
        │
        ▼
   ReportBuilder ────► PDF (on demand, POST /audits/{id}/report)
```

Every stage is a pure function from the previous stage's typed output to its own. No
stage opens a database session, reads a file, or makes an HTTP call. Persistence and
orchestration live exclusively in `backend/app/services/audit/runner.py`
(`run_audit(session, storage, configuration, framework, vendor_override) -> AuditRun`),
which calls the stages in order and writes results in one transaction. It writes the
`AuditRun` row as `status="running"` before parsing starts and updates it to
`"completed"` or `"failed"` (with the error message attached) once the pipeline stages
finish or raise — a failure is never silently lost, and it's never presented as a
successful audit. `run_audit` has zero FastAPI import; it's callable directly from a
script or a test, not only from an HTTP route (see `tests/unit/test_audit_runner.py`).

This is what keeps vendor and framework additions cheap: a parser knows one vendor's
syntax and nothing about any rule framework; the rule engine knows a framework's rules
and nothing about vendor syntax. Adding a vendor means implementing a detector, parser,
and normalizer and registering them in the three `services/*/registry.py` files —
Cisco and FortiOS are registered today. Adding a framework touches `rules/` only, which
is data, not code — CIS (Cisco, FortiOS) and NIST SP 800-53 Rev. 5 (mapped onto the same
normalized controls Cisco's normalizer already produces) are loaded today.

**Where the AI interpreter attaches.** When a normalizer meets syntax it cannot map to a
control, it records an `UnknownConstruct` and continues rather than failing the audit.
These are counted and surfaced in the audit response (`unknown_constructs`), and
otherwise inert until a human asks for an AI interpretation of one (see "AI safety
model" below) — no change is required to any other stage for that to work.

## AI safety model

```text
Unknown configuration construct
        │
        ▼
Sent to the LLM wrapped in explicit untrusted-data delimiters
(<<<UNTRUSTED_CONFIG_LINE>>> ... <<<END_UNTRUSTED_CONFIG_LINE>>>), with the
system prompt instructing the model to treat that content as data, never as
instructions (see services/ai/client.py)
        │
        ▼
Strict JSON response required
        │
        ▼
suggested_parameter validated against the fixed CONTROL_KEYS vocabulary —
anything else is dropped regardless of the model's claimed confidence
        │
        ▼
confidence clamped to [0, 1]; interpretation text length-capped and
control-character-stripped before storage
        │
        ▼
Stored as a pending AiInterpretation row
        │
        ▼
A human with MAPPING_APPROVE reviews it (approve/reject)
        │
        ▼
Recorded for the audit trail — and nothing else. No code path reads
AiInterpretation.status to change a ComplianceResult, a Rule, a Finding,
device configuration, or remediation execution.
```

This is the one architectural invariant this project cannot ever compromise on:
**the deterministic rule engine is the sole authority on PASS / FAIL / WARNING /
NOT_ASSESSABLE / NOT_APPLICABLE.** `tests/unit/test_prompt_injection.py` and
`tests/unit/test_ai_client.py` exist specifically to keep this true — they simulate
malicious configuration text (prompt-injection attempts) and a cooperating malicious
LLM response, and assert the pipeline stays safe regardless of what the model says.

## The three environment seams

Local development runs everything directly (no Docker). `docker-compose.yml` boots
the containerized target instead — Postgres and MinIO are real and wired today; the
task queue is not. Two of these three seams are a configuration change away from
their target binding; the third needs a design decision first, not just code.

| Seam | Local dev binding | Containerized binding | Status |
|------|-----------------|------------------------|----------------|
| `DATABASE_URL` | `sqlite:///./var/netsentinel.db` | `postgresql+psycopg://…` (`docker-compose.yml`) | **Wired.** `psycopg` is a real dependency, Alembic's migrations target both dialects (`app/db.py` has zero SQLite-specific SQL). CI runs the test suite against SQLite only — run `docker compose up` to exercise it against a live Postgres. |
| `StorageBackend` | `LocalFileStorage` (`./var/blobs/`) | `S3Storage` (`app/storage/s3.py`) — S3 or any S3-compatible endpoint, e.g. MinIO | **Wired.** Selected via `NETSENTINEL_STORAGE_BACKEND=s3` (`app/storage/registry.py`); self-provisions its bucket the same way `LocalFileStorage` self-creates its directory. |
| `TaskRunner` | `InlineTaskRunner` (calls the function directly) | `CeleryTaskRunner` | **Not wired** — see below. Redis runs in `docker-compose.yml` as a documented future seam; nothing reads from it yet. |

`TaskRunner` (`app/tasks/{base,inline}.py`) is not currently wired into the audit route
— `run_audit` is invoked directly from `api/audits.py`. The audit service being callable
independently of FastAPI already satisfies the actual goal ("swap in Celery later
without touching the API"); wiring the seam in for real additionally requires deciding
how a deferred call hands back the finished `AuditRun` the way today's synchronous HTTP
response does, which is a bigger, separate decision than routing through the seam alone
would solve.

## Boundary discipline

- No SQLite-specific SQL anywhere in application code
- No raw file paths outside `LocalFileStorage`
- No vendor name (`if vendor == "cisco"`-style branching) anywhere outside
  `services/{detection,parsing,normalization}/<vendor>.py` and the vendor's own
  rule/remediation YAML
- Every model uses SQLAlchemy types that map cleanly to both SQLite and PostgreSQL

These rules are what make the seam table above true rather than aspirational — violate
any of them and the "one class" switch cost stops holding.

## Universal Security Control Model

Every normalized fact carries provenance, not just a value — each finding must trace
back to specific configuration lines:

```python
@dataclass(frozen=True)
class ControlValue:
    value: bool | int | str | list[str] | None
    source_lines: list[int]      # 1-indexed lines in the redacted config
    excerpt: str                 # redacted configuration text that produced this value
    parser_confidence: float     # 1.0 for deterministic parsing
    origin: Literal["deterministic", "inferred", "learned"]
```

`origin` is `"deterministic"` throughout the current implementation;
`"inferred"`/`"learned"` exist so a future adaptive-mapping loop can populate them
without a schema migration. A control key absent from the `ControlSet` means "the
parser did not observe this"; present with `value=None` means "observed and explicitly
unset" — the rule engine treats both as `NOT_ASSESSABLE`, never as a pass. See
`backend/app/domain/controls.py` for the sixteen control keys, and
`backend/app/services/normalization/{cisco,fortinet}.py` for how each vendor populates
them — FortiOS deliberately leaves three keys unpopulated (no clean FortiOS analog
exists) rather than stretching a mapping to fit; a rule targeting one of those against a
FortiOS device correctly reads `NOT_ASSESSABLE`, never a fabricated pass or fail.

## Security model

- **Passwords**: Argon2id (`app/security/passwords.py`).
- **Tokens**: short-lived JWT access tokens; refresh tokens are rotated on every use,
  stored only as a SHA-256 hash, and grouped into a `family_id` — replaying an
  already-rotated refresh token burns the entire family (assume theft, not a race).
- **Production JWT secret**: `create_app()` (`app/main.py`) fails startup if
  `NETSENTINEL_ENVIRONMENT=production` and the JWT secret is missing, the known
  development default, or shorter than 32 bytes. Development and test environments
  tolerate the default so local setup stays simple.
- **Password reset**: a real single-use, short-lived, hashed token
  (`PasswordResetToken`) issued by `/auth/forgot-password`; the response is identical
  whether or not the account exists. `/auth/reset-password` consumes it, revokes every
  refresh token for that user, and is single-use even within its expiry window. No
  email/SMS provider is wired in yet — the token is logged
  (`app/security/reset_delivery.py`), which is a real, documented limitation, not a
  hidden one.
- **Organization isolation**: every resource-by-ID endpoint checks the resource's
  organization against the caller's before returning anything, returning 404 (not 403)
  on a mismatch to avoid leaking existence. This is currently correct everywhere but
  implemented by hand per endpoint, not centrally enforced — the second-organization
  fixture in `tests/integration/conftest.py` and the regression suite in
  `tests/integration/test_organization_isolation.py` exist so a future refactor that
  drops one of those checks gets caught immediately instead of silently.
- **Secret redaction**: happens before anything is persisted and before any text
  reaches an AI provider (`app/services/ingestion/upload.py`). Covers Cisco (enable
  secrets, passwords, SNMP community strings, TACACS+/RADIUS/ISAKMP keys, SNMPv3
  auth/priv keys, PEM private keys) and FortiOS (admin/PSK/SNMP passwords) directives.
  It is line-based, not block-aware, which is a known limitation for the rare case
  where a vendor reuses a generic field name (e.g. FortiOS's SNMP community "name")
  for both secret and non-secret purposes in different contexts.

## Testing

- **Unit** (`backend/tests/unit/`): parsing, normalization, detection, redaction,
  scoring, the rule engine, and — via `test_rule_packs_self_test.py` — every rule in
  every loaded pack proving its own inline PASS/FAIL/NOT_ASSESSABLE truth table against
  the real engine.
- **Integration** (`backend/tests/integration/`): full API flows including auth,
  cross-organization isolation, AI review, and reporting.
- **Golden** (`backend/tests/golden/`): end-to-end pipeline snapshots against
  representative configurations for each supported vendor, so a change that silently
  alters compliance behavior fails a test instead of shipping unnoticed.

Run `uv run pytest --cov=app --cov-report=term-missing` from `backend/` for the full
suite with a coverage report.
