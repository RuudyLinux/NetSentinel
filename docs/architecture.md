# Architecture — Slice 1 (the spine)

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
        │
        ▼
   Parser ───────────► ConfigTree(nodes with line numbers) + ParseWarning[]
        │
        ▼
   Normalizer ───────► ControlSet{key: ControlValue} + UnknownConstruct[]
        │
        ▼
   RuleEngine ───────► ComplianceResult[] (rules loaded from versioned YAML packs)
        │
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
which calls the stages in order and writes results in one transaction.

This is what keeps vendor and framework additions cheap: the parser knows Cisco syntax
and nothing about CIS; the rule engine knows CIS and nothing about Cisco. Adding a
vendor touches `app/services/detection/` and `app/services/parsing/` only. Adding a
framework touches `rules/` only — which is data, not code.

**Where SP4 attaches.** When the normalizer (`app/services/normalization/cisco.py`)
meets syntax it cannot map to a control, it records an `UnknownConstruct` and continues
rather than failing the audit. In slice 1 these are counted and surfaced in the audit
response (`unknown_constructs`), and are otherwise inert. SP4's AI interpreter and
Training Center attach at exactly this one point — the normalizer's unmapped-construct
path — with no change required to any other stage.

## The three environment seams

The development environment has no Docker and the parent spec assumes Postgres, Redis,
MinIO, and Celery in containers. Slice 1 binds three named seams to local
implementations instead, so adopting the containerized stack later is a configuration
change plus one new class each — never a rewrite of calling code.

| Seam | Slice 1 binding | Target (SP6) binding | Cost of switch |
|------|-----------------|------------------------|----------------|
| `DATABASE_URL` | `sqlite:///./var/netsentinel.db` | `postgresql+psycopg://…` | Env var + Alembic run |
| `StorageBackend` | `LocalFileStorage` (`./var/blobs/`) | `S3Storage` (MinIO/S3) | One class, ~60 lines |
| `TaskRunner` | `InlineTaskRunner` (BackgroundTasks) | `CeleryTaskRunner` | One class, ~40 lines |

`docker-compose.yml` at the repo root defines the SP6 target stack today and is kept
accurate even while unused in slice 1 development.

## Boundary discipline

- No SQLite-specific SQL anywhere in application code
- No raw file paths outside `LocalFileStorage`
- No `BackgroundTasks` import outside `InlineTaskRunner`
- Every model uses SQLAlchemy types that map cleanly to both SQLite and PostgreSQL

These rules are what make the seam table above true rather than aspirational — violate
any of them and the "one class, ~N lines" switch cost stops holding.

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

`origin` is `"deterministic"` throughout slice 1; `"inferred"`/`"learned"` exist so SP4
can populate them without a schema migration. A control key absent from the
`ControlSet` means "the parser did not observe this"; present with `value=None` means
"observed and explicitly unset" — the rule engine treats both as `NOT_ASSESSABLE`,
never as a pass. See `backend/app/domain/device.py` and
`backend/app/services/normalization/cisco.py` for the sixteen control keys.
