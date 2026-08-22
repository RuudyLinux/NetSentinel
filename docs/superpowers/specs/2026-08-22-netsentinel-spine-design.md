# NetSentinel Spine — Slice 1 Design

**Parent spec:** `NetSentinel_AI_SIH26155_Technical_Product_Spec.md` (SIH26155)
**Date:** 2026-08-22
**Status:** Approved for implementation
**Scope:** Sub-project 1 of 6 — the vertical spine

---

## 1. Purpose

The parent spec describes a six-subsystem platform sized for a six-person team across
eight phases. This document scopes the first buildable slice: a thin vertical cut that
carries one configuration file from upload to PDF report through every architectural
layer the full product needs.

The slice is deliberately narrow in breadth and complete in depth. One vendor, one
framework, sixteen controls — but real authentication, real RBAC, real provenance, and
real deterministic rule evaluation. Every later sub-project extends a working pipeline
rather than assembling one.

### Sub-project decomposition

The parent spec decomposes into six sub-projects. This document covers SP1 only.

| ID | Sub-project | Parent spec sections |
|----|-------------|----------------------|
| **SP1** | **Spine — parse, normalize, evaluate, report** | **13–19, 28–29, 44** |
| SP2 | Multi-vendor expansion (Juniper, Fortinet, Palo Alto) | 42 |
| SP3 | Framework expansion (NIST, STIG, ISO evidence model) | 18–19 |
| SP4 | AI interpreter + adaptive training loop | 20–22 |
| SP5 | Intelligence (risk, drift, what-if, crosswalk) | 23–27 |
| SP6 | Enterprise (SSO, Postgres/Celery/MinIO, offline packaging) | 7, 39 |

---

## 2. Slice boundary

### In scope

- Email/password authentication, Argon2id hashing, JWT access + rotating refresh tokens
- Six RBAC roles with server-side permission enforcement
- Configuration upload with validation, secret redaction, and SHA-256 content hashing
- Cisco IOS / IOS-XE vendor detection with a confidence score and stated reasons
- Cisco IOS block parser producing a typed configuration tree
- Normalizer mapping parsed facts to sixteen Universal Security Control keys
- Deterministic rule engine loading versioned YAML rule packs
- CIS subset covering all sixteen controls
- Findings carrying evidence, provenance, and severity
- Device-specific remediation guidance from a static remediation pack
- Explainable posture score
- PDF device report
- Minimal React UI: login, upload, audit list, findings detail, evidence panel
- Golden-configuration test suite

### Out of scope

Deferred to the sub-projects named in §1: additional vendors, additional frameworks,
the AI interpreter and Training Center, drift detection, what-if hardening, risk graph
visualization, the tamper-evident evidence ledger, SSO/SAML/LDAP, and Celery/Redis/MinIO
containerization.

### Non-goals

Per parent spec §3.3: no automated changes to production devices, no offensive testing,
no claim that a device configuration proves organizational ISO/IEC 27001 compliance.

---

## 3. Environment constraints and the three seams

The development machine has no Docker and defaults to Python 3.8. The parent spec
assumes Postgres, Redis, MinIO, and Celery in containers.

Resolution: build against the spec's architecture but bind three named seams to local
implementations. Each seam is a single interface with a swappable implementation, so
adopting the containerized stack in SP6 is a configuration change and one new class —
never a rewrite of calling code.

| Seam | Slice 1 binding | SP6 binding | Cost of switch |
|------|-----------------|-------------|----------------|
| `DATABASE_URL` | `sqlite:///./var/netsentinel.db` | `postgresql+psycopg://…` | Env var + Alembic run |
| `StorageBackend` | `LocalFileStorage` (`./var/blobs/`) | `S3Storage` (MinIO/S3) | One class, ~60 lines |
| `TaskRunner` | `InlineTaskRunner` (BackgroundTasks) | `CeleryTaskRunner` | One class, ~40 lines |

**Rules for keeping the seams honest.** No SQLite-specific SQL, no raw file paths outside
`LocalFileStorage`, no `BackgroundTasks` import outside `InlineTaskRunner`. Every model
uses SQLAlchemy types that map cleanly to both engines. A `docker-compose.yml` for the
full stack is committed from day one and kept accurate even while unused.

Python 3.13 is pinned via `uv`, satisfying the spec's 3.12+ requirement without touching
the system Python.

---

## 4. Technology stack

### Backend

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Runtime | Python 3.13 (managed by `uv`) | Spec §9.2 requires 3.12+ |
| API | FastAPI | Spec §9.2 |
| Validation | Pydantic v2 | Spec §9.2; also constrains AI output in SP4 |
| ORM | SQLAlchemy 2.0 (sync, typed) | Spec §9.2; sync avoids async-driver complexity at no cost for this workload |
| Migrations | Alembic | Spec §9.2 |
| Password hashing | `argon2-cffi` | Spec §7.1 mandates Argon2id |
| Tokens | `PyJWT` | Smaller surface than python-jose |
| Rule/mapping data | `PyYAML` | Human-editable rule packs |
| PDF | ReportLab | Spec §9.8 |
| Tests | pytest, pytest-cov | — |
| Lint / types | Ruff, MyPy | Spec §47 |

FastAPI endpoints touching the database are declared `def`, not `async def`, so
SQLAlchemy's synchronous session runs in the threadpool. This is a deliberate
simplification: audit workloads are CPU-bound parsing, not IO concurrency.

### Frontend

| Concern | Choice |
|---------|--------|
| Build | Vite |
| Framework | React 19 + TypeScript |
| Styling | Tailwind CSS |
| Components | shadcn/ui primitives (Radix + Tailwind) |
| Data | TanStack Query |
| Routing | React Router |
| Charts | Recharts (posture score, severity breakdown) |

Dark mode is the primary theme per spec §31. Severity is never conveyed by color alone —
every badge carries a text label.

---

## 5. Repository layout

```text
netsentinel/
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI app factory, router mounting
│   │   ├── config.py               Pydantic Settings, env binding
│   │   ├── db.py                   Engine, session factory, Base
│   │   ├── api/
│   │   │   ├── deps.py             Auth + permission dependencies
│   │   │   ├── auth.py
│   │   │   ├── users.py
│   │   │   ├── devices.py
│   │   │   ├── configurations.py
│   │   │   ├── audits.py
│   │   │   ├── findings.py
│   │   │   ├── frameworks.py
│   │   │   └── reports.py
│   │   ├── models/                 SQLAlchemy ORM models
│   │   ├── schemas/                Pydantic request/response models
│   │   ├── security/
│   │   │   ├── passwords.py        Argon2id hash/verify
│   │   │   ├── tokens.py           JWT issue/verify/rotate
│   │   │   ├── permissions.py      Permission enum, role matrix
│   │   │   └── redaction.py        Secret detection + redaction
│   │   ├── services/
│   │   │   ├── ingestion/          Validation, hashing, storage write
│   │   │   ├── detection/          Vendor/OS signature scoring
│   │   │   ├── parsing/            Cisco IOS block parser
│   │   │   ├── normalization/      Facts → Universal Control Model
│   │   │   ├── compliance/         Rule loader + deterministic engine
│   │   │   ├── remediation/        Remediation pack lookup
│   │   │   ├── scoring/            Posture score
│   │   │   ├── reporting/          ReportLab PDF builder
│   │   │   └── audit/runner.py     Pipeline orchestration
│   │   ├── storage/
│   │   │   ├── base.py             StorageBackend protocol
│   │   │   └── local.py            LocalFileStorage
│   │   ├── tasks/
│   │   │   ├── base.py             TaskRunner protocol
│   │   │   └── inline.py           InlineTaskRunner
│   │   └── audit_log.py            AuditEvent emission
│   ├── alembic/
│   ├── pyproject.toml
│   └── tests/
│       ├── unit/
│       ├── integration/
│       └── golden/cisco/
├── rules/
│   └── cis/
│       └── cisco-ios-v8.yaml
├── mappings/
│   └── cisco/
│       └── remediation.yaml
├── datasets/
│   └── demo/cisco/
├── frontend/
│   ├── src/
│   │   ├── components/{layout,ui,charts,security}/
│   │   ├── features/{auth,dashboard,devices,ingestion,audits,findings,reports}/
│   │   ├── hooks/  lib/  services/  types/  routes/
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   └── superpowers/specs/
├── deployment/docker/
├── docker-compose.yml
├── .github/workflows/ci.yml
├── README.md
└── SECURITY.md
```

---

## 6. Pipeline architecture

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

### Boundary discipline

Every stage is a pure function from the previous stage's typed output to its own. No
stage opens a database session, reads a file, or makes an HTTP call. Persistence and
orchestration live exclusively in `services/audit/runner.py`, which calls the stages in
order and writes results in one transaction.

This is what makes the parent spec's Principle 2 real: the parser knows Cisco syntax and
nothing about CIS; the rule engine knows CIS and nothing about Cisco. Adding a vendor
touches `detection/` and `parsing/` only. Adding a framework touches `rules/` only —
which is data, not code.

**The SP4 seam.** When the normalizer meets syntax it cannot map, it records an
`UnknownConstruct` and continues. In slice 1 these are counted, surfaced in the audit
response, and otherwise inert. SP4 attaches the AI interpreter and Training Center at
exactly this one point, with no change to any other stage.

---

## 7. Universal Security Control Model

Parent spec §15 sketches a flat map of dotted keys. This slice extends every value with
provenance, because Principle 4 requires that each finding trace back to specific
configuration lines.

```python
@dataclass(frozen=True)
class ControlValue:
    value: bool | int | str | list[str] | None
    source_lines: list[int]      # 1-indexed lines in the redacted config
    excerpt: str                 # redacted configuration text that produced this value
    parser_confidence: float     # 1.0 for deterministic parsing
    origin: Literal["deterministic", "inferred", "learned"]

ControlSet = dict[str, ControlValue]
```

`origin` is `"deterministic"` throughout slice 1. The other two values exist so SP4 can
populate them without a schema migration.

A key absent from the `ControlSet` means "the parser did not observe this". A key present
with `value=None` means "observed and explicitly unset". The rule engine treats both as
`NOT_ASSESSABLE` — never as a pass.

### Slice 1 control set

Sixteen keys, drawn from parent spec §44's list of thirty. Chosen for cross-vendor
generality and unambiguous CIS coverage.

| # | Key | Type | Category |
|---|-----|------|----------|
| 1 | `management.ssh.enabled` | bool | Management |
| 2 | `management.ssh.version` | int | Management |
| 3 | `management.telnet.enabled` | bool | Management |
| 4 | `management.http.enabled` | bool | Management |
| 5 | `management.https.enabled` | bool | Management |
| 6 | `management.session_timeout` | int (seconds) | Management |
| 7 | `management.acl.present` | bool | Network Security |
| 8 | `auth.password.min_length` | int | Authentication |
| 9 | `auth.aaa.enabled` | bool | Authentication |
| 10 | `auth.enable_secret.encrypted` | bool | Authentication |
| 11 | `auth.default_accounts.present` | bool | Authentication |
| 12 | `logging.local.enabled` | bool | Logging |
| 13 | `logging.remote.enabled` | bool | Logging |
| 14 | `time.ntp.enabled` | bool | Time |
| 15 | `snmp.v3.only` | bool | Management |
| 16 | `banner.login.present` | bool | Management |

---

## 8. Rules as versioned data

Parent spec §18 is explicit: framework logic must not be hard-coded. Rule packs are YAML
files loaded at startup, validated against a Pydantic schema, and hashed for provenance.

### Rule schema

```yaml
- id: CIS-SSH-002
  framework: CIS
  framework_version: "8.0"
  title: SSH protocol version 2 enforced
  description: >
    SSH version 1 contains cryptographic weaknesses and must not be used for
    device management. Version 2 is required.
  applicability:
    vendor: cisco
    os: [ios, ios-xe]
  parameter: management.ssh.version
  operator: equals
  expected: 2
  severity: HIGH
  evidence_required: true
  remediation_id: REM-SSH-002
  source: "CIS Cisco IOS Benchmark v8.0 §1.5.2"
  tests:
    - { given: 1, expect: FAIL }
    - { given: 2, expect: PASS }
    - { given: null, expect: NOT_ASSESSABLE }
```

### Operators

`equals` · `not_equals` · `gte` · `lte` · `gt` · `lt` · `in` · `not_in` · `present` ·
`absent` · `matches` (regex)

The operator set is closed. A rule requiring logic outside it is a signal that a new
normalized control is needed — not that the engine needs a scripting escape hatch. This
constraint is what keeps the engine deterministic and auditable.

### Self-testing rules

Each rule's inline `tests:` block is executed as a parametrized pytest case. A rule that
does not prove its own behavior fails CI. This directly serves the parent spec's
"audit reproducibility: 100%" target (§52).

### Result statuses

| Status | Meaning |
|--------|---------|
| `PASS` | Parameter observed, satisfies expectation |
| `FAIL` | Parameter observed, violates expectation |
| `WARNING` | Parameter observed, satisfies a weaker form of the expectation |
| `NOT_ASSESSABLE` | Parameter absent from the control set, or observed as null |
| `NOT_APPLICABLE` | Rule's `applicability` does not match the detected device |

Severity levels: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`.

### Remediation packs

Parallel YAML, keyed by `remediation_id`, per parent spec §28:

```yaml
REM-SSH-002:
  vendor: cisco
  os: [ios, ios-xe]
  title: Enforce SSH version 2
  current_state_hint: "ip ssh version 1"
  cli: |
    configure terminal
     ip ssh version 2
    end
    write memory
  verification: "show ip ssh"
  rollback: "configure terminal / ip ssh version 1 / end"
  notes: "Confirm all management clients support SSHv2 before applying."
```

Every rendered remediation carries the mandated banner:
**"Review and validate before production deployment."** Nothing is ever pushed to a device.

---

## 9. Data model

Trimmed from parent spec §32 to what slice 1 needs. Names and relationships match the
parent so later sub-projects extend rather than rename.

| Entity | Key fields | Notes |
|--------|-----------|-------|
| `Organization` | id, name | One row seeded; tenancy scaffolding for SP6 |
| `User` | id, org_id, email, password_hash, role_id, is_active | Argon2id hash |
| `Role` | id, name, permissions (JSON) | Six rows seeded from §10 |
| `RefreshToken` | id, user_id, token_hash, expires_at, revoked_at | Rotation + revocation |
| `Device` | id, org_id, name, vendor, model, os, os_version | Created or matched on upload |
| `Configuration` | id, device_id, sha256, blob_key, filename, size, uploaded_by, uploaded_at, secret_hits | Redacted text in blob store |
| `AuditRun` | id, configuration_id, framework, framework_version, status, rule_pack_hash, engine_version, started_at, finished_at | Hash + version give reproducibility |
| `NormalizedControl` | id, audit_run_id, key, value_json, source_lines, excerpt, parser_confidence, origin | Full provenance chain |
| `ComplianceResult` | id, audit_run_id, rule_id, framework, framework_version, parameter, observed_value, expected_value, status, severity | Immutable |
| `Finding` | id, compliance_result_id, severity, title, remediation_id, triage_status, notes | User-mutable triage layer |
| `Report` | id, audit_run_id, blob_key, generated_by, generated_at | PDF artifact |
| `AuditEvent` | id, user_id, action, resource, timestamp, ip, result | Parent spec §37 |

### Two deliberate decisions

**Rules are not a database table.** Parent spec §32 lists `ComplianceRule` and
`Framework` entities, but §18 requires rules to be versioned, independently loadable
files. Files win — they are the source of truth, reviewable in git, diffable across
versions. `AuditRun` records `rule_pack_hash` and `engine_version` instead, which is what
reproducibility actually requires. A rule table would be a second source of truth to keep
in sync.

**`Finding` is separate from `ComplianceResult`.** Results are immutable engine output;
findings carry human triage state (`open`, `accepted_risk`, `false_positive`) and notes.
Merging them would mean user edits mutating audit evidence.

**No `ConfigurationVersion` table.** Each upload is its own `Configuration` row keyed by
SHA-256. Version history is `Configuration` rows sharing a `device_id`, ordered by
`uploaded_at` — which is exactly the input SP5's drift engine needs, with no extra table.

---

## 10. Authentication and authorization

### Authentication

Argon2id password hashing with library defaults. Login issues a 15-minute access token
and a 30-day refresh token; refresh rotates the token and revokes its predecessor.
Reuse of a revoked refresh token revokes the entire family and emits an `AuditEvent` —
standard replay detection. Rate limiting on `/auth/login` at 5 attempts per 15 minutes
per email.

### Authorization

A `Permission` enum with a role matrix derived from parent spec §6. Every protected
endpoint declares its requirement as a FastAPI dependency:

```python
@router.post("/audits", dependencies=[Depends(require(Permission.AUDIT_RUN))])
```

Permissions: `DEVICE_READ` · `DEVICE_WRITE` · `CONFIG_UPLOAD` · `AUDIT_RUN` ·
`AUDIT_READ` · `FINDING_READ` · `FINDING_TRIAGE` · `REPORT_GENERATE` · `REPORT_READ` ·
`USER_ADMIN` · `MAPPING_SUGGEST` · `MAPPING_APPROVE`

The last two are defined and assigned in the role matrix but unused until SP4. Defining
them now means the matrix is correct from the start rather than being retrofitted.

### Role matrix

| Role | Upload | Run audit | Read findings | Triage | Reports | Devices | Admin |
|------|--------|-----------|---------------|--------|---------|---------|-------|
| Security Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| Network Engineer | ✓ | ✓ | ✓ | ✓ | ✓ | read | — |
| Security Analyst | — | ✓ | ✓ | ✓ | ✓ | read | — |
| CISO | — | — | read | — | ✓ | read | — |
| Auditor | — | — | read | — | ✓ | read | — |
| Platform Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Authorization is enforced server-side only. The frontend hides controls the user cannot
use, but that is presentation — never the control itself.

---

## 11. Secret handling

Network configurations contain credentials, keys, and SNMP communities. Parent spec §36
and threat T2 require these never reach logs, API responses, or reports.

**Redaction happens on ingest, before persistence.** The sanitizer scans for:

- `password 7 <hex>` and `password 0 <cleartext>` (Cisco type-7 / cleartext)
- `enable secret 5|8|9 <hash>`
- `username … secret|password …`
- `snmp-server community <string>`
- `key-string`, `pre-shared-key`, `crypto key` blocks
- PEM blocks (`-----BEGIN … PRIVATE KEY-----`)

Each match is replaced with `<REDACTED:type-7-password>` and counted in
`Configuration.secret_hits`. The redacted text is the only copy that reaches the
database, API responses, evidence excerpts, PDFs, or logs.

Raw bytes are written to the local blob store, which is appropriate for the offline
deployment model the parent spec targets (§39) and is the copy an auditor would need for
independent verification.

**Secret presence is itself evidence.** `auth.enable_secret.encrypted` is derived from
the hash type observed during redaction — the control is evaluated without the secret
value ever leaving storage.

### Upload validation

Extensions `.txt .cfg .conf .log .json .xml .yaml .yml`; maximum 5 MB; content must be
valid UTF-8 or Latin-1 decodable. Uploaded files are treated as untrusted input
throughout (threat T1). Archive ingestion is deferred to SP2, which removes zip-bomb
exposure from this slice entirely.

---

## 12. Device detection

Weighted signature matching against the redacted configuration, producing a confidence
score and the reasons behind it — parent spec §13 requires the UI show *why*.

```python
DeviceIdentity(
    vendor="cisco", product_family="ios", os="ios-xe", os_version="17.6",
    hostname="core-sw-01", confidence=0.97,
    reasons=["matched 'Building configuration...' (w=3)",
             "matched 'boot-start-marker' (w=3)",
             "matched 'line con 0' (w=2)",
             "version token '17.6' implies IOS-XE (w=4)"],
)
```

Confidence bands follow parent spec §13: ≥0.95 high, 0.70–0.95 medium, <0.70 requires
manual confirmation.

Below 0.70, `POST /audits` returns **409 Conflict** with the detection reasoning and the
candidate vendors. The caller re-submits with an explicit `vendor_override`, which is
recorded on the `AuditRun`. The system never guesses a vendor and silently proceeds —
a wrong vendor produces confidently wrong compliance results, which is worse than asking.

---

## 13. Posture scoring

Parent spec §23 requires an explainable formula. Severity-weighted pass rate over
assessable rules:

```text
weights = { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0 }

earned    = Σ weight(r) × credit(r)     for r in assessable results
available = Σ weight(r)                 for r in assessable results

credit: PASS = 1.0,  WARNING = 0.5,  FAIL = 0.0

score    = round(100 × earned / available)
coverage = assessable / (assessable + not_assessable)
```

`NOT_ASSESSABLE` and `NOT_APPLICABLE` are excluded from both sums and reported separately
as coverage. A configuration that reveals nothing therefore scores no points rather than
scoring 100 — the failure mode a naive pass-rate produces.

Score and coverage are always displayed together. Per parent spec §24, the UI labels the
number as a posture indicator, never as a certification.

---

## 14. Error handling

| Condition | Behavior |
|-----------|----------|
| Unsupported extension / oversized upload | 422 with specific reason; nothing persisted |
| Undecodable bytes | 422; treated as non-text upload |
| Duplicate SHA-256 for same device | 200 returning the existing `Configuration` — idempotent |
| Detection confidence < 0.70 | 409 with reasons; requires `vendor_override` |
| Unparseable individual line | `ParseWarning` collected; parsing continues |
| Construct parsed but unmappable | `UnknownConstruct` recorded; audit completes; counted in response |
| Control absent for a rule | `NOT_ASSESSABLE` — never a pass |
| Rule pack fails schema validation | **Application refuses to start.** Fail closed |
| Rule references unknown `remediation_id` | Startup validation error |
| PDF generation failure | 500; `AuditRun` remains valid and retryable |

The consistent principle: never fail an entire audit for a locally-recoverable problem,
and never let a gap in knowledge present itself as compliance.

---

## 15. API surface

Base path `/api/v1`. Endpoint shapes follow parent spec §34.

```http
POST   /auth/login                    → access + refresh tokens
POST   /auth/refresh                  → rotated pair
POST   /auth/logout                   → revoke refresh family
GET    /users/me

GET    /devices
POST   /devices
GET    /devices/{id}

POST   /configurations/upload         multipart; returns id, sha256, secret_hits
GET    /configurations/{id}           metadata + redacted text

POST   /audits                        {configuration_id, framework, vendor_override?}
GET    /audits                        filter by device, framework, status
GET    /audits/{id}                   identity, controls, results, score, unknowns

GET    /findings?audit_id=            filter by severity, status
GET    /findings/{id}                 evidence + provenance + remediation
PATCH  /findings/{id}                 triage_status, notes

GET    /frameworks                    loaded packs + versions + hashes
GET    /frameworks/{id}/rules

POST   /audits/{id}/report            generate PDF
GET    /reports/{id}                  download

GET    /healthz
```

`GET /findings/{id}` returns the complete provenance chain required by Principle 4:
configuration SHA-256 → excerpt with line numbers → normalized parameter → rule ID →
framework and version → rule pack hash → status.

---

## 16. Testing strategy

Test-driven throughout, in dependency order — each stage is tested against fixed inputs
before the stage that feeds it exists.

**1. Rule engine (pure).** Operators, status derivation, applicability filtering,
`NOT_ASSESSABLE` handling. No fixtures, no IO.

**2. Rule packs (self-testing).** Every rule's inline `tests:` block runs as a
parametrized case. Adding a rule without tests fails CI.

**3. Normalizer.** Hand-built `ConfigTree` fixtures → expected `ControlSet`, including
provenance line numbers.

**4. Parser.** Cisco config snippets → expected tree structure, indentation nesting,
line numbering.

**5. Detection.** Configuration samples → expected vendor, OS, and confidence band.

**6. Redaction.** Every secret pattern, plus assertions that no secret substring survives
into normalized output, findings, or rendered PDF text.

**7. Security.** Each endpoint × each role → expected allow/deny. Token expiry, rotation,
and replay detection.

**8. Golden configurations.** End-to-end contract:

```text
backend/tests/golden/cisco/
├── compliant.cfg      + expected_controls.json + expected_results.json
├── noncompliant.cfg   + expected_controls.json + expected_results.json
└── mixed.cfg          + expected_controls.json + expected_results.json
```

Coverage requirement: each of the sixteen controls is exercised in both a passing and a
failing state across the golden set.

**9. Integration.** Upload → audit → findings → report through the live API.

Per parent spec §41, AI evaluation metrics are deferred with SP4 — there is no AI in this
slice, so there is nothing subjective to measure.

---

## 17. Build order

Each step leaves the system in a working, committed state.

| # | Step | Delivers |
|---|------|----------|
| 1 | Scaffold | `uv` env, FastAPI app, config, SQLAlchemy base, Alembic, `/healthz`, CI workflow |
| 2 | Auth + RBAC | Users, roles, Argon2id, JWT rotation, permission dependency, seeded org and roles |
| 3 | Control model + rule engine | `ControlValue`, rule schema, loader, operators, engine — pure and fully tested |
| 4 | Rule pack | `rules/cis/cisco-ios-v8.yaml` covering all 16 controls, self-testing |
| 5 | Detection + parser | Cisco signature scoring, IOS block parser, golden fixtures |
| 6 | Normalizer | Tree → 16 controls with provenance |
| 7 | Ingestion | Upload, validation, redaction, hashing, `LocalFileStorage` |
| 8 | Audit orchestration | `runner.py`, `AuditRun` persistence, `InlineTaskRunner`, audit endpoints |
| 9 | Findings + remediation + score | Finding derivation, remediation pack, posture scoring, triage |
| 10 | PDF report | ReportLab device report per parent spec §29 |
| 11 | Frontend | Login, upload, audit list, audit detail, findings, evidence panel |
| 12 | Demo data + docs | Three Cisco configs, seed script, README, SECURITY.md, architecture doc |

Steps 1–10 produce a complete working product over the API. Step 11 is presentation on
top of a system that already works.

---

## 18. Definition of done

Slice 1 is complete when, from parent spec §53:

- [ ] User logs in securely; tokens rotate; replay is detected
- [ ] User uploads a Cisco configuration
- [ ] Vendor and OS are identified with a confidence score and stated reasons
- [ ] Configuration parses into a structured tree with line numbers
- [ ] Sixteen normalized controls are produced with provenance
- [ ] Compliance engine evaluates versioned rules deterministically
- [ ] Findings carry evidence, provenance, and severity
- [ ] Remediation guidance is generated with the validation banner
- [ ] Posture score and coverage are displayed together
- [ ] PDF report generates
- [ ] Audit history is stored and reproducible via `rule_pack_hash`
- [ ] Secrets are redacted and absent from all outputs
- [ ] RBAC is enforced server-side for every endpoint
- [ ] Golden tests cover all 16 controls in passing and failing states
- [ ] CI runs lint, types, and the full test suite

Explicitly **not** claimed at slice 1: multi-vendor support, multi-framework support,
adaptive learning, or drift detection. Those are SP2 through SP5.

---

## 19. Traceability to parent spec

| Parent section | Slice 1 treatment |
|----------------|-------------------|
| §7 Auth | Implemented (MVP tier); SSO deferred to SP6 |
| §9 Stack | Implemented with three documented seams (§3) |
| §13 Detection | Implemented, Cisco only |
| §14 Parsing pipeline | Implemented; AI branch stubbed as `UnknownConstruct` |
| §15–16 Control model | Implemented, 16 of ~30 controls, provenance added |
| §17–18 Compliance engine | Implemented, CIS only |
| §19 ISO handling | Deferred to SP3 |
| §20–22 AI + training | Deferred to SP4; seam defined |
| §23–27 Risk, drift, what-if | Deferred to SP5 |
| §28–29 Remediation + PDF | Implemented |
| §30–31 UI/UX | Implemented, minimal surface |
| §32–33 Data model | Implemented, trimmed with documented deviations (§9) |
| §34 API | Implemented, slice-1 endpoints |
| §36 Security | Implemented, minus archive handling |
| §37 Audit trail | Implemented |
| §38 Blockchain | Deferred; `rule_pack_hash` + config SHA-256 lay the groundwork |
| §39 Offline | Slice 1 *is* offline by construction — no external calls |
| §41 Testing | Implemented; AI evaluation deferred with SP4 |
| §44 Control set | 16 of 30 |
| §47–48 Standards + CI | Implemented from step 1 |
| §49 Threat model | T1, T2, T4, T6 addressed; T3, T5 arrive with SP4 |
