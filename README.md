# NetSentinel AI

NetSentinel AI is a network security compliance auditor: upload a device configuration,
and it identifies the vendor/OS, parses the configuration into a structured tree,
evaluates it against a versioned compliance rule pack, and produces an explainable
posture score, evidenced findings, remediation guidance, and a PDF report — with every
step traceable back to specific configuration lines.

AI is advisory-only, by construction: it only ever interprets configuration lines the
deterministic parser didn't recognize, and a human must approve any suggestion before
it's recorded. It never decides compliance status, never touches rule definitions, and
never pushes configuration changes to a device. See [Architecture](docs/architecture.md)
for how that boundary is actually enforced, not just documented.

## Current status vs. roadmap

| Area | Supported | Beta | Planned |
|---|---|---|---|
| Vendors | Cisco IOS / IOS-XE | FortiOS | Juniper (Junos), Palo Alto (PAN-OS) |
| Frameworks | CIS, NIST SP 800-53 Rev. 5 | — | STIG, ISO 27001 |
| Storage | SQLite + local filesystem (dev), S3/MinIO (`app/storage/s3.py`, `NETSENTINEL_STORAGE_BACKEND=s3`) | — | — |
| Database | SQLite (dev), PostgreSQL (`docker-compose.yml` boots a real Postgres-backed stack; run it yourself to validate against a live instance — CI still runs against SQLite only) | — | — |
| Async execution | — | — | Celery/Redis (the `TaskRunner` seam in `app/tasks/` exists for this; nothing wires it in yet — see Architecture) |

A vendor or framework is only ever marked **Supported** here once a real
detector+parser+normalizer (or rule pack) exists for it — see
`app/services/{detection,parsing,normalization}/registry.py` and `rules/`. The frontend's
capability badges (`frontend/src/lib/capabilities.ts`) mirror this table; neither is
allowed to claim more than the code actually does.

## Scope

**Implemented:**

- Email/password auth: Argon2id hashing, JWT access + rotating refresh tokens, a real
  (if delivery-less — see below) password-reset flow, production startup fails closed
  on a missing/default/weak `NETSENTINEL_JWT_SECRET`
- Six RBAC roles enforced server-side on every endpoint; every organization-owned
  resource is checked against the caller's own organization on every read/write
- Configuration upload with validation, secret redaction (Cisco- and FortiOS-specific
  patterns), and SHA-256 content hashing
- Pluggable vendor detection with a confidence score and stated reasons — Cisco and
  FortiOS registered today (`app/services/detection/registry.py`)
- Pluggable parsing/normalization onto sixteen vendor-neutral Universal Security
  Control keys (`app/domain/controls.py`) — the same deterministic rule engine runs
  unmodified regardless of vendor or framework
- Two rule packs (CIS/Cisco, CIS/FortiOS) and one cross-framework pack (NIST 800-53,
  mapped onto the same normalized controls Cisco already produces) — all versioned YAML,
  not code; adding a rule never touches Python
- Findings with evidence, provenance, and severity; vendor-specific remediation guidance
- Explainable, severity-weighted posture score reported separately from assessment
  coverage (a high score on low coverage is never presented as a full pass)
- AI-assisted interpretation of unrecognized configuration lines: untrusted input is
  explicitly delimited in the prompt, every response field is validated against a fixed
  vocabulary regardless of what the model claims, and nothing is applied until a human
  with the approval permission reviews it
- PDF device report, including AI interpretations (clearly marked advisory) and their
  review status
- React UI covering the full flow: upload → detection/confirmation → audit → compliance
  results → unknown constructs → AI interpretation → human approval → findings →
  remediation → PDF report, with vendor/framework capability badges throughout

**Known, disclosed limitations:**

- Password reset issues and validates a real token but has no email/SMS provider
  wired in (`app/security/reset_delivery.py` — logs the token instead; the seam is
  ready for a real provider)
- FortiOS coverage is real but narrower than Cisco's: three controls
  (`auth.aaa.enabled`, `auth.enable_secret.encrypted`, `management.ssh.version`) have
  no FortiOS analog and are deliberately left unassessed rather than stretched to fit
- Secret redaction is line-based, not block-aware — it cannot distinguish a FortiOS
  SNMP community *name* (which is the secret) from an unrelated object name using the
  same directive elsewhere; see `app/security/redaction.py`
- Everything runs synchronously inside the request (fine at current scale — see
  Architecture); the `TaskRunner` deferred-work seam exists but nothing calls it yet
- PostgreSQL support is real (driver installed, Alembic migrations are dialect-agnostic,
  `docker-compose.yml` boots a working Postgres-backed stack) but CI only runs the test
  suite against SQLite — run `docker compose up` yourself to exercise it against a live
  Postgres instance before relying on it in production

**Deferred (no code claims otherwise):** Juniper/PAN-OS parsers, STIG/ISO rule packs,
a real task queue, SSO/SAML/LDAP, drift detection, what-if hardening, risk graph
visualization, the tamper-evident evidence ledger.

## Prerequisites

- [`uv`](https://docs.astral.sh/uv/) (Python 3.13 is pinned via `uv`, no system Python
  changes needed)
- Node.js 22+

## Running it

**Backend** (from `backend/`):

```bash
uv sync --dev
uv run alembic upgrade head
uv run python -m scripts.seed
uv run uvicorn app.main:app --reload
```

The API serves on `http://127.0.0.1:8000`; SQLite lives at `backend/var/netsentinel.db`
and uploaded blobs at `backend/var/blobs/`. See `.env.example` for every environment
variable — in particular, `NETSENTINEL_ENVIRONMENT=production` requires a real
`NETSENTINEL_JWT_SECRET` (generate one with `openssl rand -hex 32`) or the app refuses
to start.

**Frontend** (from `frontend/`, in a second terminal):

```bash
npm install
npm run dev
```

Open the printed URL (`http://localhost:5173` by default) — its dev server proxies
`/api` to the backend.

## Demo accounts

Seeding creates six users, all sharing the password `demo-password-1`:

| Email | Role |
|-------|------|
| `admin@netsentinel.ai` | Platform Admin |
| `secadmin@netsentinel.ai` | Security Admin |
| `engineer@netsentinel.ai` | Network Engineer |
| `analyst@netsentinel.ai` | Security Analyst |
| `ciso@netsentinel.ai` | CISO |
| `auditor@netsentinel.ai` | Auditor |

## Rule packs

Compliance rules are versioned YAML data, not code — adding a rule never touches Python.

- `rules/cis/cisco-ios-v8.yaml` — CIS Cisco IOS Benchmark v8.0 (16 rules)
- `rules/cis/fortios-v1.yaml` — CIS FortiGate 7.4.x Benchmark v1.0.1 (13 rules)
- `rules/nist/cisco-ios-800-53r5.yaml` — NIST SP 800-53 Rev. 5, mapped onto the same
  controls Cisco's normalizer already produces (16 rules)
- `mappings/cisco/`, `mappings/fortinet/` — the matching remediation packs (CLI,
  verification, rollback per `remediation_id`)

To add a rule: add an entry to the appropriate YAML pack with a unique `id`, its
`parameter` (a Universal Security Control key — see `docs/architecture.md`),
`operator`/`expected`, `severity`, and a `remediation_id` that resolves in a remediation
pack. The application refuses to start if a rule references a remediation id that
doesn't exist, or if any pack fails schema validation — rule packs fail closed.

## Tests

```bash
cd backend
uv run pytest --cov=app --cov-report=term-missing   # full suite + coverage
uv run ruff check .      # lint
uv run ruff format --check .
uv run mypy app          # types

cd ../frontend
npm run lint              # oxlint
npx tsc --noEmit          # types
npm run build
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push to `main` and every
pull request.

See `docs/architecture.md` for the full system design, the AI safety model, and the
current limitations in more depth than fits here.
