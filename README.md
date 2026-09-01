# NetSentinel AI

NetSentinel AI is a network security compliance auditor: upload a device configuration,
and it identifies the vendor/OS, parses the configuration into a structured tree,
evaluates it against a versioned compliance rule pack, and produces an explainable
posture score, evidenced findings, remediation guidance, and a PDF report — with every
step traceable back to specific configuration lines.

This repository currently implements **slice 1 (the spine)**: one vendor (Cisco IOS /
IOS-XE), one framework (CIS), sixteen controls — but the complete pipeline, real
authentication and RBAC, and real provenance, end to end.

## Scope

**In scope (slice 1):**

- Email/password auth with Argon2id hashing, JWT access + rotating refresh tokens
- Six RBAC roles enforced server-side on every endpoint
- Configuration upload with validation, secret redaction, and SHA-256 content hashing
- Cisco IOS / IOS-XE vendor detection with a confidence score and stated reasons
- Cisco IOS block parser producing a typed configuration tree with line numbers
- Normalizer mapping parsed facts to sixteen Universal Security Control keys
- Deterministic rule engine loading versioned YAML rule packs (CIS, all 16 controls)
- Findings with evidence, provenance, and severity; device-specific remediation guidance
- Explainable, severity-weighted posture score with coverage
- PDF device report
- Minimal React UI: login, upload, audit list, audit detail, findings/evidence panel

**Deferred to later sub-projects (SP2–SP6):** additional vendors, additional compliance
frameworks, the AI interpreter and adaptive training loop, drift detection, what-if
hardening, risk graph visualization, the tamper-evident evidence ledger, SSO/SAML/LDAP,
and Postgres/Redis/MinIO/Celery containerization. See `docs/architecture.md` for how the
system is seamed so those land without rewriting this slice.

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
and uploaded blobs at `backend/var/blobs/`.

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

See `docs/demo.md` for a two-minute walkthrough script.

## Rule packs

Compliance rules are versioned YAML data, not code — adding a rule never touches Python.

- `rules/cis/cisco-ios-v8.yaml` — the CIS rule pack (16 rules, one per control)
- `mappings/cisco/` — the matching remediation pack (CLI, verification, rollback per
  `remediation_id`)

To add a rule: add an entry to the YAML pack with a unique `id`, its `parameter` (a
Universal Security Control key — see `docs/architecture.md`), `operator`/`expected`,
`severity`, and a `remediation_id` that resolves in the remediation pack. The
application refuses to start if a rule references a remediation id that doesn't exist,
or if the pack fails schema validation — rule packs fail closed.

## Tests

```bash
cd backend
uv run pytest            # full suite
uv run ruff check .      # lint
uv run ruff format --check .
uv run mypy app          # types

cd ../frontend
npm run lint              # oxlint
npx tsc --noEmit          # types
npm run build
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push and PR.
