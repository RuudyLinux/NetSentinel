# Security

## Redaction guarantee and its boundary

Every uploaded configuration is redacted **on ingest, before persistence**. The
sanitizer matches Cisco type-7/cleartext passwords, `enable secret` hashes,
`username … secret|password` lines, SNMP community strings, key-string/pre-shared-key/
crypto-key blocks, and PEM private-key blocks, replacing each with a
`<REDACTED:type>` marker and counting it in `Configuration.secret_hits`.

**The redacted text is the only copy that reaches the database, API responses, evidence
excerpts, PDF reports, logs, or the local blob store (`backend/var/blobs/`) — nothing
downstream of redaction ever sees the raw bytes.** Access to the blob store is itself
subject to the same filesystem permissions as the rest of the deployment — it is not
exposed by any API endpoint. Treat `backend/var/` as sensitive and exclude it from
backups/exports that leave the trust boundary you intend for it.

## Threat model coverage (slice 1)

Per the parent spec's threat model (§49), this slice addresses:

- **T1** — untrusted upload content (extension/size/encoding validation; the whole
  parsing/normalization pipeline treats configuration text as untrusted throughout)
- **T2** — secret exposure in outputs (redaction on ingest, described above)
- **T4** — unauthorized access to findings/reports (server-side RBAC on every endpoint,
  organization-scoped queries)
- **T6** — audit trail tampering/gaps (append-only `AuditEvent` log; refresh-token reuse
  triggers family-wide revocation and an audit event)

**Deferred to SP4:** T3 and T5 — these depend on the AI interpreter and adaptive
training loop, which are out of scope for slice 1 (see `README.md` and
`docs/architecture.md`).

## Development-only defaults

The following are placeholders for local development and **must be replaced before any
real deployment**:

- The seeded demo accounts' shared password, `demo-password-1`
- `Settings.jwt_secret`'s default value (`backend/app/config.py`) — override via the
  `NETSENTINEL_JWT_SECRET` environment variable in any real deployment; the default is
  intentionally long enough to satisfy HS256's minimum key-length recommendation but is
  still a published, guessable string

Neither default is fit for anything beyond a local demo. Slice 1 has no SSO — auth
hardening (SSO/SAML/LDAP) is SP6 scope.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than via a public issue —
using this repository's GitHub **Security Advisories** (Security tab → "Report a
vulnerability") once the repository has a GitHub remote configured. Include steps to
reproduce and the affected component. We aim to acknowledge reports promptly and will
coordinate disclosure timing with the reporter.
