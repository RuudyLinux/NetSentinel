# NetSentinel AI
## SIH26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

**Project Type:** Software  
**SIH Problem Statement:** SIH26155  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Document:** Product + Technical Design Specification  
**Status:** Proposed implementation blueprint  
**Version:** 1.0

---

## 1. Executive Summary

NetSentinel AI is a vendor-agnostic network security compliance and hardening platform designed for heterogeneous enterprise networks.

It ingests network-device configurations from different vendors and operating systems, detects the vendor/device context, converts proprietary configuration syntax into a **Universal Security Control Model**, evaluates the normalized posture against security frameworks such as CIS Benchmarks, NIST SP 800-53, DISA STIGs, and ISO/IEC 27001 evidence requirements, and produces prioritized findings and device-specific remediation guidance.

The platform's key differentiator is an **Adaptive Learning / Training Loop**. When the engine encounters an unknown configuration structure, it does not require backend code to be rewritten. Instead, an authorized administrator is shown the unknown command and surrounding context in a low-code training interface, maps it to a normalized security parameter, and approves the mapping. The learned mapping is persisted and reused for future configurations.

### Core product promise

> **Any network configuration → understand → normalize → evaluate → explain → remediate → learn.**

The system is intentionally designed as a **hybrid AI + deterministic compliance engine**. AI is used for interpretation and adaptation; authoritative compliance decisions are made by versioned, testable rules and evidence logic.

---

# 2. Problem Understanding

Modern environments contain firewalls, routers, switches, SASE/cloud controls, white-box networking and specialized appliances from many vendors. Each vendor can have different:

- CLI syntax
- hierarchy
- terminology
- configuration export format
- operating-system version
- security capabilities
- benchmark coverage

A hard-coded parser for every command becomes expensive and brittle. A generic LLM-only solution is not sufficiently deterministic or auditable for security compliance.

NetSentinel therefore separates the problem into:

1. **Ingestion**
2. **Vendor / OS identification**
3. **Configuration interpretation**
4. **Vendor-neutral normalization**
5. **Security-control evaluation**
6. **Evidence and risk analysis**
7. **Remediation**
8. **Human-guided learning**
9. **Reporting and auditability**

---

# 3. Goals

## 3.1 Primary Goals

- Support heterogeneous configuration inputs.
- Build a vendor-neutral security representation.
- Evaluate configurations against multiple frameworks.
- Provide explainable PASS / FAIL / WARNING results.
- Generate device-specific remediation guidance.
- Learn previously unseen configuration structures without redeploying backend code.
- Track configuration and security drift over time.
- Provide evidence and provenance for every compliance decision.
- Provide role-based access and strong audit controls.
- Support offline/private deployment for sensitive environments.

## 3.2 Secondary Goals

- Provide executive and engineering views.
- Provide cross-framework control mapping.
- Provide what-if hardening simulation.
- Visualize potential risk/attack paths without performing exploitation.
- Support machine-readable exports in addition to PDF reports.
- Make adding new vendors/frameworks modular.

## 3.3 Non-Goals for the Initial Release

- Fully automatic support for every vendor named in the SIH statement.
- Automatic changes to production network devices.
- Offensive exploitation of customer infrastructure.
- Claiming that a router configuration alone proves full organizational ISO/IEC 27001 compliance.
- Training a large foundation model from scratch.

---

# 4. Product Principles

### Principle 1 — AI assists; rules decide

LLMs/NLP can interpret unknown syntax, but compliance decisions must be made using deterministic, versioned rules and explicit evidence.

### Principle 2 — Normalize first

Vendor syntax should be converted to a common security vocabulary before cross-framework evaluation.

### Principle 3 — Human approval for learned knowledge

Low-confidence or novel semantic mappings require administrator approval before becoming reusable knowledge.

### Principle 4 — Every result needs provenance

Every finding should be traceable to:

`configuration → parsed evidence → normalized parameter → rule → framework/version → result`

### Principle 5 — Secure by design

Network configurations can contain credentials, secrets, keys and sensitive topology information. Sensitive content must be protected throughout ingestion, storage, processing, logs and exports.

---

# 5. Target Users

## 5.1 Security Administrator

**Primary user**

Responsibilities:
- Upload configurations
- Run audits
- Review findings
- Train unknown mappings
- Approve suggested mappings
- Generate remediation
- Download reports

Permissions:
- Audit assigned assets
- View findings
- Create/approve mappings
- Generate reports

## 5.2 Network Engineer

Responsibilities:
- Review device configuration
- Validate parser results
- Review remediation CLI
- Compare configuration versions
- Resolve configuration drift

Permissions:
- Read assigned devices
- View evidence
- Review remediation
- Submit mapping suggestions

## 5.3 Security Analyst / SOC Analyst

Responsibilities:
- Investigate high-risk findings
- Correlate findings
- Review attack-path/risk visualization
- Track security posture

Permissions:
- Cross-device visibility according to scope
- Read findings and risk information
- Export evidence

## 5.4 CISO / Security Manager

Responsibilities:
- View organizational posture
- Track trends
- Review critical risks
- Compare frameworks
- Download executive reports

Permissions:
- Read-only executive dashboard
- Organization-wide analytics
- Report access

## 5.5 Compliance Auditor

Responsibilities:
- Verify evidence
- Review rule provenance
- Review framework mappings
- Validate audit history

Permissions:
- Read evidence
- Read rule metadata
- Read audit trails
- Export audit package

## 5.6 Platform Administrator

Responsibilities:
- Manage users and roles
- Configure organization settings
- Manage framework/rule packs
- Manage model providers
- Configure retention policies
- Manage integrations

Permissions:
- Full platform administration

---

# 6. Role-Based Access Control

Recommended RBAC roles:

| Role | Upload | Audit | Findings | Train AI | Approve Rules | Reports | Admin |
|---|---:|---:|---:|---:|---:|---:|---:|
| Security Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Limited |
| Network Engineer | ✓ | ✓ | ✓ | Suggest | — | ✓ | — |
| Security Analyst | — | ✓ | ✓ | Suggest | — | ✓ | — |
| CISO | — | Read | Read | — | — | ✓ | — |
| Auditor | — | Read | Read | — | Review | ✓ | — |
| Platform Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Use least privilege. A user who can **suggest** a learned mapping should not automatically be able to **publish** it globally.

---

# 7. Authentication and Authorization

## 7.1 Authentication

For MVP:

- Email + password
- Password hashing using Argon2id
- Access token + refresh token
- Secure session handling
- Account lockout/rate limiting
- Email verification for cloud deployments

For advanced / enterprise deployment:

- OAuth 2.0 / OpenID Connect
- SSO
- SAML 2.0
- LDAP / Active Directory integration
- Optional MFA/TOTP
- Enterprise identity provider integration

## 7.2 Authorization

Use:

- RBAC
- Organization / tenant isolation
- Project / asset scopes
- Resource-level authorization
- Server-side permission checks

Never trust frontend-only authorization.

## 7.3 Session Security

- Short-lived access tokens
- Refresh-token rotation
- HttpOnly secure cookies where applicable
- CSRF protections for cookie-based sessions
- Logout/revocation
- Session audit events

---

# 8. High-Level System Architecture

```text
                         ┌──────────────────────────┐
                         │       Web Frontend       │
                         │ React + TypeScript       │
                         └────────────┬─────────────┘
                                      │ HTTPS
                                      ▼
                         ┌──────────────────────────┐
                         │       API Gateway        │
                         │ FastAPI + Auth + RBAC    │
                         └────────────┬─────────────┘
                                      │
             ┌────────────────────────┼─────────────────────────┐
             │                        │                         │
             ▼                        ▼                         ▼
      ┌──────────────┐       ┌────────────────┐        ┌───────────────┐
      │ Ingestion    │       │ Audit/Workflow │        │ Report Service│
      │ Service      │       │ Service        │        │ PDF/JSON/CSV  │
      └──────┬───────┘       └───────┬────────┘        └───────────────┘
             │                       │
             ▼                       ▼
      ┌──────────────┐       ┌────────────────┐
      │ Parser /     │       │ Compliance     │
      │ Normalizer   │◄─────►│ Engine         │
      └──────┬───────┘       └───────┬────────┘
             │                       │
             ▼                       ▼
      ┌──────────────┐       ┌────────────────┐
      │ AI / NLP     │       │ Risk + Drift   │
      │ Interpreter  │       │ Engine         │
      └──────┬───────┘       └────────────────┘
             │
             ▼
      ┌─────────────────────────────────────────┐
      │ Universal Security Control Graph        │
      │ + Learned Mapping Knowledge Base        │
      └────────────────┬────────────────────────┘
                       │
                       ▼
      ┌─────────────────────────────────────────┐
      │ PostgreSQL / Object Storage / Cache     │
      └─────────────────────────────────────────┘

                 Optional Offline Deployment
          ┌──────────────────────────────────────┐
          │ Local LLM + Local Rules + Local DB  │
          │ No external network required        │
          └──────────────────────────────────────┘
```

---

# 9. Recommended Technology Stack

## 9.1 Frontend

**Primary**
- React
- TypeScript
- Vite or Next.js
- Tailwind CSS
- shadcn/ui or equivalent component system

**Visualization**
- Apache ECharts / Recharts
- React Flow for control/risk graphs

**Why**
- Fast dashboard development
- Strong typing
- Good component ecosystem
- Excellent for interactive training workflows

## 9.2 Backend

**Primary**
- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy
- Alembic

**Why**
- Excellent AI/ML ecosystem
- Good network-automation libraries
- Fast API development
- Strong validation

## 9.3 Network / Parsing

Candidate libraries:
- Netmiko
- NAPALM
- TextFSM
- NTC Templates
- Custom vendor parsers
- XML/JSON/YAML parsers

Use deterministic vendor-aware parsing whenever possible.

## 9.4 AI / NLP

Recommended approach:

**MVP**
- Embeddings
- Semantic similarity
- Structured LLM extraction
- Regex/pattern recognition
- Small classifier where useful

**Advanced**
- Local LLM option
- Retrieval-augmented generation
- Domain-specific classifier
- Fine-tuned model only after enough approved training examples exist

The model should return structured JSON, not arbitrary prose.

## 9.5 Database

**PostgreSQL**

Store:
- Organizations
- Users
- Devices
- Configurations metadata
- Normalized controls
- Audit runs
- Findings
- Rules
- Frameworks
- Learned mappings
- Training events
- Reports
- Audit events

## 9.6 Object Storage

Use S3-compatible object storage:
- MinIO for local/private deployment
- S3-compatible cloud storage for hosted deployments

Store large:
- Raw configuration files
- Generated reports
- Evidence packages

Keep secrets and raw sensitive files out of application logs.

## 9.7 Cache / Queue

- Redis
- Celery / RQ / Dramatiq

Use asynchronous workers for:
- Large configuration parsing
- Batch audits
- AI processing
- PDF generation
- Report exports

## 9.8 PDF

- ReportLab

## 9.9 Deployment

**Development**
- Docker Compose

**Production**
- Docker
- Kubernetes optional
- Nginx / reverse proxy
- PostgreSQL
- Redis
- Object storage

Do not introduce Kubernetes unless deployment complexity is justified.

---

# 10. Frontend Structure

```text
frontend/
├── src/
│   ├── app/
│   ├── components/
│   │   ├── layout/
│   │   ├── ui/
│   │   ├── charts/
│   │   └── security/
│   ├── features/
│   │   ├── auth/
│   │   ├── dashboard/
│   │   ├── devices/
│   │   ├── ingestion/
│   │   ├── audits/
│   │   ├── findings/
│   │   ├── training/
│   │   ├── frameworks/
│   │   ├── remediation/
│   │   ├── reports/
│   │   └── settings/
│   ├── hooks/
│   ├── lib/
│   ├── services/
│   ├── types/
│   └── routes/
└── tests/
```

---

# 11. Backend Structure

```text
backend/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── api/
│   │   ├── auth.py
│   │   ├── users.py
│   │   ├── devices.py
│   │   ├── ingestion.py
│   │   ├── audits.py
│   │   ├── findings.py
│   │   ├── training.py
│   │   ├── frameworks.py
│   │   ├── remediation.py
│   │   ├── reports.py
│   │   └── analytics.py
│   ├── models/
│   ├── schemas/
│   ├── services/
│   │   ├── ingestion/
│   │   ├── detection/
│   │   ├── parsing/
│   │   ├── normalization/
│   │   ├── compliance/
│   │   ├── ai/
│   │   ├── risk/
│   │   ├── drift/
│   │   ├── remediation/
│   │   └── reporting/
│   ├── workers/
│   ├── security/
│   ├── repositories/
│   └── utils/
├── rules/
│   ├── cis/
│   ├── nist/
│   ├── stig/
│   └── iso/
├── mappings/
│   ├── cisco/
│   ├── juniper/
│   ├── fortinet/
│   └── paloalto/
└── tests/
```

---

# 12. Major Product Modules

## 12.1 Authentication Module

Features:
- Login
- Registration
- Password reset
- MFA
- SSO (advanced)
- Session management
- Audit events

---

## 12.2 Organization / Workspace Module

An organization represents a customer, lab, institution or SIH demo tenant.

Hierarchy:

```text
Organization
 ├── Projects / Environments
 │    ├── Devices
 │    ├── Audits
 │    └── Reports
 ├── Users
 ├── Roles
 └── Framework Configuration
```

---

## 12.3 Configuration Ingestion Module

Input types:
- `.txt`
- `.cfg`
- `.conf`
- `.log`
- `.json`
- `.xml`
- `.yaml/.yml`
- Vendor-specific export formats

Features:
- Single upload
- Bulk upload
- Drag and drop
- ZIP ingestion
- File validation
- Duplicate detection
- Sensitive-data detection
- Secret redaction
- Hashing
- Metadata extraction

Each upload receives a SHA-256 content hash.

---

# 13. Device Identification

The system attempts to identify:

```text
Vendor
Product family
Model
OS
OS version
Configuration format
Serial number (when present)
Hostname
Management IP (when present)
```

Identification confidence:

```text
95–100%  → High confidence
70–95%   → Medium confidence
<70%     → Manual confirmation
```

The UI should show why the system made the identification.

---

# 14. Parsing Pipeline

```text
Raw Configuration
       │
       ▼
Sanitization
       │
       ▼
Vendor/OS Detection
       │
       ▼
Deterministic Parser
       │
       ├── Known syntax → Structured result
       │
       └── Unknown syntax
                 │
                 ▼
             AI Interpreter
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
      High    Medium      Low
      Conf.   Conf.       Conf.
        │        │          │
      Auto    Confirm      Train
```

---

# 15. Universal Security Control Model

The central normalized object should be roughly:

```json
{
  "device": {
    "vendor": "Cisco",
    "product": "Catalyst",
    "model": "C9300",
    "os": "IOS-XE",
    "version": "17.x"
  },
  "controls": {
    "management.ssh.enabled": true,
    "management.ssh.version": 2,
    "management.telnet.enabled": false,
    "management.http.enabled": false,
    "logging.remote.enabled": true,
    "time.ntp.enabled": true
  }
}
```

The exact schema should evolve as the rule catalog grows.

---

# 16. Universal Control Categories

Initial categories:

### Authentication
- Password policy
- Password length
- Complexity
- History
- Lockout
- AAA
- MFA evidence
- Session timeout

### Management
- SSH
- Telnet
- HTTP management
- HTTPS management
- Management ACL
- Privileged access

### Cryptography
- TLS minimum version
- Weak ciphers
- Weak hashes
- Key length
- Certificate validation

### Logging
- Local logging
- Remote syslog
- Administrative event logging
- Log retention evidence

### Time
- NTP enabled
- Approved NTP source
- Time synchronization

### Network Security
- ACLs
- Anti-spoofing
- Unused services
- Insecure protocols
- Management plane restrictions

### Resilience
- Redundancy
- Failover
- Backup configuration
- High availability

---

# 17. Compliance Engine

The compliance engine must be deterministic.

Input:

```text
Normalized Security Control
+
Framework
+
Framework Version
+
Device Context
```

Output:

```text
PASS
FAIL
WARNING
NOT_ASSESSABLE
NOT_APPLICABLE
```

Each result should contain:

```json
{
  "rule_id": "CIS-SSH-001",
  "framework": "CIS",
  "framework_version": "specific-version",
  "parameter": "management.ssh.version",
  "observed_value": 1,
  "expected_value": 2,
  "status": "FAIL",
  "severity": "HIGH",
  "evidence": [],
  "remediation_id": "REM-SSH-001"
}
```

---

# 18. Framework Model

Do not hard-code framework logic into application code.

Instead:

```text
frameworks/
├── cis/
├── nist/
├── stig/
└── iso/
```

Rules should be versioned, testable and independently loadable.

Every rule should have:

- Unique ID
- Framework
- Framework version
- Control/title
- Description
- Applicability
- Normalized parameter(s)
- Operator
- Expected value
- Severity
- Evidence requirements
- Remediation reference
- Source/provenance
- Test cases

---

# 19. ISO/IEC 27001 Handling

ISO/IEC 27001 should be treated differently from device-specific configuration benchmarks.

Use:

```text
DIRECT
```

when a device configuration provides sufficient technical evidence.

Use:

```text
PARTIAL
```

when the configuration provides supporting evidence but cannot prove the organizational requirement.

Use:

```text
NOT_ASSESSABLE
```

when non-configuration evidence is required.

This prevents misleading "ISO compliance percentages."

---

# 20. AI / NLP Layer

## 20.1 Responsibilities

AI should help with:

- Unknown command interpretation
- Semantic classification
- Context extraction
- Vendor/OS hints
- Suggested normalized mapping
- Explanation generation
- Remediation drafting
- Natural-language search

## 20.2 AI must return structured output

Example:

```json
{
  "candidate_parameter": "management.session_timeout",
  "candidate_value": 300,
  "category": "authentication",
  "confidence": 0.91,
  "reason": "Command contains timeout semantics in an administrative session context"
}
```

The application validates this response against a strict Pydantic schema.

---

# 21. Adaptive Training Module

This is the signature feature.

When unknown syntax is found:

```text
Unknown Command
        ↓
Context Window
        ↓
AI Candidates
        ↓
Administrator Decision
        ↓
Approved Mapping
        ↓
Knowledge Store
        ↓
Future Recognition
```

## Training UI

Show:

### Raw command
```text
secure-session-timeout 300
```

### Context
A small amount of surrounding configuration.

### AI suggestion
```text
Likely:
Session Timeout
Confidence: 91%
```

### Mapping

```text
Security category:
[ Authentication ]

Universal parameter:
[ management.session_timeout ]

Value:
[ 300 ]
```

### Actions

- Approve
- Edit
- Reject
- Save for this vendor
- Save globally (admin only)

---

# 22. Learned Knowledge Lifecycle

Mappings should have states:

```text
PENDING
  ↓
REVIEWED
  ↓
APPROVED
  ↓
ACTIVE
  ↓
DEPRECATED
```

Every approved mapping records:

- Who approved it
- When
- Original input
- Model suggestion
- Final mapping
- Confidence
- Vendor/OS scope
- Version scope
- Number of successful future uses

---

# 23. Risk Engine

Risk should not equal severity only.

Recommended risk score inputs:

```text
Rule Severity
×
Asset Criticality
×
Exposure
×
Confidence
×
Exploitability indicator
```

For SIH, keep the formula explainable.

Example:

```text
Base severity: HIGH
Internet exposure: +20
Critical asset: +20
Confidence: 98%
Final risk: 88/100
```

Do not invent real-world exploitability claims without evidence.

---

# 24. Security Posture Score

Display:

```text
Overall Score
Framework Score
Critical Findings
High Findings
Medium Findings
Low Findings
```

Example:

```text
Security Posture
82 / 100

CIS       87%
NIST      79%
STIG      81%
ISO       Evidence-based
```

Clearly distinguish scores from formal certifications.

---

# 25. Configuration Drift

Store audit snapshots.

Example:

```text
Monday
Score: 91

Friday
Score: 76
```

System identifies changes in security-relevant normalized controls.

Example:

```text
SSH version      2 → 1
Remote logging   ON → OFF
Management ACL   Changed
```

The drift engine compares **normalized controls**, not only raw text.

---

# 26. What-If Hardening

Create a simulation mode:

```text
Current score: 62

Select:
[x] Disable Telnet
[x] Enable SSH v2
[x] Enable remote logging
[x] Restrict management ACL

Predicted score: 91
```

The simulation must clearly say:

> **Simulation only — no changes are made to devices.**

---

# 27. Attack-Path / Risk Visualization

Use configuration-derived risk relationships rather than actual exploitation.

Example:

```text
Internet
   ↓
Exposed Management
   ↓
Insecure Protocol
   ↓
Credential Risk
   ↓
Administrative Access Risk
```

Each link should identify the underlying finding(s).

This feature should communicate risk, not perform offensive actions.

---

# 28. Remediation Engine

Every finding should have:

1. Explanation
2. Current state
3. Desired state
4. Device-specific remediation
5. Verification steps
6. Rollback guidance where appropriate

Example:

```text
Finding:
Telnet enabled

Current:
transport input telnet

Recommended:
transport input ssh

Verification:
show running-config | section line vty
```

Generated remediation must be labeled:

> **Review and validate before production deployment.**

Never automatically push generated CLI in the SIH prototype.

---

# 29. PDF Reporting

## Device Report

### Cover
- Organization
- Device
- Audit date
- Configuration hash
- Overall posture

### Executive summary
- Overall score
- Critical/high/medium/low findings
- Framework summary

### Device details
- Vendor
- Model
- OS/version
- Serial number if available

### Findings
For each:
- Rule ID
- Framework
- Status
- Severity
- Evidence
- Description
- Risk
- Remediation

### Evidence
- Relevant configuration excerpt
- Source/hash
- Parser confidence

### Remediation
- CLI
- Verification
- Notes

### Audit metadata
- Engine version
- Rule-pack version
- Model/version if AI used

---

# 30. Main UI / UX

## Login

Simple enterprise login.

## Overview Dashboard

Show:

- Security score
- Critical findings
- Devices
- Framework scores
- Recent audits
- Drift alerts
- Pending training items

## Devices

Cards/table:

```text
Device
Vendor
OS
Score
Critical
Last Audit
Status
```

## Audit Upload

Large drag-and-drop interface:

```text
┌───────────────────────────────────┐
│                                   │
│      Drop configuration files     │
│                                   │
│         or Browse Files           │
│                                   │
└───────────────────────────────────┘
```

## Audit Details

Tabs:

- Overview
- Findings
- Configuration
- Compliance
- Evidence
- Remediation
- Drift
- Risk

## Training Center

Queue:

```text
12 unknown mappings

[Review]
[Approve]
[Edit]
[Reject]
```

## Framework Explorer

Control crosswalk:

```text
Universal Control
      ↓
CIS
NIST
STIG
ISO Evidence
```

---

# 31. Visual Design Direction

Use a modern security-operations style:

- Dark mode as primary
- Light mode optional
- High information density without clutter
- Strong typography
- Clear severity hierarchy
- Consistent badges
- Accessible contrast
- Minimal decorative graphics

Suggested semantic colors:

- Critical → red
- High → orange
- Medium → amber
- Low → blue
- Pass → green
- Warning → amber
- Unknown → neutral

Do not rely on color alone; always include labels/icons.

---

# 32. Core Database Entities

Recommended entities:

```text
Organization
User
Role
Project
Device
Configuration
ConfigurationVersion
AuditRun
NormalizedControl
Framework
FrameworkVersion
ComplianceRule
ComplianceResult
Finding
Remediation
LearnedMapping
TrainingEvent
RiskScore
DriftEvent
Report
AuditEvent
ModelRun
```

---

# 33. Suggested Entity Relationships

```text
Organization
 ├── Users
 ├── Projects
 │    ├── Devices
 │    │    └── Configurations
 │    │          └── ConfigurationVersions
 │    └── AuditRuns
 ├── Rules
 └── LearnedMappings

AuditRun
 ├── ComplianceResults
 │      ├── Findings
 │      └── Evidence
 ├── RiskScore
 ├── DriftEvents
 └── Report
```

---

# 34. API Design

Base URL:

```text
/api/v1
```

## Authentication

```http
POST /auth/login
POST /auth/refresh
POST /auth/logout
POST /auth/forgot-password
POST /auth/reset-password
```

## Users

```http
GET    /users/me
GET    /users
POST   /users
PATCH  /users/{id}
```

## Devices

```http
GET    /devices
POST   /devices
GET    /devices/{id}
PATCH  /devices/{id}
DELETE /devices/{id}
```

## Ingestion

```http
POST /configurations/upload
POST /configurations/bulk-upload
GET  /configurations/{id}
```

## Audits

```http
POST /audits
GET  /audits
GET  /audits/{id}
POST /audits/{id}/rerun
```

## Findings

```http
GET /findings
GET /findings/{id}
PATCH /findings/{id}
```

## Training

```http
GET  /training/queue
GET  /training/{id}
POST /training/{id}/approve
POST /training/{id}/reject
POST /training/{id}/edit
```

## Frameworks

```http
GET /frameworks
GET /frameworks/{id}
GET /frameworks/{id}/rules
```

## Remediation

```http
POST /findings/{id}/remediation
GET  /remediations/{id}
```

## Reports

```http
POST /audits/{id}/report
GET  /reports/{id}
```

---

# 35. Example Audit API Flow

```text
1. Upload configuration
        ↓
2. Create audit
        ↓
3. Detect device
        ↓
4. Parse configuration
        ↓
5. Normalize controls
        ↓
6. Resolve unknown mappings
        ↓
7. Load applicable rules
        ↓
8. Evaluate compliance
        ↓
9. Calculate risk
        ↓
10. Generate remediation
        ↓
11. Generate report
        ↓
12. Update dashboard
```

---

# 36. Security Architecture

## Data Protection

- TLS 1.2+ / modern TLS
- Encryption at rest
- Encrypted object storage
- Secrets in environment/secret manager
- No secrets in logs
- Sensitive-value redaction

## File Security

Treat uploaded configuration files as untrusted input.

Implement:
- file type validation
- size limits
- decompression limits
- malware scanning where available
- path traversal protection
- parser sandboxing for risky parsers
- content hashing

## AI Security

Never blindly send sensitive configuration to a public model.

Use a policy:

```text
Sensitive file
     ↓
Secret redaction
     ↓
Policy check
     ↓
Allowed AI provider?
     ├── No → local model / deterministic parser
     └── Yes → approved provider
```

Protect against:
- prompt injection inside configuration text
- malicious model output
- untrusted tool instructions
- data leakage
- hallucinated remediation

---

# 37. Audit Trail

Log security-sensitive actions:

```text
LOGIN
LOGOUT
UPLOAD_CONFIGURATION
START_AUDIT
VIEW_FINDING
APPROVE_MAPPING
REJECT_MAPPING
CHANGE_RULE
GENERATE_REPORT
CHANGE_ROLE
CHANGE_SECURITY_SETTING
```

Each event:

```json
{
  "user_id": "...",
  "action": "APPROVE_MAPPING",
  "resource": "mapping-id",
  "timestamp": "...",
  "ip": "...",
  "result": "SUCCESS"
}
```

---

# 38. Optional Blockchain / Tamper-Evident Evidence Layer

Blockchain should not be part of the critical path for the first MVP.

A meaningful optional implementation is:

```text
Configuration Hash
      ↓
Audit Result Hash
      ↓
Report Hash
      ↓
Timestamp / Ledger
```

Purpose:

- Evidence integrity
- Tamper detection
- Audit verification

Do not put raw configurations or sensitive content on-chain.

For SIH, a simpler append-only tamper-evident audit log may be sufficient if blockchain adds more complexity than value.

---

# 39. Offline / Private Deployment

Recommended architecture for sensitive environments:

```text
Browser
   ↓
Local NetSentinel
   ├── Local API
   ├── Local PostgreSQL
   ├── Local Object Storage
   ├── Local Rules
   └── Local AI Model
```

Benefits:
- Configuration never leaves the environment
- Suitable for restricted networks
- Lower data-exfiltration risk

This should be a major future/advanced feature.

---

# 40. Observability

Implement:

- Structured application logs
- Request IDs
- Audit run IDs
- Metrics
- Error tracking
- Worker job status
- AI latency
- Parser success rate
- Unknown-command rate
- Mapping approval rate

Useful metrics:

```text
Audit success rate
Parser coverage
AI interpretation accuracy
Unknown mapping rate
Average audit time
Average report time
Critical findings per device
Drift events per week
```

---

# 41. Testing Strategy

## Unit Tests

Test:
- Parsers
- Normalizers
- Rules
- Severity calculation
- Risk scoring
- Authorization
- Redaction

## Integration Tests

Test:

```text
Configuration
→ Parser
→ Normalizer
→ Rule Engine
→ Findings
```

## Golden Configuration Tests

Maintain known configurations with expected normalized outputs.

Example:

```text
tests/golden/
├── cisco/
├── juniper/
├── fortinet/
└── paloalto/
```

Each test proves:

```text
input config
→ expected controls
→ expected compliance result
```

## AI Evaluation

Measure:
- Classification precision
- Recall
- Confidence calibration
- False acceptance rate
- Human approval rate

Never evaluate AI only by subjective demo quality.

---

# 42. Demo Dataset

For the SIH demonstration, prepare:

### Vendor 1
Cisco IOS/IOS-XE

### Vendor 2
Juniper Junos

### Vendor 3
Fortinet FortiOS

### Vendor 4
Palo Alto or another structurally different configuration

### Unknown vendor
A deliberately unseen sample format created for the demo.

For each:
- Compliant configuration
- Non-compliant configuration
- Mixed configuration
- Version variation
- Unknown command example

---

# 43. Suggested MVP Scope

## MVP-1

- Authentication
- Dashboard
- File upload
- Cisco parser
- Universal schema
- 15–20 controls
- CIS subset
- Findings
- PDF report

## MVP-2

- Juniper
- Fortinet
- NIST
- STIG subset
- Remediation
- Multi-device audits

## MVP-3

- AI interpretation
- Training Center
- Learned mapping database
- Confidence workflow

## MVP-4

- Palo Alto
- ISO evidence model
- Crosswalk visualization
- Drift detection
- What-if hardening

## MVP-5

- Advanced risk graph
- Offline mode
- Evidence integrity
- Enterprise SSO
- Final SIH demo polish

---

# 44. Recommended Initial Control Set

Do not start with hundreds of rules.

Start with approximately 20–30 high-value, cross-vendor concepts:

1. SSH enabled
2. SSH version
3. Telnet disabled
4. HTTP management disabled
5. HTTPS management enabled where applicable
6. Password minimum length
7. Password complexity
8. Password history
9. Account lockout
10. AAA configuration
11. Privileged access controls
12. Session timeout
13. Remote logging
14. Administrative event logging
15. NTP enabled
16. Approved NTP source
17. Weak cipher detection
18. Weak protocol detection
19. Management ACL
20. Unused service detection
21. SNMP security
22. SNMPv3 preference
23. Configuration backup evidence
24. Warning/banner evidence
25. Insecure management interface exposure
26. ACL presence
27. Default accounts
28. Encryption policy
29. Certificate validation
30. Device/version identification

Expand only after these are reliable.

---

# 45. Suggested Team Structure

For a 5–6 person team:

## Member 1 — Backend / Architecture

Own:
- FastAPI
- PostgreSQL
- APIs
- Authentication
- Core architecture

## Member 2 — Network Security / Parser Engineer

Own:
- Cisco
- Juniper
- Fortinet
- Parsing
- Normalization

## Member 3 — AI/ML Engineer

Own:
- AI interpretation
- Embeddings
- Training workflow
- Confidence engine
- Evaluation

## Member 4 — Frontend Engineer

Own:
- Dashboard
- Training UI
- Findings
- Graphs
- User experience

## Member 5 — Compliance / Research

Own:
- CIS
- NIST
- STIG
- ISO evidence logic
- Rule provenance
- Test cases

## Member 6 — DevOps / QA / Demo

Own:
- Docker
- CI/CD
- Testing
- Security testing
- Deployment
- SIH presentation/demo

One person can cover multiple roles for a smaller team.

---

# 46. Repository Structure

```text
netsentinel-ai/
│
├── frontend/
├── backend/
├── rules/
├── mappings/
├── datasets/
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── security.md
│   ├── compliance-model.md
│   ├── ai-design.md
│   └── demo.md
├── tests/
├── scripts/
├── deployment/
│   ├── docker/
│   └── k8s/
├── .github/
│   └── workflows/
├── docker-compose.yml
├── README.md
├── LICENSE
└── SECURITY.md
```

---

# 47. Engineering Standards

Use:

- Python type hints
- Pydantic validation
- Ruff
- MyPy or equivalent static checks
- Pre-commit
- ESLint
- Prettier
- Conventional commits
- Pull requests
- Automated tests
- Dependency scanning
- Secret scanning

Never commit:
- API keys
- passwords
- real customer configurations
- private keys
- production credentials

---

# 48. CI/CD

On every pull request:

```text
Lint
 ↓
Type Check
 ↓
Unit Tests
 ↓
Integration Tests
 ↓
Security Scan
 ↓
Build
```

On main branch:

```text
Test
 ↓
Docker Build
 ↓
Publish Image
 ↓
Deploy
```

---

# 49. Threat Model

Primary threats:

### T1 — Malicious configuration upload

Mitigation:
- validation
- sandboxing
- size limits
- malware scanning
- parser isolation

### T2 — Configuration secret leakage

Mitigation:
- secret detection
- redaction
- encryption
- access control

### T3 — Prompt injection in configuration

Mitigation:
- treat configuration as untrusted data
- structured prompts
- constrained output schemas
- no automatic tool execution
- human approval

### T4 — Unauthorized remediation

Mitigation:
- no automatic production push
- human review
- RBAC
- audit logging

### T5 — Poisoned learned mapping

Mitigation:
- human approval
- mapping scope
- versioning
- review workflow
- rollback

### T6 — Rule tampering

Mitigation:
- signed/versioned rule packs
- admin-only changes
- audit trail
- rule hashes

---

# 50. Key UX "Wow" Features

The final product should include these moments:

### Wow #1 — Multi-vendor normalization

```text
Cisco + Juniper + Fortinet
        ↓
Same security model
```

### Wow #2 — Unknown vendor

```text
Unknown command
        ↓
AI interpretation
        ↓
Human confirmation
        ↓
Learned
```

### Wow #3 — What-if hardening

```text
62 → 91
```

without touching the real device.

### Wow #4 — Cross-framework graph

```text
One security control
        ↓
CIS
NIST
STIG
ISO evidence
```

### Wow #5 — Security drift

```text
Yesterday: 91
Today: 76
```

with exact security-relevant changes identified.

---

# 51. SIH Demo Story

## 0–15 seconds

Show heterogeneous network.

> "Every vendor speaks a different configuration language."

## 15–35 seconds

Upload 3–4 configuration files.

## 35–55 seconds

Show normalization into Universal Security Model.

## 55–75 seconds

Run CIS/NIST/STIG assessment.

## 75–95 seconds

Open critical finding and show evidence + remediation.

## 95–115 seconds

Upload unknown vendor command and train it.

## 115–125 seconds

Re-run and show recognition.

## 125–120 seconds

End with the security posture improvement and final product statement.

The official SIH deliverables include a short demo video and limited technical presentation space, so the UI should be optimized for a very clear visual narrative.

---

# 52. Success Metrics

Do not only measure features.

Measure:

### Parser

- Known-command recognition accuracy
- Vendor detection accuracy
- Normalization accuracy

### AI

- Unknown-command classification precision
- Human approval rate
- False mapping rate
- Confidence calibration

### Compliance

- Rule correctness
- Evidence traceability
- Reproducibility

### Product

- Audit time
- Report generation time
- Number of supported devices
- Security posture improvement in simulation

Example target for a prototype:

```text
Known vendor detection:       >95%
Known control extraction:     >95%
Critical rule accuracy:       >98%
AI mapping human approval:    >90%
Audit reproducibility:        100%
```

Targets should be validated on your test dataset, not claimed in the final presentation before measurement.

---

# 53. Definition of Done — MVP

The MVP is ready when all of the following work:

- [ ] User can securely log in.
- [ ] User can upload one configuration.
- [ ] System identifies vendor/OS with a confidence score.
- [ ] System parses a supported vendor.
- [ ] System generates normalized security controls.
- [ ] Compliance engine evaluates versioned rules.
- [ ] Findings contain evidence and provenance.
- [ ] Findings contain severity.
- [ ] Remediation guidance is generated.
- [ ] PDF report can be generated.
- [ ] Unknown command triggers training workflow.
- [ ] Approved mapping is reusable.
- [ ] Audit history is stored.
- [ ] Configuration secrets are redacted.
- [ ] RBAC works server-side.
- [ ] Automated tests cover critical paths.

---

# 54. Definition of Done — SIH Showcase Version

- [ ] 3–4 meaningful vendor formats.
- [ ] 20–30 reliable normalized controls.
- [ ] CIS support.
- [ ] NIST support.
- [ ] STIG support.
- [ ] Evidence-aware ISO representation.
- [ ] Adaptive training.
- [ ] Cross-framework control graph.
- [ ] Risk scoring.
- [ ] Drift detection.
- [ ] What-if hardening.
- [ ] High-quality PDF.
- [ ] CISO dashboard.
- [ ] Offline/private deployment demonstration.
- [ ] Security audit logging.
- [ ] Complete architecture document.
- [ ] Clean GitHub repository.
- [ ] 2-minute demo.
- [ ] 5-slide presentation.

---

# 55. Recommended Build Order

```text
PHASE 1
Foundation
├── Repository
├── Docker
├── Auth
├── Database
└── Basic UI

PHASE 2
Security Model
├── Universal schema
├── Device model
├── Control model
├── Rule model
└── Provenance model

PHASE 3
Parser
├── Cisco
├── Juniper
└── Fortinet

PHASE 4
Compliance
├── CIS
├── NIST
└── STIG

PHASE 5
Reporting
├── Findings
├── Remediation
└── PDF

PHASE 6
AI Adaptation
├── Unknown detection
├── AI interpretation
├── Confidence
└── Training UI

PHASE 7
Advanced Intelligence
├── Crosswalk graph
├── Drift
├── What-if
└── Risk visualization

PHASE 8
SIH Polish
├── UX
├── Security
├── Testing
├── Demo data
├── Demo video
└── Presentation
```

---

# 56. Final Product Positioning

Do **not** position NetSentinel as:

> "An AI tool that scans network configurations."

Position it as:

> **"An adaptive security-control intelligence platform for heterogeneous networks."**

The differentiating technical statement is:

> **NetSentinel decouples vendor syntax from security intent. It converts proprietary configuration semantics into a universal security-control representation, evaluates that representation using deterministic and versioned compliance logic, and continuously expands its parser knowledge through human-approved learning.**

---

# 57. Reference Sources

Use authoritative/current sources as the basis for framework ingestion and validation:

- SIH 2026 Problem Statements: https://sih.gov.in/sih2026PS
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- NIST SP 800-53: https://csrc.nist.gov/pubs/sp/800/53/r5/final
- NIST SP 800-53 control downloads/resources: https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads
- DISA Cyber Exchange STIG downloads: https://public.cyber.mil/stigs/downloads/
- ISO/IEC 27001:2022: https://www.iso.org/standard/27001
- NTC Templates: https://github.com/networktocode/ntc-templates
- Netmiko: https://github.com/ktbyers/netmiko
- NAPALM: https://napalm.readthedocs.io/

---

# 58. Final Architecture Principle

The entire system can be remembered as:

```text
                  NETSENTINEL AI

Configurations
      │
      ▼
Identify
      │
      ▼
Parse
      │
      ▼
Understand
      │
      ▼
Normalize
      │
      ▼
Universal Security Control Graph
      │
      ├──────────► CIS
      ├──────────► NIST
      ├──────────► STIG
      └──────────► ISO Evidence
      │
      ▼
Risk + Evidence
      │
      ├──────────► Findings
      ├──────────► Remediation
      ├──────────► Drift
      └──────────► What-if
      │
      ▼
Learn Unknown Syntax
      │
      └──────────► Knowledge Base
                         │
                         └──────► Future Audits
```

## North-star outcome

**One platform that lets a security team understand, audit, explain, improve and continuously learn from a heterogeneous network without being locked to a single vendor.**
