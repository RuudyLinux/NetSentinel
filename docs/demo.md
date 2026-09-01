# Demo script — slice 1

A two-minute walkthrough, adapted from the parent spec's SIH demo story (§51) to what
slice 1 actually does. **This script does not claim multi-vendor normalization or the
adaptive training loop** — those are SP2 and SP4 respectively, not built yet. Slice 1 is
one vendor (Cisco IOS/IOS-XE), one framework (CIS), sixteen controls, but the complete
pipeline end to end.

## Setup

Both servers running (see `README.md`), signed in as `admin@netsentinel.ai` /
`demo-password-1`.

## Script

**1. Upload a noncompliant configuration (~30s)**

Go to Upload, drop `datasets/demo/cisco/noncompliant.cfg`. Narrate while it processes:
*"NetSentinel identifies the vendor and OS with a stated confidence, parses the
configuration into a structured tree, and evaluates it against a versioned CIS rule
pack — deterministically, not by guessing."*

Expected: redirected to the audit detail page. **Score 0**, coverage <100% (one control,
`management.ssh.version`, is `NOT_ASSESSABLE` — SSH is off entirely, so its version
can't be assessed; that's an honest gap, not a silent pass), **15 findings**.

**2. Open a CRITICAL finding (~30s)**

Click a CRITICAL-severity finding in the list. Narrate: *"Every finding traces back to
the exact configuration line it came from, and secrets are already redacted before this
data ever reached the server."*

Expected: evidence panel shows the offending line number(s) and excerpt, observed vs.
expected value, device-specific remediation CLI, a verification step, and the
"review and validate before production deployment" banner — remediation is guidance,
not an automated change.

**3. Generate the PDF report (~20s)**

Click "Generate PDF report" on the audit detail page. Narrate: *"The same evidence and
provenance — rule pack hash, configuration hash, engine version — travels into a report
an auditor can file."*

Expected: a PDF opens in a new tab, starting with the organization/device/detection
summary, followed by every finding with its evidence and remediation section.

**4. Upload a compliant configuration (~20s)**

Upload `datasets/demo/cisco/compliant.cfg`. Narrate: *"Same pipeline, same rule pack —
a hardened configuration scores accordingly."*

Expected: **score 100**, coverage 100%, zero findings.

**5. Close (~10s)**

*"That's the spine: real auth and RBAC, real parsing, real deterministic evaluation,
real evidence — for one vendor and one framework today. Every later phase — more
vendors, more frameworks, an AI interpreter for the constructs it doesn't yet recognize
— extends this pipeline. It doesn't replace it."*

## What this demo intentionally does not show

- Uploading multiple vendors in one pass (SP2)
- Training the system on an unrecognized command (SP4 — slice 1 only records
  `UnknownConstruct`s and counts them; it does not learn from them yet)
- NIST/STIG/ISO assessment (SP3 — CIS only today)
- Drift / what-if / risk graph views (SP5)

If asked, say so plainly rather than implying any of the above exists.
