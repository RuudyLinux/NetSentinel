You are working on my existing project: NETSENTINEL AI.

IMPORTANT:
DO NOT rewrite the project from scratch.
DO NOT replace the existing architecture unnecessarily.
FIRST inspect the existing codebase, routing, components, APIs, authentication, database models, styling system, and current UI.
Then improve and extend the existing implementation.

==================================================
1. PRODUCT CONTEXT
==================================================

NetSentinel AI is an AI-Driven Multi-Vendor Network Security Compliance Auditor.

Core product flow:

ANY NETWORK CONFIGURATION
        ↓
UNDERSTAND
        ↓
NORMALIZE
        ↓
EVALUATE
        ↓
EXPLAIN
        ↓
REMEDIATE
        ↓
LEARN

The system supports:

- Multi-vendor network devices
- Automatic network discovery
- IP and port detection
- Device/vendor detection
- Configuration ingestion
- Configuration parsing
- Universal Security Control Model
- CIS
- NIST SP 800-53
- DISA STIG
- ISO/IEC 27001 evidence requirements
- Compliance auditing
- Risk scoring
- Findings
- Remediation
- Configuration drift
- What-if hardening
- AI-assisted interpretation
- Human-approved AI mappings
- Reports
- Evidence
- Audit trails
- RBAC
- Offline/enterprise deployment

The UI must feel like a serious enterprise security operations platform.

Design inspiration:
- Modern SOC platform
- Linear
- Vercel
- Enterprise network management
- Security/compliance consoles

Do NOT make it look like:
- A gaming dashboard
- A crypto dashboard
- A neon cyberpunk website
- A generic SaaS admin template
- A ChatGPT clone

==================================================
2. PRIMARY UI DESIGN PRINCIPLE
==================================================

The UI should answer these questions immediately:

1. What is happening?
2. What is wrong?
3. How serious is it?
4. Why is it wrong?
5. What should I do next?

Every screen must prioritize:

- Clarity
- Evidence
- Severity
- User role
- Next action
- System status

Animations should communicate STATE, not decoration.

==================================================
3. GLOBAL VISUAL DESIGN SYSTEM
==================================================

Use a dark SOC-style interface.

Base:
- Deep dark neutral background
- Slightly lighter cards/panels
- Subtle borders
- High contrast text
- Minimal shadows
- Avoid excessive gradients

Use semantic colors carefully:

Critical = red
High = orange/red
Medium = amber
Low = blue/neutral
Pass = green
Warning = amber
Not Assessable = gray
Not Applicable = gray

Do not rely on color alone.
Always combine:
- icon
- label
- badge
- text

Typography:

Page title:
28–32px

Section title:
18–20px

Body:
14px

Secondary/meta:
11–13px

Configuration/CLI/code:
Monospace font

UI should have strong hierarchy.

==================================================
4. GLOBAL LAYOUT
==================================================

Desktop application shell:

LEFT SIDEBAR
approximately 240–260px

TOPBAR
approximately 64px

MAIN CONTENT
responsive

Content padding:
24–32px

Maximum content width:
approximately 1400–1500px

Cards:
10–12px radius

Buttons:
36–40px height

Inputs:
40px height

Tables:
compact but readable

Avoid huge empty spaces.

Avoid overly dense spreadsheet-like layouts.

==================================================
5. SIDEBAR
==================================================

Sidebar should be quiet and professional.

Top:

◈ NETSENTINEL AI

Navigation grouped logically.

Example:

OVERVIEW
Dashboard

NETWORK
Devices
Discovery
Device Groups
Configurations

SECURITY
Audits
Findings
Risk
Drift
Remediation

COMPLIANCE
Frameworks
Controls
Rule Packs
Cross-Framework
Evidence

AI INTELLIGENCE
AI Insights
Training Center
Learned Mappings
AI Evaluation

REPORTING
Reports

ADMINISTRATION
Users
Roles & Permissions
Organizations
Integrations
AI Providers
Framework Management
Retention
Audit Logs
System Settings

Bottom:

User avatar
Name
Role
Settings
Logout

Sidebar must change based on RBAC.

Do NOT show every section to every role.

==================================================
6. TOPBAR
==================================================

Topbar:

Breadcrumb

Page title/context

Search

Notifications

System status

User profile

Example:

Dashboard
Security posture overview

                         Search
                         🔔
                         System Healthy
                         Admin

Use a clean global search.

Notifications should open a panel, not navigate immediately.

==================================================
7. PAGE HEADER PATTERN
==================================================

Every major page should follow:

Page Title

One-line explanation

Right-side primary action

Example:

Devices
Manage and monitor discovered network infrastructure.

                         [ + Add Device ]

Do NOT put 5 competing buttons in the header.

Button hierarchy:

PRIMARY:
One important action.

SECONDARY:
Supporting action.

TERTIARY:
Text/icon action.

DESTRUCTIVE:
Red/destructive confirmation action.

==================================================
8. BUTTON DESIGN
==================================================

Buttons must have:

Normal
Hover
Pressed
Disabled
Loading
Success
Error

states.

Hover:
120–160ms

Press:
80–120ms

Panel:
180–250ms

Modal:
200–250ms

Example:

[ Run Audit ]

click

[ ◌ Running Audit... ]

complete

[ ✓ Audit Complete ]

Never create bouncing buttons.

Never use excessive glow effects.

==================================================
9. AUTHENTICATION EXPERIENCE
==================================================

Create a polished authentication system.

Routes:

/auth/login
/auth/register
/auth/forgot-password
/auth/reset-password
/auth/mfa
/auth/verify-email
/auth/session-expired

Error pages:

/403
/404

==================================================
10. LOGIN PAGE
==================================================

Create a professional centered login experience.

Structure:

NETSENTINEL AI logo

Welcome back

Sign in to your security workspace

Email

Password
show/hide password icon

Remember me

Forgot password?

[ Sign In ]

or

[ Continue with SSO ]

Subtle security/network visualization in background.

Background should be extremely subtle.

No Matrix rain.
No giant locks.
No hacker imagery.
No excessive particles.

Login card:
approximately 420–460px.

Animation:

Logo:
fade + slight upward motion

Card:
fade + slight scale

Form:
small staggered appearance

Total animation:
300–500ms.

==================================================
11. LOGIN LOADING
==================================================

When signing in:

[ Sign In ]

↓

[ ◌ Authenticating... ]

↓

[ ✓ Authentication successful ]

↓

Dashboard

Do not freeze the UI without feedback.

==================================================
12. LOGIN ERROR
==================================================

Use:

Unable to sign in

The email or password you entered is incorrect.

Please check your credentials and try again.

Do not reveal whether a specific account exists.

==================================================
13. FORGOT PASSWORD
==================================================

Screen:

← Back to sign in

Reset your password

Enter your account email and we'll send reset instructions.

Email

[ Send Reset Link ]

Success:

✓ Check your email

If an account is associated with that address,
reset instructions have been sent.

==================================================
14. RESET PASSWORD
==================================================

Fields:

New password
Confirm password

Password strength indicator.

Requirements:

✓ Minimum length
✓ Uppercase
✓ Number
✓ Special character

Button:

[ Update Password ]

==================================================
15. MFA
==================================================

Create MFA verification screen.

Title:

Verify your identity

Enter the 6-digit authentication code from your authenticator.

Use six digit input boxes.

Support pasting the complete code.

[ Verify ]

Use recovery method

Do not require users to manually click every box.

==================================================
16. SESSION EXPIRED
==================================================

Show:

Your session expired

For your security, you need to sign in again.

[ Sign In Again ]

Do not silently dump users at the login screen.

==================================================
17. 403 PAGE
==================================================

403

Access restricted

You don't have permission to access this resource.

Show required permission if appropriate.

[ Return to Dashboard ]

==================================================
18. 404 PAGE
==================================================

404

This security endpoint doesn't exist.

The resource you're looking for couldn't be found.

[ Back to Dashboard ]

==================================================
19. ROLE-BASED UI
==================================================

There are six roles:

admin@netsentinel.ai
Platform Admin

secadmin@netsentinel.ai
Security Admin

engineer@netsentinel.ai
Network Engineer

analyst@netsentinel.ai
Security Analyst

ciso@netsentinel.ai
CISO

auditor@netsentinel.ai
Auditor

Do not give all roles the same dashboard.

==================================================
20. PLATFORM ADMIN
==================================================

Platform Admin sees:

Dashboard
Devices
Discovery
Configurations
Audits
Findings
Risk
Drift
Remediation
Compliance
AI
Reports
Administration

Admin dashboard:

System Health

Users
Devices
Audits
Critical Findings
AI Services
Framework Status
Integrations

Administration should feel like a CONTROL CENTER.

Not another security dashboard.

==================================================
21. SECURITY ADMIN
==================================================

Focus:

Dashboard
Devices
Discovery
Audits
Findings
Compliance
AI Training
Risk
Remediation
Reports

Primary goals:

- Manage security posture
- Run audits
- Review findings
- Manage compliance
- Manage AI mappings
- Coordinate remediation

==================================================
22. NETWORK ENGINEER
==================================================

Navigation:

Dashboard
Devices
Discovery
Configurations
Audits
Findings
Remediation
Drift

Primary goals:

- Discover devices
- Inspect configurations
- Run audits
- Fix findings
- Review drift
- Generate CLI remediation

==================================================
23. SECURITY ANALYST
==================================================

Navigation:

Dashboard
Devices
Audits
Findings
Risk
Drift
Reports

Primary goals:

- Investigate
- Analyze risk
- Review findings
- Monitor drift
- Track security posture

==================================================
24. CISO
==================================================

CISO interface must be much simpler.

Focus on:

Executive Dashboard
Security Posture
Risk
Compliance
Critical Findings
Trends
Devices
Reports

Do NOT expose unnecessary engineering details by default.

CISO dashboard:

Security Score
Critical Findings
High Findings
Compliance Score
Risk Trend
Security Posture
Framework Scores
Top Risks
Recent Activity

Primary CTA:

[ View Executive Report ]

==================================================
25. AUDITOR
==================================================

Navigation:

Audit Dashboard
Audits
Findings
Compliance
Evidence
Frameworks
Controls
Rules
Audit History
Reports

Focus:

- Evidence
- Compliance
- Rule metadata
- Audit trails
- Findings
- Reports

==================================================
26. DASHBOARD
==================================================

Dashboard is the command center.

Top KPI cards:

Security Score
Devices
Critical Findings
Open Audits
Compliance Score

Example:

Security Score
82 / 100
↓ 3 from last audit

Devices
342
14 require attention

Critical Findings
8
3 new

Audits
12
2 running

Use animated count-up once on load.

Do not continuously animate numbers.

==================================================
27. SECURITY POSTURE
==================================================

Show:

Security Score radial visualization.

Framework scores:

CIS
84%

NIST
79%

STIG
72%

ISO
88%

Risk distribution.

Critical findings.

Trend graph.

Use animation only when data changes or first loads.

==================================================
28. DISCOVERY UI
==================================================

Create:

Discovery

Auto-detect your authorized network and discover network devices.

Before scan:

Detected Interface
Local IP
Subnet
CIDR
Gateway

Example:

Interface:
Wi-Fi

Local IP:
192.168.1.10

Subnet:
255.255.255.0

Network:
192.168.1.0/24

[ Start Discovery ]

[ Configure Manually ]

Do not force the user to manually enter CIDR if automatic detection is possible.

==================================================
29. DISCOVERY PROCESS
==================================================

Flow:

Auto-detect local network

↓

Discover authorized hosts

↓

Detect open management ports

↓

Confirm relevant services

↓

Identify device/vendor/OS

↓

Show confidence

During scan:

Discovery in progress

Network:
192.168.1.0/24

Progress:
████████████░░░░ 72%

Hosts discovered:
18

Ports checked:
126

Devices identified:
11

[ Stop Scan ]

Use real-time progress.

Do not fake progress.

==================================================
30. PORT DETECTION
==================================================

Do NOT assume SSH always runs on port 22.

Detect common management ports, including:

22
80
443
161
830
3389
8080
8443
2222
and configurable ports.

Distinguish:

OPEN PORT

from

CONFIRMED SERVICE

Example:

192.168.1.25

22/tcp
OPEN

SSH
CONFIRMED

or:

2222/tcp
OPEN

SSH
DETECTED

Use the existing detection architecture instead of creating a disconnected scanner.

==================================================
31. DISCOVERED DEVICE TABLE
==================================================

Columns:

Select

IP Address

Port

Service

Vendor

Device

OS

Confidence

Status

Actions

Example:

☑ 192.168.1.1
443
HTTPS
Cisco
Router
IOS XE
94%
Ready

☑ 192.168.1.20
22
SSH
Fortinet
Firewall
FortiOS
91%
Ready

Action:

[ Add Selected Devices ]

Allow manual addition as fallback.

==================================================
32. DEVICE DETAILS
==================================================

Device page tabs:

Overview
Configuration
Compliance
Risk
Findings
Drift
Remediation
History

Header:

Cisco Router

192.168.1.1

IOS XE

● Online

[ Run Audit ]
[ Edit Device ]

Overview cards:

Security Score
Compliance
Open Findings
Last Audit
Last Configuration Change

==================================================
33. CONFIGURATION PAGE
==================================================

Support:

Upload configuration
Paste configuration
Configuration library
Versions
History

Show code/configuration in monospace.

Use:

Line numbers
Syntax highlighting
Search
Copy
Download
Compare versions

Never use proportional fonts for network CLI/config.

==================================================
34. AUDIT PAGE
==================================================

Audit creation:

Select device(s)

Select configuration

Select framework(s)

Select rule pack

Optional advanced settings

[ Run Audit ]

Audit progress:

1. Detect device
2. Parse configuration
3. Normalize controls
4. Resolve mappings
5. Load rules
6. Evaluate compliance
7. Calculate risk
8. Generate remediation
9. Generate report

Show animated progress between states.

Do not make fake animations longer than necessary.

==================================================
35. FINDINGS
==================================================

Finding structure:

Severity

Title

Device

Framework

Control

Status

Risk

First detected

Last seen

Use badges:

CRITICAL
HIGH
MEDIUM
LOW
PASS
WARNING

Finding detail must follow:

WHAT
WHY
EVIDENCE
IMPACT
REMEDIATION
VERIFY

Example:

CRITICAL

Telnet is enabled

Why:
Telnet transmits credentials without encryption.

Evidence:
service telnet enabled

Impact:
Credentials may be intercepted.

Remediation:

no ip telnet server

[ Copy CLI ]

[ Mark Remediated ]

[ Verify Fix ]

==================================================
36. COMPLIANCE UI
==================================================

Framework page:

CIS
NIST SP 800-53
DISA STIG
ISO/IEC 27001

Show:

Overall score
Passed
Failed
Warning
Not Assessable
Not Applicable

Framework detail:

Controls
Rules
Evidence
Findings
Mapping
History

==================================================
37. AI SECURITY UI
==================================================

Do NOT make AI screens look like ChatGPT.

Instead:

AI Security Insight

Finding:
Weak SSH configuration detected

Confidence:
94%

Evidence:
Relevant configuration lines

Interpretation:
The device allows a weak SSH configuration.

Suggested control:
SSH security policy

[ Approve ]
[ Edit ]
[ Reject ]

AI is advisory.

Deterministic compliance rules remain authoritative.

==================================================
38. AI TRAINING CENTER
==================================================

Split screen:

LEFT:

Raw configuration

RIGHT:

AI interpretation

Show:

Detected syntax

Vendor

Device family

Suggested normalized control

Confidence

Reasoning/evidence

Buttons:

[ Approve Mapping ]

[ Edit Mapping ]

[ Reject ]

Mapping lifecycle:

PENDING
REVIEWED
APPROVED
ACTIVE
DEPRECATED

Use clear status badges.

==================================================
39. RISK UI
==================================================

Risk overview:

Overall Risk
Critical Assets
Critical Findings
Risk Trend

Risk visualization should be useful, not decorative.

If using a graph:

Device
 ↓
Finding
 ↓
Control
 ↓
Framework
 ↓
Risk

Animate node entrance subtly.

==================================================
40. WHAT-IF HARDENING
==================================================

Provide:

Current Security Score
82

After Hardening
91

Difference
+9

Example:

Current:

Telnet enabled
Weak SSH
No NTP

Simulation:

Telnet disabled
SSH hardened
NTP enabled

Show:

82 → 91

Clearly label:

SIMULATION ONLY

Do not imply that the actual device has been changed.

==================================================
41. CONFIGURATION DRIFT
==================================================

Show:

Previous Security Score
91

Current
82

Change
-9

Security-relevant changes:

Telnet enabled
Logging changed
SSH policy weakened

Show:

[ View Configuration Diff ]

Use a clear diff viewer.

==================================================
42. REMEDIATION
==================================================

Remediation page:

Finding

Recommended action

Generated CLI

Risk reduction

Verification

Example:

Recommended Remediation

Disable Telnet

CLI:

no ip telnet server

[ Copy CLI ]

[ Generate Again ]

[ Verify Fix ]

Never automatically apply production changes without explicit authorization.

==================================================
43. REPORTS
==================================================

Reports:

Executive Report
Device Report
Compliance Report
Evidence Report
Risk Report
Audit Report

Use clean report cards.

Example:

Executive Security Report

Security Score
82

Compliance
84%

Critical Findings
8

Risk Trend
Improving

[ Generate Report ]

[ Export PDF ]

==================================================
44. ADMIN PANEL
==================================================

Administration should use a settings/control-center layout.

Sections:

Users
Roles & Permissions
Organizations
Integrations
AI Providers
Frameworks
Rule Packs
Retention
Audit Logs
System Settings

Use a left settings navigation.

Example:

Administration

Identity
  Users
  Roles

Security
  Sessions
  Audit Logs

Compliance
  Frameworks
  Rule Packs

AI
  Providers
  Models
  Training

System
  Integrations
  Retention
  General

==================================================
45. USERS
==================================================

User table:

Name
Email
Role
Status
Last Login
MFA
Actions

Actions:

View
Edit
Disable
Reset Password

Destructive actions require confirmation.

==================================================
46. ROLES & PERMISSIONS
==================================================

Show permissions clearly.

Example:

Role:
Network Engineer

Devices:
View ✓
Create ✓
Edit ✓
Delete ✕

Audits:
View ✓
Run ✓
Delete ✕

Administration:
View ✕
Manage ✕

Do not rely only on frontend hiding.

Backend authorization must remain authoritative.

==================================================
47. AUDIT LOGS
==================================================

Audit log table:

Timestamp
User
Action
Resource
Result
IP
Details

Example:

10:42:13
admin
RUN_AUDIT
Device: Cisco-R1
SUCCESS

Clicking a row opens detailed event information.

==================================================
48. NOTIFICATIONS
==================================================

Bottom-right toast.

Examples:

✓ Audit completed

⚠ 3 new high-severity findings

✓ Device added

✕ Discovery failed

Toast duration:
approximately 3–5 seconds.

Critical errors should remain visible until dismissed if necessary.

==================================================
49. MODALS
==================================================

Use modals only for decisions.

Good:

Delete device?
Disable user?
Approve AI mapping?
Start audit?

Bad:

Showing entire pages inside giant modals.

Modal animation:
fade + slight scale

200–250ms.

==================================================
50. TABLE DESIGN
==================================================

Tables should:

- Have strong column hierarchy
- Support sorting
- Support filtering
- Support pagination
- Have compact rows
- Have subtle hover
- Show clear status
- Support row selection where needed

Do not create spreadsheet-like visual noise.

==================================================
51. FILTER DESIGN
==================================================

Use filter bars.

Example:

Severity
[ All ▼ ]

Status
[ Open ▼ ]

Framework
[ CIS ▼ ]

Device
[ All ▼ ]

Date
[ Last 30 days ▼ ]

[ Clear Filters ]

Do not hide important filters inside unnecessarily deep menus.

==================================================
52. SEARCH
==================================================

Global search should be available.

Search:

Devices
Audits
Findings
Controls
Configurations
Reports

Results grouped by type.

Example:

Devices
Cisco-R1
192.168.1.1

Findings
Telnet enabled

Controls
CIS-SSH-01

==================================================
53. LOADING STATES
==================================================

Use skeleton loaders.

Do NOT use random spinners everywhere.

For known operations, show meaningful state.

Example:

Audit:

Detecting device...
Parsing configuration...
Normalizing controls...
Evaluating compliance...
Calculating risk...
Generating remediation...

Discovery:

Detecting network...
Scanning hosts...
Checking ports...
Identifying devices...

==================================================
54. ANIMATION SYSTEM
==================================================

Use consistent motion.

Hover:
120–160ms

Press:
80–120ms

Dropdown:
150–200ms

Panel:
180–250ms

Modal:
200–250ms

Page transition:
200–300ms

Use:

- Count-up numbers
- Progress bars
- Circular score animation
- Tab indicator animation
- Toast slide/fade
- Modal fade/scale
- Sidebar collapse
- Discovery progress
- Audit step progression
- Graph node entrance
- Before/after score animation
- Skeleton loading

Avoid:

- Bouncing buttons
- Excessive particles
- Infinite animations
- Neon glow everywhere
- 3D effects
- Long transitions
- Excessive parallax

==================================================
55. ACCESSIBILITY
==================================================

Support:

Keyboard navigation

Visible focus states

ARIA labels

Readable contrast

Reduced-motion preference

Do not depend only on color.

For users with reduced motion:

Disable decorative animations.

Keep functional transitions minimal.

==================================================
56. RESPONSIVE DESIGN
==================================================

Desktop first because this is an enterprise SOC product.

But support:

Laptop
Tablet
Mobile

On smaller screens:

Sidebar becomes drawer.

Tables become horizontally scrollable or card-based.

Do not simply shrink everything.

==================================================
57. EMPTY STATES
==================================================

Every major page needs a useful empty state.

Example:

No devices yet

Discover your authorized network to automatically identify devices.

[ Start Discovery ]

or

[ Add Device Manually ]

Do not show empty blank screens.

==================================================
58. ERROR STATES
==================================================

Every API-driven page must handle:

Loading
Success
Empty
Error
Retry

Example:

Unable to load devices

Something went wrong while retrieving device information.

[ Try Again ]

==================================================
59. SECURITY UX
==================================================

Security is a core product requirement.

Discovery must only operate against networks/devices the user is authorized to assess.

Do NOT implement:

- Credential spraying
- Brute force
- Exploitation
- Unauthorized scanning
- Automatic credential guessing
- Automatic production configuration changes

Authentication must remain user-controlled.

Open port detection is not the same as authenticated service access.

==================================================
60. AUTOMATIC NETWORK DISCOVERY
==================================================

The desired UX:

User logs in

↓

Discovery page

↓

Automatically detect active interface

↓

Determine local IPv4

↓

Determine subnet mask

↓

Determine CIDR

↓

Determine gateway

↓

Show detected network

↓

User confirms authorized network

↓

Scan

↓

Discover hosts

↓

Detect management ports

↓

Identify services

↓

Identify device/vendor/OS

↓

User selects devices

↓

Add devices

↓

Existing audit pipeline begins

Manual CIDR entry remains available.

==================================================
61. DISCOVERY API
==================================================

If the existing architecture supports it, use endpoints similar to:

POST /api/v1/discovery/detect-network

POST /api/v1/discovery/scan

GET /api/v1/discovery/{scan_id}

POST /api/v1/discovery/{scan_id}/cancel

POST /api/v1/discovery/import

Adapt names to the existing backend conventions.

Do not create duplicate architectures.

==================================================
62. DEVICE DATA
==================================================

A device should support:

Vendor
Product Family
Model
OS / Version
Configuration Format
Serial
Hostname
Management IP
Management Port
Service
Detection Confidence
Discovery Source
Status
Last Seen

Reuse existing device models where available.

==================================================
63. DISCOVERY HISTORY
==================================================

Create:

Discovery History

Show:

Scan ID
Network
Started
Duration
Hosts Found
Devices Identified
Status
Started By

Click for details.

==================================================
64. DATA VISUALIZATION
==================================================

Charts should communicate information.

Useful charts:

Risk trend
Compliance trend
Severity distribution
Framework comparison
Device security distribution
Finding trend

Avoid charts that exist only to fill space.

No unnecessary pie charts.

Prefer:

Line
Bar
Progress
Radial score
Stacked severity

==================================================
65. MICRO-INTERACTIONS
==================================================

Use subtle interactions:

Button hover
Row hover
Copy confirmation
Tab selection
Status changes
Filter updates
Progress updates
Expand/collapse

Example:

[ Copy CLI ]

↓

[ ✓ Copied ]

Return to normal after a short delay.

==================================================
66. DESIGN CONSISTENCY
==================================================

Create reusable components:

Button
Input
Select
Badge
Card
Modal
Drawer
Tabs
Table
Toast
Tooltip
Dropdown
Progress
Skeleton
EmptyState
ErrorState
PageHeader
StatCard
SeverityBadge
StatusBadge
CodeViewer
DiffViewer
Timeline
ScoreCard
FindingCard

Do not create slightly different versions of the same component on every page.

==================================================
67. DESIGN TOKENS
==================================================

Centralize:

Colors
Typography
Spacing
Radius
Shadows
Transitions
Breakpoints
Button sizes
Input sizes
Severity colors
Status colors

Do not hardcode random values throughout the project.

==================================================
68. EXISTING CODEBASE RULE
==================================================

Before modifying anything:

1. Inspect frontend architecture.
2. Inspect routing.
3. Inspect existing components.
4. Inspect current auth implementation.
5. Inspect backend APIs.
6. Inspect database models.
7. Inspect RBAC.
8. Inspect discovery/detection code.
9. Inspect audit pipeline.
10. Identify reusable components.

Then provide a short report:

- Current architecture
- Existing UI system
- What already works
- What is missing
- Files/components to modify
- New files required
- Potential conflicts

Only then start implementation.

==================================================
69. IMPLEMENTATION STRATEGY
==================================================

Implement incrementally.

PHASE 1
Design system

- Colors
- Typography
- Spacing
- Buttons
- Inputs
- Cards
- Badges
- Tables
- Modals
- Toasts
- Skeletons

PHASE 2
Authentication

- Login
- Register
- Forgot password
- Reset password
- MFA
- Session expired
- 403
- 404

PHASE 3
Application shell

- Sidebar
- Topbar
- Breadcrumbs
- Global search
- Notifications
- User menu

PHASE 4
Role-based dashboards

- Platform Admin
- Security Admin
- Network Engineer
- Security Analyst
- CISO
- Auditor

PHASE 5
Core network UX

- Devices
- Discovery
- Configurations
- Device details

PHASE 6
Security workflows

- Audits
- Findings
- Risk
- Drift
- Remediation

PHASE 7
Compliance

- Frameworks
- Controls
- Rule Packs
- Evidence
- Cross-framework mapping

PHASE 8
AI

- AI Insights
- Training Center
- Learned Mappings
- AI Evaluation

PHASE 9
Reports

- Executive
- Device
- Compliance
- Evidence
- Risk
- Audit

PHASE 10
Administration

- Users
- Roles
- Organizations
- Integrations
- AI providers
- Frameworks
- Rule packs
- Retention
- Audit logs
- System settings

==================================================
70. IMPORTANT UX RULES
==================================================

Do not make every page look identical.

Use the same DESIGN SYSTEM,
but different INFORMATION HIERARCHY.

CISO:
high-level business/security posture.

Auditor:
evidence and compliance.

Network Engineer:
devices and configuration.

Security Analyst:
findings and risk.

Security Admin:
security operations.

Platform Admin:
system administration.

==================================================
71. FINAL QUALITY CHECK
==================================================

Before considering the UI complete, verify:

Authentication works.

Login has proper loading/error states.

Forgot password works.

MFA UI exists.

Session expiration is handled.

RBAC changes navigation.

403/404 exist.

Dashboard is understandable immediately.

Discovery automatically detects local network where supported.

Manual CIDR remains available.

Discovery shows real-time progress.

Ports are detected correctly.

SSH is not assumed to always be port 22.

Open port is distinguished from confirmed service.

Device details are clear.

Configuration viewer is readable.

Audit progress is understandable.

Findings follow:
WHAT → WHY → EVIDENCE → IMPACT → REMEDIATION → VERIFY

Compliance is easy to navigate.

AI suggestions show confidence and evidence.

Human approval is required for AI mappings.

Risk visualization is useful.

Drift is understandable.

What-if hardening clearly says SIMULATION ONLY.

Remediation does not silently modify production devices.

Reports are accessible.

Admin panel is organized.

Tables support filtering/search/sorting.

Loading/empty/error states exist.

Animations are consistent.

Reduced motion is supported.

No excessive visual effects.

No duplicated UI components.

No broken routes.

No console errors.

No obvious accessibility violations.

==================================================
72. MOST IMPORTANT PRINCIPLE
==================================================

Make NetSentinel AI feel like a REAL enterprise security product.

It should feel:

Professional
Technical
Trustworthy
Fast
Clear
Intelligent
Operational
Evidence-driven

NOT:

Flashy
Gaming-like
Over-animated
Generic SaaS
AI chatbot-like

The final experience should make a security professional feel:

"I immediately understand the state of my network,
I know what is risky,
I know why it is risky,
I can see the evidence,
and I know exactly what to do next."

Start by inspecting the existing project and report your architecture findings before making major changes.