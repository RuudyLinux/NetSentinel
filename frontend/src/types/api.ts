export interface DeviceOut {
  id: number;
  name: string;
  vendor: string;
  os: string;
  os_version: string | null;
}

export interface DiscoveredHost {
  device_name: string;
  ip: string;
  status: "ssh_available" | "ssh_unavailable";
  port: number | null;
  vendor: string | null;
}

export interface DiscoverResponse {
  hosts: DiscoveredHost[];
}

export interface LocalNetworkResponse {
  interface: string;
  local_ip: string;
  cidr: string;
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
  detection: {
    vendor: string | null;
    os: string | null;
    confidence: number | null;
    reasons: string[];
    override: string | null;
  };
  fail_counts: Record<string, number>;
}

export interface AuditDetail extends AuditSummary {
  controls: {
    key: string;
    value: unknown;
    source_lines: number[];
    excerpt: string;
    parser_confidence: number;
    origin: string;
  }[];
  results: {
    rule_id: string;
    parameter: string;
    observed_value: unknown;
    expected_value: unknown;
    status: string;
    severity: string;
    evidence_lines: number[];
    evidence_excerpt: string;
  }[];
  unknown_constructs: { text: string; lineno: number; block: string | null }[];
  parse_warnings: Record<string, unknown>[];
}

export interface DashboardSummary {
  security_score: number | null;
  security_score_previous: number | null;
  security_coverage: number | null;
  devices_total: number;
  devices_needing_attention: number;
  critical_findings_open: number;
  critical_findings_new_7d: number;
  audits_total: number;
  framework_scores: { framework: string; framework_version: string; score: number; coverage: number }[];
  risk_trend: { date: string; score: number }[];
  recent_findings: {
    id: number;
    title: string;
    severity: string;
    device_name: string;
    audit_run_id: number;
  }[];
}

export interface ReportSummary {
  id: number;
  audit_run_id: number;
  device_name: string;
  framework: string;
  framework_version: string;
  created_at: string;
}

export interface AdminUserOut {
  id: number;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface RoleOut {
  name: string;
  permissions: string[];
}

export interface AuditLogEntry {
  id: number;
  created_at: string;
  user_email: string;
  action: string;
  resource: string;
  result: string;
  ip: string;
}

export interface AuditLogPage {
  entries: AuditLogEntry[];
  next_before_id: number | null;
}

export interface FrameworkOut {
  framework: string;
  framework_version: string;
  rule_count: number;
  sha256: string;
}

export interface ComplianceBreakdown {
  framework: string;
  framework_version: string;
  score: number | null;
  devices_assessed: number;
  pass_count: number;
  fail_count: number;
  warning_count: number;
  not_assessable_count: number;
  not_applicable_count: number;
}

export interface RuleOut {
  id: string;
  framework: string;
  framework_version: string;
  title: string;
  description: string;
  impact: string;
  parameter: string;
  severity: string;
  source: string;
}

export interface FindingSummary {
  id: number;
  audit_run_id: number;
  device_id: number;
  device_name: string;
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
  impact: string;
  observed_value: unknown;
  expected_value: unknown;
  evidence_lines: number[];
  evidence_excerpt: string;
  notes: string;
  remediation: {
    id: string;
    title: string;
    cli: string;
    verification: string;
    rollback: string;
    notes: string;
    banner: string;
  };
}
