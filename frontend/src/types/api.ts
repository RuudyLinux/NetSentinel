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
  port: number;
}

export interface DiscoverResponse {
  hosts: DiscoveredHost[];
}

export interface LocalNetworkResponse {
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

export interface FindingSummary {
  id: number;
  audit_run_id: number;
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
