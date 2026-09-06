import type { Tone } from "../components/ui/Badge";

/**
 * The single source of truth for "what does this deployment actually support"
 * claims in the UI. A vendor/framework only ever gets to "supported" here once
 * a real detector+parser+normalizer (or rule pack) exists for it in the
 * backend — see backend/app/services/{detection,parsing,normalization}/registry.py
 * and backend/rules/. Never mark something supported to make a page look more
 * complete than the system actually is.
 */
export type CapabilityLevel = "supported" | "beta" | "planned";

export interface Capability {
  level: CapabilityLevel;
  label: string;
  tone: Tone;
}

const LEVELS: Record<CapabilityLevel, Omit<Capability, "level">> = {
  supported: { label: "Supported", tone: "pass" },
  beta: { label: "Beta", tone: "warning" },
  planned: { label: "Planned", tone: "neutral" },
};

// Cisco IOS/IOS-XE: full detector + parser + normalizer + CIS/NIST rule packs.
// FortiOS: same, but a narrower normalized-control surface (see
// backend/app/services/normalization/fortinet.py's module docstring) — real,
// not fake, but young enough to label Beta rather than Supported.
// Juniper/Palo Alto: no parser/normalizer exists yet (services/parsing/registry.py
// raises UnsupportedVendorError for both) — Planned, not Supported.
const VENDOR_CAPABILITIES: Record<string, CapabilityLevel> = {
  cisco: "supported",
  fortinet: "beta",
  juniper: "planned",
  paloalto: "planned",
};

const FRAMEWORK_CAPABILITIES: Record<string, CapabilityLevel> = {
  CIS: "supported",
  NIST: "supported",
  STIG: "planned",
  ISO: "planned",
};

function resolve(level: CapabilityLevel | undefined): Capability {
  const known = level ?? "planned";
  return { level: known, ...LEVELS[known] };
}

export function vendorCapability(vendor: string): Capability {
  return resolve(VENDOR_CAPABILITIES[vendor.toLowerCase()]);
}

export function frameworkCapability(framework: string): Capability {
  return resolve(FRAMEWORK_CAPABILITIES[framework.toUpperCase()]);
}
