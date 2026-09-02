import { Badge, type Tone } from "../ui/Badge";

const TONES: Record<string, Tone> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "neutral",
  PASS: "pass",
  FAIL: "critical",
  WARNING: "warning",
  NOT_ASSESSABLE: "neutral",
  NOT_APPLICABLE: "neutral",
};

/** Always renders the label as text — color alone must never carry the meaning. */
export function SeverityBadge({ value }: { value: string }) {
  return <Badge tone={TONES[value] ?? "neutral"}>{value}</Badge>;
}
