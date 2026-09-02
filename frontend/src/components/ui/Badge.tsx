export type Tone = "critical" | "high" | "medium" | "low" | "pass" | "warning" | "neutral";

const TONE_STYLES: Record<Tone, string> = {
  critical: "bg-critical-surface text-critical border-critical-border",
  high: "bg-high-surface text-high border-high-border",
  medium: "bg-medium-surface text-medium border-medium-border",
  low: "bg-low-surface text-low border-low-border",
  pass: "bg-pass-surface text-pass border-pass-border",
  warning: "bg-warning-surface text-warning border-warning-border",
  neutral: "bg-neutral-surface text-neutral border-neutral-border",
};

/**
 * Token-driven badge. Never carries meaning by color alone — callers always
 * pass a visible label alongside the tone (section 3: icon/label/badge/text).
 */
export function Badge({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${TONE_STYLES[tone]}`}
    >
      {children}
    </span>
  );
}
