import type { ReactNode } from "react";
import { useCountUp } from "../../lib/useCountUp";
import { Card } from "./Card";

/** KPI tile with a once-on-load count-up, per latest.md section 26. */
export function StatCard({
  label,
  value,
  suffix,
  sub,
  tone = "neutral",
}: {
  label: string;
  value: number | null;
  suffix?: string;
  sub?: ReactNode;
  tone?: "neutral" | "critical" | "warning" | "pass";
}) {
  const display = useCountUp(value);
  const toneClass =
    tone === "critical"
      ? "text-critical"
      : tone === "warning"
        ? "text-warning"
        : tone === "pass"
          ? "text-pass"
          : "text-text-primary";

  return (
    <Card className="p-5">
      <p className="text-xs font-medium uppercase tracking-wide text-text-tertiary">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tabular-nums ${toneClass}`}>
        {display === null ? "—" : display}
        {suffix && display !== null && <span className="text-lg text-text-tertiary">{suffix}</span>}
      </p>
      {sub && <p className="mt-1 text-xs text-text-secondary">{sub}</p>}
    </Card>
  );
}
