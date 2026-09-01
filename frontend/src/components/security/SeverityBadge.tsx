const STYLES: Record<string, string> = {
  CRITICAL: "bg-red-950 text-red-300 border-red-800",
  HIGH: "bg-orange-950 text-orange-300 border-orange-800",
  MEDIUM: "bg-amber-950 text-amber-300 border-amber-800",
  LOW: "bg-blue-950 text-blue-300 border-blue-800",
  INFO: "bg-slate-800 text-slate-300 border-slate-700",
  PASS: "bg-emerald-950 text-emerald-300 border-emerald-800",
  FAIL: "bg-red-950 text-red-300 border-red-800",
  WARNING: "bg-amber-950 text-amber-300 border-amber-800",
  NOT_ASSESSABLE: "bg-slate-800 text-slate-400 border-slate-700",
  NOT_APPLICABLE: "bg-slate-800 text-slate-500 border-slate-700",
};

/** Always renders the label as text — color alone must never carry the meaning. */
export function SeverityBadge({ value }: { value: string }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${STYLES[value] ?? STYLES.INFO}`}
    >
      {value}
    </span>
  );
}
