export function ScoreRing({
  score,
  coverage,
  deltaLabel,
}: {
  score: number | null;
  coverage: number | null;
  deltaLabel?: string;
}) {
  const value = score ?? 0;
  const tone = value >= 80 ? "text-emerald-400" : value >= 50 ? "text-amber-400" : "text-red-400";
  return (
    <div className="rounded-card border border-border bg-surface p-6">
      <div className={`text-5xl font-semibold tabular-nums ${tone}`}>
        {value}
        <span className="text-2xl text-text-tertiary"> / 100</span>
      </div>
      <p className="mt-1 text-sm text-text-secondary">
        Posture score · {Math.round((coverage ?? 0) * 100)}% of controls assessable
      </p>
      {deltaLabel && <p className="mt-1 text-xs text-text-secondary">{deltaLabel}</p>}
      <p className="mt-2 text-xs text-text-tertiary">
        An indicator of configuration hardening, not a compliance certification.
      </p>
    </div>
  );
}
