export function ScoreRing({ score, coverage }: { score: number | null; coverage: number | null }) {
  const value = score ?? 0;
  const tone = value >= 80 ? "text-emerald-400" : value >= 50 ? "text-amber-400" : "text-red-400";
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className={`text-5xl font-semibold tabular-nums ${tone}`}>
        {value}
        <span className="text-2xl text-slate-500"> / 100</span>
      </div>
      <p className="mt-1 text-sm text-slate-400">
        Posture score · {Math.round((coverage ?? 0) * 100)}% of controls assessable
      </p>
      <p className="mt-2 text-xs text-slate-500">
        An indicator of configuration hardening, not a compliance certification.
      </p>
    </div>
  );
}
