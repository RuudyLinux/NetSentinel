import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import type { FindingDetail } from "../../types/api";

export function FindingPanel({ findingId }: { findingId: number }) {
  const { data } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api.get<FindingDetail>(`/findings/${findingId}`),
  });
  if (!data) return <p className="text-slate-400">Loading finding…</p>;

  return (
    <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-center gap-3">
        <SeverityBadge value={data.severity} />
        <h2 className="font-semibold">
          {data.rule_id} — {data.title}
        </h2>
      </div>
      <p className="text-sm text-slate-300">{data.description}</p>

      <section>
        <h3 className="text-xs uppercase tracking-wide text-slate-500">Evidence</h3>
        <pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
          {data.evidence_excerpt || "(no matching configuration line)"}
        </pre>
        <p className="mt-1 text-xs text-slate-500">
          Line(s) {data.evidence_lines.join(", ") || "—"} · observed{" "}
          {String(data.observed_value)} · expected {String(data.expected_value)}
        </p>
      </section>

      <section>
        <h3 className="text-xs uppercase tracking-wide text-slate-500">Remediation</h3>
        <pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-emerald-300">
          {data.remediation.cli}
        </pre>
        <p className="mt-1 text-xs text-slate-400">
          Verify: <code>{data.remediation.verification}</code>
        </p>
        <p className="mt-2 rounded border border-amber-900 bg-amber-950/40 p-2 text-xs text-amber-300">
          {data.remediation.banner}
        </p>
      </section>

      <section>
        <h3 className="text-xs uppercase tracking-wide text-slate-500">Provenance</h3>
        <dl className="mt-1 grid grid-cols-2 gap-1 text-xs text-slate-400">
          <dt>Framework</dt>
          <dd>
            {data.framework} {data.framework_version}
          </dd>
          <dt>Parameter</dt>
          <dd className="font-mono">{data.parameter}</dd>
          <dt>Config SHA-256</dt>
          <dd className="font-mono">{data.configuration_sha256.slice(0, 16)}…</dd>
          <dt>Rule pack SHA-256</dt>
          <dd className="font-mono">{data.rule_pack_hash.slice(0, 16)}…</dd>
        </dl>
      </section>
    </div>
  );
}
