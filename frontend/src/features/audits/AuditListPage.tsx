import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import type { AuditSummary } from "../../types/api";

export function AuditListPage() {
  const { data = [], isLoading } = useQuery({
    queryKey: ["audits"],
    queryFn: () => api.get<AuditSummary[]>("/audits"),
  });

  if (isLoading) return <p className="text-slate-400">Loading…</p>;
  if (!data.length)
    return <p className="text-slate-400">No audits yet. Upload a configuration to begin.</p>;

  return (
    <table className="w-full text-sm">
      <thead className="text-left text-slate-400">
        <tr className="border-b border-slate-800">
          <th className="py-2">Device</th>
          <th>Framework</th>
          <th>Score</th>
          <th>Coverage</th>
          <th>Critical</th>
          <th>High</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {data.map((audit) => (
          <tr key={audit.id} className="border-b border-slate-900 hover:bg-slate-900">
            <td className="py-2 font-medium">{audit.device_name}</td>
            <td>
              {audit.framework} {audit.framework_version}
            </td>
            <td className="tabular-nums">{audit.score}</td>
            <td className="tabular-nums">{Math.round((audit.coverage ?? 0) * 100)}%</td>
            <td className="tabular-nums">{audit.fail_counts.CRITICAL ?? 0}</td>
            <td className="tabular-nums">{audit.fail_counts.HIGH ?? 0}</td>
            <td>
              <Link to={`/audits/${audit.id}`} className="text-sky-400 hover:underline">
                Open
              </Link>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
