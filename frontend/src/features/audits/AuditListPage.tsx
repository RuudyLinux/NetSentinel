import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import type { AuditSummary } from "../../types/api";

export function AuditListPage() {
  const { data = [], isLoading, isError } = useQuery({
    queryKey: ["audits"],
    queryFn: () => api.get<AuditSummary[]>("/audits"),
  });

  if (isLoading) return <p className="text-text-secondary">Loading…</p>;
  if (isError) return <p className="text-text-secondary">Couldn't load audits. Try refreshing.</p>;
  if (!data.length)
    return <p className="text-text-secondary">No audits yet. Upload a configuration to begin.</p>;

  return (
    <table className="w-full text-sm">
      <thead className="text-left text-text-secondary">
        <tr className="border-b border-border">
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
          <tr key={audit.id} className="border-b border-border hover:bg-surface">
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
