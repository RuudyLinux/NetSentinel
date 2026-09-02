import { useQuery } from "@tanstack/react-query";
import { ShieldOff } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import { EmptyState } from "../../components/ui/EmptyState";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { FindingSummary } from "../../types/api";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const TRIAGE_STATUSES = ["open", "accepted_risk", "false_positive", "resolved"];

const selectClass =
  "h-9 rounded-md border border-border-strong bg-canvas px-2 text-sm text-text-primary";

export function FindingsPage() {
  const [severity, setSeverity] = useState("");
  const [triageStatus, setTriageStatus] = useState("");

  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (triageStatus) params.set("triage_status", triageStatus);
  const query = params.toString();

  const { data, isLoading } = useQuery({
    queryKey: ["findings", { severity, triageStatus }],
    queryFn: () => api.get<FindingSummary[]>(`/findings${query ? `?${query}` : ""}`),
  });

  return (
    <div>
      <PageHeader title="Findings" subtitle="Every open and resolved finding across your fleet." />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={selectClass}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={triageStatus}
          onChange={(e) => setTriageStatus(e.target.value)}
          className={selectClass}
        >
          <option value="">All statuses</option>
          {TRIAGE_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.replace("_", " ")}
            </option>
          ))}
        </select>
      </div>

      {isLoading && <p className="text-text-secondary">Loading…</p>}

      {!isLoading && data && data.length === 0 && (
        <EmptyState
          icon={ShieldOff}
          title="No findings"
          description="Nothing matches these filters, or no audits have run yet."
        />
      )}

      {data && data.length > 0 && (
        <div className="overflow-x-auto rounded-card border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-left text-text-tertiary">
              <tr className="border-b border-border">
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Title</th>
                <th className="px-4 py-2 font-medium">Device</th>
                <th className="px-4 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.map((finding) => (
                <tr key={finding.id} className="border-b border-border last:border-0 hover:bg-surface">
                  <td className="px-4 py-2.5">
                    <SeverityBadge value={finding.severity} />
                  </td>
                  <td className="px-4 py-2.5">
                    <Link to={`/findings/${finding.id}`} className="font-medium text-sky-400 hover:underline">
                      {finding.title}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-text-secondary">
                    <Link to={`/devices/${finding.device_id}`} className="hover:underline">
                      {finding.device_name}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-text-secondary">{finding.triage_status.replace("_", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
