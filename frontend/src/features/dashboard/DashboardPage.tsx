import { useQuery } from "@tanstack/react-query";
import { ShieldQuestion } from "lucide-react";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Link } from "react-router-dom";
import { ScoreRing } from "../../components/security/ScoreRing";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { EmptyState } from "../../components/ui/EmptyState";
import { StatCard } from "../../components/ui/StatCard";
import { api } from "../../lib/api";
import type { DashboardSummary } from "../../types/api";

function scoreDelta(current: number | null, previous: number | null): string | undefined {
  if (current === null || previous === null) return undefined;
  const diff = current - previous;
  if (diff === 0) return "No change from last audit";
  return `${diff > 0 ? "↑" : "↓"} ${Math.abs(diff)} from last audit`;
}

export function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => api.get<DashboardSummary>("/dashboard/summary"),
  });

  if (isLoading) return <p className="text-text-secondary">Loading…</p>;
  if (!data) return <p className="text-text-secondary">Unable to load dashboard.</p>;

  if (data.audits_total === 0) {
    return (
      <EmptyState
        icon={ShieldQuestion}
        title="No audits yet"
        description="Run your first audit to see your security posture here."
        action={
          <Link to="/configurations">
            <Button>Go to Configurations</Button>
          </Link>
        }
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <ScoreRing
          score={data.security_score}
          coverage={data.security_coverage}
          deltaLabel={scoreDelta(data.security_score, data.security_score_previous)}
        />
        <StatCard
          label="Devices"
          value={data.devices_total}
          sub={
            data.devices_needing_attention > 0
              ? `${data.devices_needing_attention} require attention`
              : "All up to date"
          }
          tone={data.devices_needing_attention > 0 ? "warning" : "neutral"}
        />
        <StatCard
          label="Critical Findings"
          value={data.critical_findings_open}
          sub={data.critical_findings_new_7d > 0 ? `${data.critical_findings_new_7d} new this week` : "None new"}
          tone={data.critical_findings_open > 0 ? "critical" : "pass"}
        />
        <StatCard
          label="Audits"
          value={data.audits_total}
          sub={`${data.framework_scores.length} framework${data.framework_scores.length === 1 ? "" : "s"} assessed`}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <p className="text-sm font-semibold text-text-primary">Framework Scores</p>
          <div className="mt-4 space-y-3">
            {data.framework_scores.map((framework) => (
              <div key={framework.framework}>
                <div className="mb-1 flex justify-between text-xs text-text-secondary">
                  <span>
                    {framework.framework} {framework.framework_version}
                  </span>
                  <span className="tabular-nums">{framework.score}%</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-surface-raised">
                  <div
                    className="h-full rounded-full bg-sky-500"
                    style={{ width: `${framework.score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-5">
          <p className="text-sm font-semibold text-text-primary">Risk Trend</p>
          {data.risk_trend.length < 2 ? (
            <p className="mt-4 text-sm text-text-tertiary">Not enough audits yet to show a trend.</p>
          ) : (
            <div className="mt-4 h-40">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data.risk_trend}>
                  <XAxis dataKey="date" tick={{ fontSize: 11, fill: "var(--color-text-tertiary)" }} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "var(--color-text-tertiary)" }} width={28} />
                  <Tooltip
                    contentStyle={{
                      background: "var(--color-surface)",
                      border: "1px solid var(--color-border)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Line type="monotone" dataKey="score" stroke="#0ea5e9" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>

      <Card className="p-5">
        <p className="text-sm font-semibold text-text-primary">Recent Findings</p>
        {data.recent_findings.length === 0 ? (
          <p className="mt-4 text-sm text-text-tertiary">No open findings.</p>
        ) : (
          <div className="mt-3 divide-y divide-border">
            {data.recent_findings.map((finding) => (
              <Link
                key={finding.id}
                to={`/audits/${finding.audit_run_id}`}
                className="flex items-center justify-between gap-4 py-3 first:pt-0 last:pb-0 hover:bg-surface-raised"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm text-text-primary">{finding.title}</p>
                  <p className="text-xs text-text-tertiary">{finding.device_name}</p>
                </div>
                <SeverityBadge value={finding.severity} />
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
