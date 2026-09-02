import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import { Badge } from "../../components/ui/Badge";
import { Card } from "../../components/ui/Card";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { ComplianceBreakdown, FindingSummary, RuleOut } from "../../types/api";

export function ComplianceDetailPage() {
  const { framework } = useParams();

  const compliance = useQuery({
    queryKey: ["compliance", framework],
    queryFn: () => api.get<ComplianceBreakdown>(`/frameworks/${framework}/compliance`),
  });
  const rules = useQuery({
    queryKey: ["framework-rules", framework],
    queryFn: () => api.get<RuleOut[]>(`/frameworks/${framework}/rules`),
  });
  const findings = useQuery({
    queryKey: ["findings", { framework }],
    queryFn: () => api.get<FindingSummary[]>(`/findings?framework=${framework}`),
  });

  if (!compliance.data) return <p className="text-text-secondary">Loading…</p>;
  const breakdown = compliance.data;

  return (
    <div className="space-y-6">
      <PageHeader
        title={breakdown.framework}
        subtitle={`Version ${breakdown.framework_version} · ${breakdown.devices_assessed} device${breakdown.devices_assessed === 1 ? "" : "s"} assessed`}
      />

      <Card className="p-5">
        <div className="flex flex-wrap items-center gap-6">
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-text-tertiary">Score</p>
            <p className="mt-1 text-3xl font-semibold tabular-nums text-text-primary">
              {breakdown.score === null ? "—" : `${breakdown.score}%`}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge tone="pass">{breakdown.pass_count} Passed</Badge>
            <Badge tone="critical">{breakdown.fail_count} Failed</Badge>
            <Badge tone="warning">{breakdown.warning_count} Warning</Badge>
            <Badge tone="neutral">{breakdown.not_assessable_count} Not Assessable</Badge>
            <Badge tone="neutral">{breakdown.not_applicable_count} Not Applicable</Badge>
          </div>
        </div>
      </Card>

      <Card className="p-5">
        <p className="text-sm font-semibold text-text-primary">Rules ({rules.data?.length ?? 0})</p>
        <div className="mt-3 divide-y divide-border">
          {rules.data?.map((rule) => (
            <div key={rule.id} className="flex items-center justify-between gap-4 py-2.5 first:pt-0 last:pb-0">
              <div className="min-w-0">
                <p className="truncate text-sm text-text-primary">{rule.title}</p>
                <p className="font-mono text-xs text-text-tertiary">{rule.id} · {rule.parameter}</p>
              </div>
              <SeverityBadge value={rule.severity} />
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-5">
        <p className="text-sm font-semibold text-text-primary">Findings ({findings.data?.length ?? 0})</p>
        {findings.data && findings.data.length === 0 ? (
          <p className="mt-3 text-sm text-text-tertiary">No findings for this framework yet.</p>
        ) : (
          <div className="mt-3 divide-y divide-border">
            {findings.data?.map((finding) => (
              <Link
                key={finding.id}
                to={`/findings/${finding.id}`}
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
