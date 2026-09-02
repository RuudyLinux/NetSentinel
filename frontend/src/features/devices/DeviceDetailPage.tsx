import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { ScoreRing } from "../../components/security/ScoreRing";
import { Card } from "../../components/ui/Card";
import { EmptyState } from "../../components/ui/EmptyState";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { AuditSummary, DeviceOut } from "../../types/api";

export function DeviceDetailPage() {
  const { id } = useParams();

  const device = useQuery({
    queryKey: ["device", id],
    queryFn: () => api.get<DeviceOut>(`/devices/${id}`),
  });
  const audits = useQuery({
    queryKey: ["audits", { device_id: id }],
    queryFn: () => api.get<AuditSummary[]>(`/audits?device_id=${id}`),
  });

  if (!device.data) return <p className="text-text-secondary">Loading…</p>;
  const latest = audits.data?.[0];

  return (
    <div className="space-y-6">
      <PageHeader
        title={device.data.name}
        subtitle={`${device.data.vendor} · ${device.data.os}${device.data.os_version ? ` ${device.data.os_version}` : ""}`}
      />

      <div className="grid gap-4 md:grid-cols-3">
        <ScoreRing score={latest?.score ?? null} coverage={latest?.coverage ?? null} />
        <Card className="p-6 text-sm md:col-span-2">
          <p className="font-semibold text-text-primary">Overview</p>
          <dl className="mt-2 grid grid-cols-2 gap-2 text-text-secondary">
            <div>
              <dt className="text-xs text-text-tertiary">Vendor</dt>
              <dd>{device.data.vendor}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-tertiary">OS</dt>
              <dd>{device.data.os}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-tertiary">OS Version</dt>
              <dd>{device.data.os_version ?? "—"}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-tertiary">Audits run</dt>
              <dd>{audits.data?.length ?? 0}</dd>
            </div>
          </dl>
        </Card>
      </div>

      <Card className="p-5">
        <p className="text-sm font-semibold text-text-primary">Recent Audits</p>
        {audits.data && audits.data.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No audits yet"
            description="Run an audit against this device's configuration to see results here."
          />
        ) : (
          <div className="mt-3 divide-y divide-border">
            {audits.data?.map((audit) => (
              <Link
                key={audit.id}
                to={`/audits/${audit.id}`}
                className="flex items-center justify-between gap-4 py-3 first:pt-0 last:pb-0 hover:bg-surface-raised"
              >
                <div>
                  <p className="text-sm text-text-primary">
                    {audit.framework} {audit.framework_version}
                  </p>
                  <p className="text-xs text-text-tertiary">Coverage {Math.round((audit.coverage ?? 0) * 100)}%</p>
                </div>
                <p className="tabular-nums text-sm font-medium text-text-primary">{audit.score ?? "—"}</p>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
