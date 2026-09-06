import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { EmptyState } from "../../components/ui/EmptyState";
import { ScoreRing } from "../../components/security/ScoreRing";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import { api } from "../../lib/api";
import { FindingPanel } from "../findings/FindingPanel";
import { UnknownConstructsPanel } from "./UnknownConstructsPanel";
import type { AuditDetail, FindingSummary } from "../../types/api";

export function AuditDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [selected, setSelected] = useState<number | null>(null);

  const audit = useQuery({
    queryKey: ["audit", id],
    queryFn: () => api.get<AuditDetail>(`/audits/${id}`),
  });
  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.get<FindingSummary[]>(`/findings?audit_id=${id}`),
  });

  if (audit.isError) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="Audit not found"
        description="This audit doesn't exist or you don't have access to it."
        action={<Button onClick={() => navigate("/audits")}>Back to Audits</Button>}
      />
    );
  }
  if (!audit.data) return <p className="text-text-secondary">Loading…</p>;
  const detail = audit.data;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <ScoreRing score={detail.score} coverage={detail.coverage} />
        <div className="rounded-xl border border-border bg-surface p-6 text-sm">
          <h2 className="font-semibold">{detail.device_name}</h2>
          <p className="mt-1 text-text-secondary">
            {detail.detection.vendor} {detail.detection.os} · detection confidence{" "}
            {Math.round((detail.detection.confidence ?? 0) * 100)}%
          </p>
          <ul className="mt-2 space-y-0.5 text-xs text-text-tertiary">
            {detail.detection.reasons.map((reason) => (
              <li key={reason}>· {reason}</li>
            ))}
          </ul>
        </div>
        <div className="rounded-xl border border-border bg-surface p-6 text-sm">
          <h2 className="font-semibold">Audit provenance</h2>
          <dl className="mt-2 space-y-1 text-xs text-text-secondary">
            <div>
              Framework: {detail.framework} {detail.framework_version}
            </div>
            <div className="font-mono">Rule pack: {detail.rule_pack_hash.slice(0, 16)}…</div>
            <div>Engine: {detail.engine_version}</div>
            <div>Unrecognized commands: {detail.unknown_constructs.length}</div>
          </dl>
          <a
            className="mt-3 inline-block rounded bg-sky-600 px-3 py-1 text-xs hover:bg-sky-500"
            href="#"
            onClick={async (event) => {
              event.preventDefault();
              const report = await api.post<{ id: number }>(`/audits/${detail.id}/report`);
              const blob = await api.get<Blob>(`/reports/${report.id}`);
              const url = URL.createObjectURL(blob);
              window.open(url, "_blank");
            }}
          >
            Generate PDF report
          </a>
        </div>
      </div>

      <UnknownConstructsPanel auditId={detail.id} />

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-1">
          <h2 className="mb-2 font-semibold">Findings ({findings.data?.length ?? 0})</h2>
          {(findings.data ?? []).map((finding) => (
            <button
              key={finding.id}
              onClick={() => setSelected(finding.id)}
              className={`flex w-full items-center gap-3 rounded border p-2 text-left text-sm ${
                selected === finding.id
                  ? "border-sky-700 bg-surface"
                  : "border-border hover:bg-surface"
              }`}
            >
              <SeverityBadge value={finding.severity} />
              <span className="flex-1">{finding.title}</span>
              <span className="font-mono text-xs text-text-tertiary">{finding.rule_id}</span>
            </button>
          ))}
        </div>
        <div>
          {selected ? <FindingPanel findingId={selected} /> : <p className="text-text-tertiary">Select a finding.</p>}
        </div>
      </div>
    </div>
  );
}
