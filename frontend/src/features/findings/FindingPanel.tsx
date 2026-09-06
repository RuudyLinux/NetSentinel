import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";
import { Link } from "react-router-dom";
import { SeverityBadge } from "../../components/security/SeverityBadge";
import { Button } from "../../components/ui/Button";
import { useToast } from "../../lib/useToast";
import { api } from "../../lib/api";
import { RequirePermission } from "../../lib/auth";
import { Permission } from "../../lib/permissions";
import type { FindingDetail } from "../../types/api";

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-text-tertiary">{label}</h3>
      <div className="mt-1.5">{children}</div>
    </section>
  );
}

/**
 * WHAT → WHY → EVIDENCE → IMPACT → REMEDIATION → VERIFY, per latest.md
 * section 35. Used both embedded (AuditDetailPage's split view) and
 * standalone (FindingDetailPage) — one component, no near-duplicate.
 */
export function FindingPanel({ findingId }: { findingId: number }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { data, isError } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api.get<FindingDetail>(`/findings/${findingId}`),
  });

  const markRemediated = useMutation({
    mutationFn: () => api.patch(`/findings/${findingId}`, { triage_status: "resolved" }),
    onSuccess: () => {
      toast.push("Finding marked remediated", "success");
      queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
    onError: (error: Error) => toast.push(error.message, "error"),
  });

  async function copyCli() {
    if (!data) return;
    await navigator.clipboard.writeText(data.remediation.cli);
    toast.push("Copied", "success");
  }

  if (isError) {
    return (
      <p className="rounded-card border border-border bg-surface p-5 text-sm text-text-secondary">
        Finding not found or you don't have access to it.
      </p>
    );
  }
  if (!data) return <p className="text-text-secondary">Loading finding…</p>;

  return (
    <div className="space-y-5 rounded-card border border-border bg-surface p-5">
      <div>
        <div className="flex items-center gap-3">
          <SeverityBadge value={data.severity} />
          <h2 className="font-semibold text-text-primary">{data.title}</h2>
        </div>
        <p className="mt-1 text-xs text-text-tertiary">
          {data.rule_id} ·{" "}
          <Link to={`/devices/${data.device_id}`} className="text-sky-400 hover:underline">
            {data.device_name}
          </Link>
        </p>
      </div>

      <Section label="Why">
        <p className="text-sm text-text-secondary">{data.description}</p>
      </Section>

      <Section label="Evidence">
        <pre className="overflow-x-auto rounded-md bg-canvas p-3 font-mono text-xs text-text-secondary">
          {data.evidence_excerpt || "(no matching configuration line)"}
        </pre>
        <p className="mt-1 text-xs text-text-tertiary">
          Line(s) {data.evidence_lines.join(", ") || "—"} · observed {String(data.observed_value)} ·
          expected {String(data.expected_value)}
        </p>
      </Section>

      <Section label="Impact">
        <p className="text-sm text-text-secondary">{data.impact}</p>
      </Section>

      <Section label="Remediation">
        <pre className="overflow-x-auto rounded-md bg-canvas p-3 font-mono text-xs text-pass">
          {data.remediation.cli}
        </pre>
        <p className="mt-2 rounded-md border border-warning-border bg-warning-surface p-2 text-xs text-warning">
          {data.remediation.banner}
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="button" variant="secondary" onClick={copyCli}>
            <Copy className="size-4" /> Copy CLI
          </Button>
          <RequirePermission perm={Permission.FINDING_TRIAGE}>
            <Button
              type="button"
              variant="secondary"
              disabled={data.triage_status === "resolved"}
              loading={markRemediated.isPending}
              loadingLabel="Saving…"
              onClick={() => markRemediated.mutate()}
            >
              {data.triage_status === "resolved" ? (
                <>
                  <Check className="size-4" /> Remediated
                </>
              ) : (
                "Mark Remediated"
              )}
            </Button>
          </RequirePermission>
        </div>
      </Section>

      <Section label="Verify">
        <p className="text-sm text-text-secondary">
          Verify: <code className="font-mono text-xs">{data.remediation.verification}</code>
        </p>
        <p className="mt-1 text-xs text-text-tertiary">
          Findings are tied to the configuration audited — there's no live device check. Connect to
          or re-upload this device's updated configuration and re-audit to confirm the fix.
        </p>
        <Link to={`/devices/${data.device_id}`} className="mt-2 inline-block">
          <Button type="button" variant="secondary">
            Verify Fix
          </Button>
        </Link>
      </Section>

      <Section label="Provenance">
        <dl className="grid grid-cols-2 gap-1 text-xs text-text-tertiary">
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
      </Section>
    </div>
  );
}
