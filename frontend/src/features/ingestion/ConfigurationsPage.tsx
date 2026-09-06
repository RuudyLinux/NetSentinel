import { useMutation } from "@tanstack/react-query";
import { Lock, UploadCloud } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { EmptyState } from "../../components/ui/EmptyState";
import { PageHeader } from "../../components/ui/PageHeader";
import { ApiError, api } from "../../lib/api";
import { hasPermission, useAuth } from "../../lib/authHooks";
import { Permission } from "../../lib/permissions";
import type { AuditSummary, ConfigurationOut, DetectionConfirmationDetail } from "../../types/api";

export function ConfigurationsPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [dragging, setDragging] = useState(false);
  const [message, setMessage] = useState("");
  // Set when POST /audits 409s because detection confidence is too low to proceed
  // without an operator decision — offers the same override the API accepts, instead
  // of leaving the upload at a dead end (see audits.py's DetectionConfirmationRequired).
  const [needsConfirmation, setNeedsConfirmation] = useState<{
    configurationId: number;
    detail: DetectionConfirmationDetail;
  } | null>(null);

  const describe = (configuration: ConfigurationOut) =>
    `Detected ${configuration.device.vendor} ${configuration.device.os} · ` +
    `${configuration.secret_hits} secret(s) redacted · SHA-256 ${configuration.sha256.slice(0, 12)}…`;

  async function runAudit(configurationId: number, vendorOverride?: string) {
    try {
      const audit = await api.post<AuditSummary>("/audits", {
        configuration_id: configurationId,
        framework: "CIS",
        ...(vendorOverride ? { vendor_override: vendorOverride } : {}),
      });
      navigate(`/audits/${audit.id}`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        setNeedsConfirmation({
          configurationId,
          detail: error.detail as DetectionConfirmationDetail,
        });
        return;
      }
      throw error;
    }
  }

  const upload = useMutation({
    mutationFn: async (file: File) => {
      const form = new FormData();
      form.append("file", file);
      const configuration = await api.postForm<ConfigurationOut>("/configurations/upload", form);
      setMessage(describe(configuration));
      setNeedsConfirmation(null);
      await runAudit(configuration.id);
    },
    onError: (error: Error) => setMessage(error.message),
  });

  const confirmVendor = useMutation({
    mutationFn: () => {
      if (!needsConfirmation) return Promise.resolve();
      return runAudit(needsConfirmation.configurationId, needsConfirmation.detail.candidate_vendor);
    },
    onError: (error: Error) => setMessage(error.message),
  });

  if (!hasPermission(user, Permission.CONFIG_UPLOAD)) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <PageHeader
          title="Configurations"
          subtitle="Upload a device configuration to normalize, evaluate, and audit it."
        />
        <EmptyState
          icon={Lock}
          title="You don't have permission to upload configurations"
          description="Ask a Network Engineer, Security Admin, or Platform Admin to upload on your behalf."
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <PageHeader
        title="Configurations"
        subtitle="Upload a device configuration to normalize, evaluate, and audit it."
      />

      <label
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files[0];
          if (file) upload.mutate(file);
        }}
        className={`flex h-56 cursor-pointer flex-col items-center justify-center rounded-card border-2 border-dashed transition-colors duration-150 ${
          dragging ? "border-sky-500 bg-sky-950/30" : "border-border-strong bg-surface"
        }`}
      >
        <UploadCloud className="mb-2 size-6 text-text-tertiary" aria-hidden="true" />
        <p className="text-lg text-text-primary">Drop configuration files</p>
        <p className="mt-1 text-sm text-text-secondary">
          or browse — .cfg .conf .txt .log .json .xml .yaml, up to 5 MB
        </p>
        <input
          type="file"
          className="hidden"
          accept=".cfg,.conf,.txt,.log,.json,.xml,.yaml,.yml"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) upload.mutate(file);
          }}
        />
      </label>

      {upload.isPending && <p className="text-sm text-sky-400">Running audit…</p>}

      {needsConfirmation && (
        <Card className="space-y-2 p-4">
          <p className="text-sm font-medium text-text-primary">Confirm device vendor</p>
          <p className="text-sm text-text-secondary">
            Detection confidence is only {Math.round(needsConfirmation.detail.confidence * 100)}% —
            best guess is <strong>{needsConfirmation.detail.candidate_vendor}</strong>.
          </p>
          <ul className="space-y-0.5 text-xs text-text-tertiary">
            {needsConfirmation.detail.reasons.map((reason) => (
              <li key={reason}>· {reason}</li>
            ))}
          </ul>
          <div className="flex gap-2 pt-1">
            <Button
              type="button"
              loading={confirmVendor.isPending}
              loadingLabel="Running audit…"
              onClick={() => confirmVendor.mutate()}
            >
              Confirm {needsConfirmation.detail.candidate_vendor} and run audit
            </Button>
            <Button type="button" variant="secondary" onClick={() => setNeedsConfirmation(null)}>
              Cancel
            </Button>
          </div>
        </Card>
      )}

      {message && <Card className="p-3 text-sm text-text-secondary">{message}</Card>}
    </div>
  );
}
