import { useMutation } from "@tanstack/react-query";
import { UploadCloud } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "../../components/ui/Card";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { AuditSummary, ConfigurationOut } from "../../types/api";

export function ConfigurationsPage() {
  const navigate = useNavigate();
  const [dragging, setDragging] = useState(false);
  const [message, setMessage] = useState("");

  const describe = (configuration: ConfigurationOut) =>
    `Detected ${configuration.device.vendor} ${configuration.device.os} · ` +
    `${configuration.secret_hits} secret(s) redacted · SHA-256 ${configuration.sha256.slice(0, 12)}…`;

  const upload = useMutation({
    mutationFn: async (file: File) => {
      const form = new FormData();
      form.append("file", file);
      const configuration = await api.postForm<ConfigurationOut>("/configurations/upload", form);
      setMessage(describe(configuration));
      return api.post<AuditSummary>("/audits", {
        configuration_id: configuration.id,
        framework: "CIS",
      });
    },
    onSuccess: (audit) => navigate(`/audits/${audit.id}`),
    onError: (error: Error) => setMessage(error.message),
  });

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
      {message && <Card className="p-3 text-sm text-text-secondary">{message}</Card>}
    </div>
  );
}
