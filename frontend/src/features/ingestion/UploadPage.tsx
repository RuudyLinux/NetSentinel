import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../lib/api";
import type { AuditSummary, ConfigurationOut } from "../../types/api";

export function UploadPage() {
  const navigate = useNavigate();
  const [dragging, setDragging] = useState(false);
  const [message, setMessage] = useState("");

  const run = useMutation({
    mutationFn: async (file: File) => {
      const form = new FormData();
      form.append("file", file);
      const configuration = await api.postForm<ConfigurationOut>("/configurations/upload", form);
      setMessage(
        `Detected ${configuration.device.vendor} ${configuration.device.os} · ` +
          `${configuration.secret_hits} secret(s) redacted · SHA-256 ${configuration.sha256.slice(0, 12)}…`,
      );
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
      <h1 className="text-xl font-semibold">Upload configuration</h1>
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
          if (file) run.mutate(file);
        }}
        className={`flex h-56 cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed transition ${
          dragging ? "border-sky-500 bg-sky-950/30" : "border-slate-700 bg-slate-900"
        }`}
      >
        <p className="text-lg">Drop configuration files</p>
        <p className="mt-1 text-sm text-slate-400">
          or browse — .cfg .conf .txt .log .json .xml .yaml, up to 5 MB
        </p>
        <input
          type="file"
          className="hidden"
          accept=".cfg,.conf,.txt,.log,.json,.xml,.yaml,.yml"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) run.mutate(file);
          }}
        />
      </label>
      {run.isPending && <p className="text-sm text-sky-400">Running audit…</p>}
      {message && (
        <p className="rounded border border-slate-800 bg-slate-900 p-3 text-sm text-slate-300">
          {message}
        </p>
      )}
    </div>
  );
}
