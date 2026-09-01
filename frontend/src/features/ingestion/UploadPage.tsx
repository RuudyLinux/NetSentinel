import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../lib/api";
import type {
  AuditSummary,
  ConfigurationOut,
  DiscoverResponse,
  LocalNetworkResponse,
} from "../../types/api";

type Tab = "upload" | "connect";

const inputClass =
  "mt-1 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-100";

function tabClass(active: boolean): string {
  return `px-3 py-2 text-sm font-medium ${
    active ? "border-b-2 border-sky-500 text-sky-400" : "text-slate-400"
  }`;
}

export function UploadPage() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("upload");
  const [dragging, setDragging] = useState(false);
  const [message, setMessage] = useState("");
  const [connectForm, setConnectForm] = useState({
    host: "",
    port: "22",
    username: "",
    password: "",
    enablePassword: "",
  });
  const [cidr, setCidr] = useState("");
  const [foundHosts, setFoundHosts] = useState<string[] | null>(null);

  const startAudit = (configuration: ConfigurationOut) =>
    api.post<AuditSummary>("/audits", {
      configuration_id: configuration.id,
      framework: "CIS",
    });

  const describe = (configuration: ConfigurationOut) =>
    `Detected ${configuration.device.vendor} ${configuration.device.os} · ` +
    `${configuration.secret_hits} secret(s) redacted · SHA-256 ${configuration.sha256.slice(0, 12)}…`;

  const upload = useMutation({
    mutationFn: async (file: File) => {
      const form = new FormData();
      form.append("file", file);
      const configuration = await api.postForm<ConfigurationOut>("/configurations/upload", form);
      setMessage(describe(configuration));
      return startAudit(configuration);
    },
    onSuccess: (audit) => navigate(`/audits/${audit.id}`),
    onError: (error: Error) => setMessage(error.message),
  });

  const connect = useMutation({
    mutationFn: async () => {
      const configuration = await api.post<ConfigurationOut>("/configurations/connect", {
        host: connectForm.host,
        port: Number(connectForm.port) || 22,
        username: connectForm.username,
        password: connectForm.password,
        enable_password: connectForm.enablePassword || null,
      });
      setMessage(describe(configuration));
      setConnectForm((f) => ({ ...f, password: "", enablePassword: "" }));
      return startAudit(configuration);
    },
    onSuccess: (audit) => navigate(`/audits/${audit.id}`),
    onError: (error: Error) => setMessage(error.message),
  });

  const discover = useMutation({
    mutationFn: () =>
      api.post<DiscoverResponse>("/devices/discover", {
        cidr,
        port: Number(connectForm.port) || 22,
      }),
    onSuccess: (result) => setFoundHosts(result.hosts),
    onError: (error: Error) => setMessage(error.message),
  });

  const detectNetwork = useMutation({
    mutationFn: () => api.get<LocalNetworkResponse>("/devices/local-network"),
    onSuccess: (result) => setCidr(result.cidr),
    onError: (error: Error) => setMessage(error.message),
  });

  const running = upload.isPending || connect.isPending;

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-xl font-semibold">Add a configuration</h1>

      <div className="flex gap-2 border-b border-slate-800">
        <button type="button" onClick={() => setTab("upload")} className={tabClass(tab === "upload")}>
          Upload file
        </button>
        <button type="button" onClick={() => setTab("connect")} className={tabClass(tab === "connect")}>
          Connect to device
        </button>
      </div>

      {tab === "upload" && (
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
              if (file) upload.mutate(file);
            }}
          />
        </label>
      )}

      {tab === "connect" && (
        <div className="space-y-3 rounded-xl border border-slate-700 bg-slate-900 p-4">
          <p className="text-sm font-medium text-slate-200">Scan a range for devices</p>
          <div className="flex gap-2">
            <input
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="10.0.0.0/24"
              className={inputClass}
            />
            <button
              type="button"
              disabled={detectNetwork.isPending}
              onClick={() => detectNetwork.mutate()}
              title="Fill in this server's own subnet"
              className="shrink-0 rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50"
            >
              {detectNetwork.isPending ? "Detecting…" : "Detect my network"}
            </button>
            <button
              type="button"
              disabled={!cidr || discover.isPending}
              onClick={() => discover.mutate()}
              className="shrink-0 rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50"
            >
              {discover.isPending ? "Scanning…" : "Scan"}
            </button>
          </div>
          <p className="text-xs text-slate-500">
            Probes each address for an open port {connectForm.port || 22} — up to a /24 per scan.
            No credentials are tried; pick a result below to fill it into the form.
          </p>
          {foundHosts && (
            <div className="flex flex-wrap gap-2">
              {foundHosts.length === 0 && (
                <p className="text-sm text-slate-400">No hosts responded in that range.</p>
              )}
              {foundHosts.map((host) => (
                <button
                  key={host}
                  type="button"
                  onClick={() => setConnectForm((f) => ({ ...f, host }))}
                  className="rounded-full border border-sky-700 bg-sky-950/40 px-3 py-1 text-sm text-sky-300 hover:bg-sky-900/50"
                >
                  {host}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === "connect" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            connect.mutate();
          }}
          className="space-y-3 rounded-xl border border-slate-700 bg-slate-900 p-4"
        >
          <div className="grid grid-cols-3 gap-3">
            <label className="col-span-2 text-sm text-slate-300">
              Target host or IP
              <input
                required
                value={connectForm.host}
                onChange={(e) => setConnectForm((f) => ({ ...f, host: e.target.value }))}
                placeholder="10.0.0.1"
                className={inputClass}
              />
            </label>
            <label className="text-sm text-slate-300">
              Port
              <input
                value={connectForm.port}
                onChange={(e) => setConnectForm((f) => ({ ...f, port: e.target.value }))}
                className={inputClass}
              />
            </label>
          </div>
          <label className="block text-sm text-slate-300">
            Username
            <input
              required
              value={connectForm.username}
              onChange={(e) => setConnectForm((f) => ({ ...f, username: e.target.value }))}
              className={inputClass}
            />
          </label>
          <label className="block text-sm text-slate-300">
            Password
            <input
              required
              type="password"
              value={connectForm.password}
              onChange={(e) => setConnectForm((f) => ({ ...f, password: e.target.value }))}
              className={inputClass}
            />
          </label>
          <label className="block text-sm text-slate-300">
            Enable password <span className="text-slate-500">(optional)</span>
            <input
              type="password"
              value={connectForm.enablePassword}
              onChange={(e) => setConnectForm((f) => ({ ...f, enablePassword: e.target.value }))}
              className={inputClass}
            />
          </label>
          <button
            type="submit"
            disabled={connect.isPending}
            className="rounded bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {connect.isPending ? "Connecting…" : "Connect and audit"}
          </button>
        </form>
      )}

      {running && <p className="text-sm text-sky-400">Running audit…</p>}
      {message && (
        <p className="rounded border border-slate-800 bg-slate-900 p-3 text-sm text-slate-300">
          {message}
        </p>
      )}
    </div>
  );
}
