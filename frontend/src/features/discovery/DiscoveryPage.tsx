import { useMutation } from "@tanstack/react-query";
import { Radar, Search } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Input, PasswordInput } from "../../components/ui/Input";
import { PageHeader } from "../../components/ui/PageHeader";
import { ApiError, api } from "../../lib/api";
import type {
  AuditSummary,
  ConfigurationOut,
  DetectionConfirmationDetail,
  DiscoveredHost,
  DiscoverResponse,
  LocalNetworkResponse,
} from "../../types/api";

export function DiscoveryPage() {
  const navigate = useNavigate();
  const [message, setMessage] = useState("");
  const [network, setNetwork] = useState<LocalNetworkResponse | null>(null);
  const [cidr, setCidr] = useState("");
  const [foundHosts, setFoundHosts] = useState<DiscoveredHost[] | null>(null);
  const [connectForm, setConnectForm] = useState({
    host: "",
    port: "22",
    username: "",
    password: "",
    enablePassword: "",
  });
  // Set when POST /audits 409s because detection confidence is too low to proceed
  // without an operator decision — offers the same override the API accepts, instead
  // of leaving the connect flow at a dead end (see audits.py's DetectionConfirmationRequired).
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

  const detectNetwork = useMutation({
    mutationFn: () => api.get<LocalNetworkResponse>("/devices/local-network"),
    onSuccess: (result) => {
      setNetwork(result);
      setCidr(result.cidr);
    },
    onError: (error: Error) => setMessage(error.message),
  });

  const discover = useMutation({
    mutationFn: () => api.post<DiscoverResponse>("/devices/discover", { cidr }),
    onSuccess: (result) => setFoundHosts(result.hosts),
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

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <PageHeader
        title="Discovery"
        subtitle="Auto-detect your authorized network and discover network devices."
      />

      <Card className="space-y-3 p-4">
        <div className="flex items-center justify-between">
          <p className="text-sm font-medium text-text-primary">Detected network</p>
          <Button
            type="button"
            variant="secondary"
            loading={detectNetwork.isPending}
            loadingLabel="Detecting…"
            onClick={() => detectNetwork.mutate()}
          >
            Auto Detect
          </Button>
        </div>
        {network && (
          <div className="grid grid-cols-3 gap-3 rounded-md border border-border bg-canvas p-3 text-sm text-text-secondary">
            <div>
              <p className="text-xs text-text-tertiary">Interface</p>
              {network.interface}
            </div>
            <div>
              <p className="text-xs text-text-tertiary">Local IP</p>
              {network.local_ip}
            </div>
            <div>
              <p className="text-xs text-text-tertiary">Network</p>
              {network.cidr}
            </div>
          </div>
        )}

        <div className="flex gap-2 pt-1">
          <Input
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="10.0.0.0/24"
            className="flex-1"
          />
          <Button
            type="button"
            disabled={!cidr}
            loading={discover.isPending}
            loadingLabel="Scanning…"
            onClick={() => discover.mutate()}
          >
            Start Discovery
          </Button>
        </div>
        <p className="text-xs text-text-tertiary">
          Checks each reachable address for a real SSH service on port 22 or 2222 (verified by
          its banner, not just an open port) — up to a /24 per scan. No credentials are tried;
          pick a result below to fill it into the form, or enter one manually.
        </p>

        {foundHosts && (
          <div className="space-y-2 pt-1">
            <p className="text-sm font-medium text-text-primary">
              Discovered hosts ({foundHosts.length})
            </p>
            {foundHosts.length === 0 && (
              <p className="flex items-center gap-2 text-sm text-text-tertiary">
                <Search className="size-4" /> No hosts responded in that range.
              </p>
            )}
            {foundHosts.map((host) => {
              const confirmed = host.status === "ssh_available";
              return (
                <button
                  key={host.ip}
                  type="button"
                  disabled={!confirmed}
                  onClick={() =>
                    setConnectForm((f) => ({ ...f, host: host.ip, port: String(host.port) }))
                  }
                  className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm transition-colors duration-150 ${
                    confirmed
                      ? "border-sky-800 bg-sky-950/30 hover:bg-sky-900/40"
                      : "cursor-default border-border bg-canvas"
                  }`}
                >
                  <div>
                    <p className="font-medium text-text-primary">{host.ip}</p>
                    <p className="text-xs text-text-tertiary">
                      {host.vendor ?? "Unknown vendor"}
                      {confirmed ? ` · ${host.port}/tcp` : ""}
                    </p>
                  </div>
                  <Badge tone={confirmed ? "pass" : "neutral"}>
                    {confirmed ? "SSH CONFIRMED" : "No SSH detected"}
                  </Badge>
                </button>
              );
            })}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <p className="mb-3 text-sm font-medium text-text-primary">Connect and audit</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            connect.mutate();
          }}
          className="space-y-3"
        >
          <div className="grid grid-cols-3 gap-3">
            <Input
              label="Target host or IP"
              required
              value={connectForm.host}
              onChange={(e) => setConnectForm((f) => ({ ...f, host: e.target.value }))}
              placeholder="10.0.0.1"
              className="col-span-2"
            />
            <Input
              label="Port"
              value={connectForm.port}
              onChange={(e) => setConnectForm((f) => ({ ...f, port: e.target.value }))}
            />
          </div>
          <Input
            label="Username"
            required
            value={connectForm.username}
            onChange={(e) => setConnectForm((f) => ({ ...f, username: e.target.value }))}
          />
          <PasswordInput
            label="Password"
            required
            value={connectForm.password}
            onChange={(e) => setConnectForm((f) => ({ ...f, password: e.target.value }))}
          />
          <PasswordInput
            label="Enable password (optional)"
            value={connectForm.enablePassword}
            onChange={(e) => setConnectForm((f) => ({ ...f, enablePassword: e.target.value }))}
          />
          <Button type="submit" loading={connect.isPending} loadingLabel="Connecting…">
            <Radar className="size-4" /> Connect and audit
          </Button>
        </form>
      </Card>

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
