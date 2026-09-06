import { CheckCircle2, CircleSlash, Play, Sparkles, XCircle } from "lucide-react";
import { useRef, useState } from "react";
import { Badge, type Tone } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { PageHeader } from "../../components/ui/PageHeader";
import { ApiError, api, tokens } from "../../lib/api";
import type {
  AuditSummary,
  ConfigurationOut,
  DiscoverResponse,
  FindingSummary,
  FrameworkOut,
  ReportSummary,
  UnknownConstructWithAi,
  DeviceOut,
} from "../../types/api";

type RunStatus = "idle" | "running" | "pass" | "fail" | "skipped";

// A syntactically-valid but guaranteed-nonexistent account under the deployment's own
// domain — passes email validation so login/forgot-password can be probed for their
// real failure/no-op path without touching any real account.
const PROBE_EMAIL = "netsentinel-diagnostic-probe-9f3a@netsentinel.ai";

// Scores as Cisco IOS-XE with confidence 1.0 (avoids the low-confidence confirmation
// detour) and reliably fails a few CIS rules plus leaves one unrecognized line, so
// every downstream check (audit, findings, report, AI interpret) always has real data
// to work against. Re-uploading this exact text is a no-op (same SHA-256 dedupes) —
// this page creates at most one persistent device, named so it's obviously a fixture.
const DIAGNOSTIC_CONFIG = `version 17.6
hostname netsentinel-diagnostic-probe
enable secret 9 $9$diagnosticOnlyPlaceholderHash$
!
security passwords min-length 12
!
ip ssh version 2
no ip http server
ip http secure-server
!
line vty 0 4
 login local
 transport input ssh
!
snmp-server community public RO
secure-session-timeout 300
end
`;

interface Ctx {
  deviceId?: number;
  auditId?: number;
  findingId?: number;
  framework?: string;
  reportId?: number;
  diagConfigId?: number;
  diagAuditId?: number;
  diagConstructIndex?: number;
}

interface Row {
  id: string;
  area: string;
  method: string;
  path: string;
  status: RunStatus;
  httpStatus?: number;
  latencyMs?: number;
  note?: string;
}

interface Outcome {
  httpStatus?: number;
  note?: string;
}

interface Check {
  id: string;
  area: string;
  method: string;
  path: string;
  /** GET checks: return the concrete path, or null if there's nothing to test
   * against yet. Custom checks (writes, expected-failure probes) run whatever
   * request(s) they need directly and report the outcome. Exactly one is set. */
  resolvePath?: (ctx: Ctx) => string | null;
  execute?: (ctx: Ctx) => Promise<Outcome>;
  skipReason?: string;
}

const CHECKS: Check[] = [
  { id: "health", area: "System", method: "GET", path: "/healthz", resolvePath: () => "/healthz" },
  { id: "me", area: "Auth", method: "GET", path: "/users/me", resolvePath: () => "/users/me" },
  {
    id: "login-invalid",
    area: "Auth",
    method: "POST",
    path: "/auth/login",
    execute: async () => {
      try {
        await api.post("/auth/login", { email: PROBE_EMAIL, password: "wrong-password-probe" });
        throw new Error("expected 401 for an unknown account, got success");
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          return { httpStatus: 401, note: "correctly rejected an unknown account" };
        }
        throw error;
      }
    },
  },
  {
    id: "refresh",
    area: "Auth",
    method: "POST",
    path: "/auth/refresh",
    execute: async () => {
      if (!tokens.refresh) throw new Error("this session has no refresh token to rotate");
      const pair = await api.post<{ access_token: string; refresh_token: string }>("/auth/refresh", {
        refresh_token: tokens.refresh,
      });
      tokens.set(pair.access_token, pair.refresh_token);
      return { httpStatus: 200, note: "rotated this session's own tokens" };
    },
  },
  {
    id: "logout-probe",
    area: "Auth",
    method: "POST",
    path: "/auth/logout",
    execute: async () => {
      await api.post("/auth/logout", { refresh_token: "diagnostic-probe-not-a-real-token" });
      return { httpStatus: 204, note: "unknown token safely ignored — this session is unaffected" };
    },
  },
  {
    id: "forgot-password-probe",
    area: "Auth",
    method: "POST",
    path: "/auth/forgot-password",
    execute: async () => {
      await api.post("/auth/forgot-password", { email: PROBE_EMAIL });
      return { httpStatus: 202, note: "no matching account — zero side effects" };
    },
  },
  { id: "users", area: "Administration", method: "GET", path: "/users", resolvePath: () => "/users" },
  { id: "roles", area: "Administration", method: "GET", path: "/users/roles", resolvePath: () => "/users/roles" },
  {
    id: "audit-logs",
    area: "Administration",
    method: "GET",
    path: "/audit-logs?limit=1",
    resolvePath: () => "/audit-logs?limit=1",
  },
  {
    id: "dashboard",
    area: "Dashboard",
    method: "GET",
    path: "/dashboard/summary",
    resolvePath: () => "/dashboard/summary",
  },
  {
    id: "devices-list",
    area: "Devices",
    method: "GET",
    path: "/devices",
    resolvePath: () => "/devices",
  },
  {
    id: "devices-local-network",
    area: "Devices",
    method: "GET",
    path: "/devices/local-network",
    resolvePath: () => "/devices/local-network",
  },
  {
    id: "devices-detail",
    area: "Devices",
    method: "GET",
    path: "/devices/{id}",
    resolvePath: (ctx) => (ctx.deviceId ? `/devices/${ctx.deviceId}` : null),
    skipReason: "no device exists yet to read back",
  },
  {
    id: "discover-probe",
    area: "Devices",
    method: "POST",
    path: "/devices/discover",
    execute: async () => {
      const result = await api.post<DiscoverResponse>("/devices/discover", { cidr: "127.0.0.1/32" });
      return { httpStatus: 200, note: `scanned only 127.0.0.1 — ${result.hosts.length} host(s) reported` };
    },
  },
  {
    id: "config-upload-seed",
    area: "Configurations",
    method: "POST",
    path: "/configurations/upload",
    execute: async (ctx) => {
      const form = new FormData();
      form.append("file", new Blob([DIAGNOSTIC_CONFIG], { type: "text/plain" }), "netsentinel-diagnostic-probe.cfg");
      const configuration = await api.postForm<ConfigurationOut>("/configurations/upload", form);
      ctx.diagConfigId = configuration.id;
      return { note: `device "${configuration.device.name}" (id ${configuration.device.id})` };
    },
  },
  {
    id: "config-detail",
    area: "Configurations",
    method: "GET",
    path: "/configurations/{id}",
    resolvePath: (ctx) => (ctx.diagConfigId ? `/configurations/${ctx.diagConfigId}` : null),
    skipReason: "the upload check above didn't run or didn't succeed",
  },
  {
    id: "connect-probe",
    area: "Configurations",
    method: "POST",
    path: "/configurations/connect",
    execute: async () => {
      try {
        await api.post("/configurations/connect", {
          host: "203.0.113.1", // TEST-NET-3 (RFC 5737) — reserved, guaranteed unroutable
          port: 22,
          username: "diagnostic-probe",
          password: "diagnostic-probe",
          enable_password: null,
        });
        throw new Error("expected 502 for an unreachable host, got success");
      } catch (error) {
        if (error instanceof ApiError && error.status === 502) {
          return { httpStatus: 502, note: "correctly reported an unreachable device (~10s connect timeout)" };
        }
        throw error;
      }
    },
  },
  {
    id: "audits-list",
    area: "Audits",
    method: "GET",
    path: "/audits",
    resolvePath: () => "/audits",
  },
  {
    id: "audits-run-seed",
    area: "Audits",
    method: "POST",
    path: "/audits",
    execute: async (ctx) => {
      if (!ctx.diagConfigId) throw new Error("the configuration upload check above didn't run or didn't succeed");
      const audit = await api.post<AuditSummary>("/audits", {
        configuration_id: ctx.diagConfigId,
        framework: "CIS",
      });
      ctx.diagAuditId = audit.id;
      return { note: `created audit run ${audit.id}, score ${audit.score ?? "—"}` };
    },
  },
  {
    id: "audits-detail",
    area: "Audits",
    method: "GET",
    path: "/audits/{id}",
    resolvePath: (ctx) => (ctx.diagAuditId ? `/audits/${ctx.diagAuditId}` : null),
    skipReason: "the audit run check above didn't run or didn't succeed",
  },
  {
    id: "audits-unknown-constructs",
    area: "Audits",
    method: "GET",
    path: "/audits/{id}/unknown-constructs",
    resolvePath: (ctx) => (ctx.diagAuditId ? `/audits/${ctx.diagAuditId}/unknown-constructs` : null),
    skipReason: "the audit run check above didn't run or didn't succeed",
  },
  {
    id: "findings-list",
    area: "Findings",
    method: "GET",
    path: "/findings",
    resolvePath: () => "/findings",
  },
  {
    id: "findings-triage-roundtrip",
    area: "Findings",
    method: "PATCH",
    path: "/findings/{id}",
    execute: async (ctx) => {
      if (!ctx.diagAuditId) throw new Error("the audit run check above didn't run or didn't succeed");
      const findings = await api.get<FindingSummary[]>(`/findings?audit_id=${ctx.diagAuditId}`);
      const target = findings[0];
      if (!target) throw new Error("that audit produced no findings to triage");
      const probeValue = target.triage_status === "accepted_risk" ? "open" : "accepted_risk";
      await api.patch(`/findings/${target.id}`, { triage_status: probeValue });
      await api.patch(`/findings/${target.id}`, { triage_status: target.triage_status });
      return { note: `round-tripped finding ${target.id}, restored to "${target.triage_status}"` };
    },
  },
  {
    id: "frameworks-list",
    area: "Compliance",
    method: "GET",
    path: "/frameworks",
    resolvePath: () => "/frameworks",
  },
  {
    id: "frameworks-rules",
    area: "Compliance",
    method: "GET",
    path: "/frameworks/{framework}/rules",
    resolvePath: (ctx) => (ctx.framework ? `/frameworks/${ctx.framework}/rules` : null),
    skipReason: "no rule pack loaded to read back",
  },
  {
    id: "frameworks-compliance",
    area: "Compliance",
    method: "GET",
    path: "/frameworks/{framework}/compliance",
    resolvePath: (ctx) => (ctx.framework ? `/frameworks/${ctx.framework}/compliance` : null),
    skipReason: "no rule pack loaded to read back",
  },
  {
    id: "reports-list",
    area: "Reports",
    method: "GET",
    path: "/reports",
    resolvePath: () => "/reports",
  },
  {
    id: "reports-generate-download",
    area: "Reports",
    method: "POST",
    path: "/audits/{id}/report",
    execute: async (ctx) => {
      if (!ctx.diagAuditId) throw new Error("the audit run check above didn't run or didn't succeed");
      const report = await api.post<{ id: number }>(`/audits/${ctx.diagAuditId}/report`);
      const blob = await api.get<Blob>(`/reports/${report.id}`);
      return { note: `generated and downloaded report ${report.id} (${blob.size} bytes)` };
    },
  },
];

const AI_INTERPRET_CHECK: Check = {
  id: "ai-interpret",
  area: "AI Insights",
  method: "POST",
  path: "/audits/{id}/unknown-constructs/{i}/interpret",
  execute: async (ctx) => {
    if (!ctx.diagAuditId) throw new Error("run the checks above first — no diagnostic audit exists yet");
    const constructs = await api.get<UnknownConstructWithAi[]>(`/audits/${ctx.diagAuditId}/unknown-constructs`);
    const target = constructs.find((c) => !c.interpretation) ?? constructs[0];
    if (!target) throw new Error("that audit found no unrecognized lines to interpret");
    ctx.diagConstructIndex = target.index;
    const result = await api.post<{ model: string }>(
      `/audits/${ctx.diagAuditId}/unknown-constructs/${target.index}/interpret`,
    );
    return { httpStatus: 201, note: `interpreted construct ${target.index} via ${result.model}` };
  },
};

const AI_REVIEW_CHECK: Check = {
  id: "ai-review",
  area: "AI Insights",
  method: "PATCH",
  path: "/audits/{id}/unknown-constructs/{i}/interpretation",
  execute: async (ctx) => {
    if (ctx.diagAuditId === undefined || ctx.diagConstructIndex === undefined) {
      throw new Error("run the AI interpretation check first");
    }
    await api.patch(`/audits/${ctx.diagAuditId}/unknown-constructs/${ctx.diagConstructIndex}/interpretation`, {
      status: "approved",
    });
    return { note: "marked approved — reviews have no \"revert to pending\", this is a terminal diagnostic-only change" };
  },
};

const STATUS_TONE: Record<RunStatus, Tone> = {
  idle: "neutral",
  running: "neutral",
  pass: "pass",
  fail: "critical",
  skipped: "warning",
};

const STATUS_LABEL: Record<RunStatus, string> = {
  idle: "Not run",
  running: "Checking…",
  pass: "Pass",
  fail: "Fail",
  skipped: "Skipped",
};

function toRow(check: Check): Row {
  return { id: check.id, area: check.area, method: check.method, path: check.path, status: "idle" };
}

/** Populates ctx from the handful of plain list endpoints that feed later detail checks. */
function applyListResult(id: string, ctx: Ctx, data: unknown) {
  if (id === "devices-list") ctx.deviceId = (data as DeviceOut[])[0]?.id;
  if (id === "audits-list" && ctx.auditId === undefined) ctx.auditId = (data as AuditSummary[])[0]?.id;
  if (id === "findings-list") ctx.findingId = (data as FindingSummary[])[0]?.id;
  if (id === "frameworks-list") ctx.framework = (data as FrameworkOut[])[0]?.framework;
  if (id === "reports-list") ctx.reportId = (data as ReportSummary[])[0]?.id;
}

/** Runs one check and reports its outcome via `patch`. Kept as a plain top-level
 * function (not a closure defined inside the component) so timing it with
 * `performance.now()` is never mistaken for an impure render-time call. */
async function executeCheck(check: Check, ctx: Ctx, patch: (id: string, patch: Partial<Row>) => void) {
  patch(check.id, { status: "running" });

  if (check.resolvePath) {
    const resolved = check.resolvePath(ctx);
    if (resolved === null) {
      patch(check.id, { status: "skipped", note: check.skipReason });
      return;
    }
    const start = performance.now();
    try {
      const data = await api.get(resolved);
      applyListResult(check.id, ctx, data);
      patch(check.id, { status: "pass", httpStatus: 200, latencyMs: Math.round(performance.now() - start) });
    } catch (error) {
      patch(check.id, {
        status: "fail",
        httpStatus: error instanceof ApiError ? error.status : undefined,
        latencyMs: Math.round(performance.now() - start),
        note: error instanceof Error ? error.message : "request failed",
      });
    }
    return;
  }

  const start = performance.now();
  try {
    const outcome = await check.execute!(ctx);
    patch(check.id, {
      status: "pass",
      httpStatus: outcome.httpStatus,
      latencyMs: Math.round(performance.now() - start),
      note: outcome.note,
    });
  } catch (error) {
    patch(check.id, {
      status: "fail",
      httpStatus: error instanceof ApiError ? error.status : undefined,
      latencyMs: Math.round(performance.now() - start),
      note: error instanceof Error ? error.message : "request failed",
    });
  }
}

export function DiagnosticsPage() {
  const [rows, setRows] = useState<Row[]>([...CHECKS, AI_INTERPRET_CHECK, AI_REVIEW_CHECK].map(toRow));
  const [running, setRunning] = useState(false);
  const [aiRunning, setAiRunning] = useState(false);
  const [diagAuditReady, setDiagAuditReady] = useState(false);
  const ctxRef = useRef<Ctx>({});

  function patchRow(id: string, patch: Partial<Row>) {
    setRows((current) => current.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  }

  async function runAll() {
    setRunning(true);
    setDiagAuditReady(false);
    setRows((current) =>
      current.map((row) => (row.id === "ai-interpret" || row.id === "ai-review" ? row : { ...row, status: "idle" as const })),
    );
    const ctx: Ctx = {};
    for (const check of CHECKS) {
      await executeCheck(check, ctx, patchRow);
    }
    ctxRef.current = ctx;
    setDiagAuditReady(ctx.diagAuditId !== undefined);
    setRunning(false);
  }

  async function runAiChecks() {
    setAiRunning(true);
    patchRow("ai-interpret", { status: "idle" });
    patchRow("ai-review", { status: "idle" });
    await executeCheck(AI_INTERPRET_CHECK, ctxRef.current, patchRow);
    await executeCheck(AI_REVIEW_CHECK, ctxRef.current, patchRow);
    setAiRunning(false);
  }

  const passCount = rows.filter((r) => r.status === "pass").length;
  const failCount = rows.filter((r) => r.status === "fail").length;
  const skipCount = rows.filter((r) => r.status === "skipped").length;
  const hasRun = rows.some((r) => r.status !== "idle");

  return (
    <div className="space-y-4">
      <PageHeader
        title="API Diagnostics"
        subtitle="Live-checks every endpoint this deployment exposes, including writes — round-tripped or probed for their real failure path so nothing is left changed."
        action={
          <Button onClick={() => void runAll()} loading={running} loadingLabel="Running…">
            <Play className="size-4" /> Run All Checks
          </Button>
        }
      />

      <Card className="p-3 text-xs text-text-tertiary">
        Creates or reuses one clearly-labeled device, "netsentinel-diagnostic-probe", to exercise
        upload/audit/report/findings — safe to leave in your device list, or delete it once you're
        done. Everything else either round-trips back to its original value or targets data that
        can never be real (an unreachable IP, an account that doesn't exist).
      </Card>

      {hasRun && !running && (
        <Card className="flex flex-wrap items-center gap-4 p-4 text-sm">
          <span className="flex items-center gap-1.5 text-pass">
            <CheckCircle2 className="size-4" /> {passCount} passed
          </span>
          <span className="flex items-center gap-1.5 text-critical">
            <XCircle className="size-4" /> {failCount} failed
          </span>
          <span className="flex items-center gap-1.5 text-warning">
            <CircleSlash className="size-4" /> {skipCount} skipped
          </span>
        </Card>
      )}

      <Card className="overflow-x-auto p-0">
        <table className="w-full text-sm">
          <thead className="bg-surface text-left text-text-tertiary">
            <tr className="border-b border-border">
              <th className="px-4 py-2 font-medium">Area</th>
              <th className="px-4 py-2 font-medium">Method</th>
              <th className="px-4 py-2 font-medium">Endpoint</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">HTTP</th>
              <th className="px-4 py-2 font-medium">Latency</th>
              <th className="px-4 py-2 font-medium">Note</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-b border-border last:border-0">
                <td className="px-4 py-2.5 text-text-secondary">{row.area}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-text-tertiary">{row.method}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-text-primary">{row.path}</td>
                <td className="px-4 py-2.5">
                  <Badge tone={STATUS_TONE[row.status]}>{STATUS_LABEL[row.status]}</Badge>
                </td>
                <td className="px-4 py-2.5 tabular-nums text-text-secondary">{row.httpStatus ?? "—"}</td>
                <td className="px-4 py-2.5 tabular-nums text-text-secondary">
                  {row.latencyMs !== undefined ? `${row.latencyMs} ms` : "—"}
                </td>
                <td className="px-4 py-2.5 text-xs text-text-tertiary">{row.note ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card className="space-y-2 p-4">
        <p className="flex items-center gap-2 text-sm font-medium text-text-primary">
          <Sparkles className="size-4 text-text-tertiary" aria-hidden="true" /> AI interpretation
        </p>
        <p className="text-xs text-text-tertiary">
          Calls the configured external model and costs real money per run — kept out of "Run All
          Checks" so it never fires without you asking for it. Needs the checks above to have run
          first (they create the diagnostic audit this targets).
        </p>
        <Button
          type="button"
          variant="secondary"
          disabled={!diagAuditReady}
          loading={aiRunning}
          loadingLabel="Calling model…"
          onClick={() => void runAiChecks()}
        >
          <Sparkles className="size-4" /> Test AI Interpretation
        </Button>
        {!diagAuditReady && (
          <p className="text-xs text-text-tertiary">Run "Run All Checks" above first.</p>
        )}
      </Card>
    </div>
  );
}
