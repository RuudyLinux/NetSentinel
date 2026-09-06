import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "../../components/ui/Button";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { AuditLogEntry, AuditLogPage } from "../../types/api";

export function AuditLogsPage() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [cursor, setCursor] = useState<number | undefined>(undefined);
  const [nextCursor, setNextCursor] = useState<number | null>(null);
  const [loadedOnce, setLoadedOnce] = useState(false);

  const { isFetching, isError } = useQuery({
    queryKey: ["audit-logs", cursor],
    queryFn: async () => {
      const params = new URLSearchParams({ limit: "50" });
      if (cursor) params.set("before_id", String(cursor));
      const page = await api.get<AuditLogPage>(`/audit-logs?${params}`);
      setEntries((prev) => [...prev, ...page.entries]);
      setNextCursor(page.next_before_id);
      setLoadedOnce(true);
      return page;
    },
  });

  return (
    <div>
      <PageHeader title="Audit Logs" subtitle="Security-relevant events for your organization." />

      {!loadedOnce && isFetching && <p className="text-text-secondary">Loading…</p>}
      {isError && <p className="text-text-secondary">Couldn't load audit logs. Try refreshing.</p>}

      {entries.length > 0 && (
        <div className="overflow-x-auto rounded-card border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-left text-text-tertiary">
              <tr className="border-b border-border">
                <th className="px-4 py-2 font-medium">Timestamp</th>
                <th className="px-4 py-2 font-medium">User</th>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Resource</th>
                <th className="px-4 py-2 font-medium">Result</th>
                <th className="px-4 py-2 font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id} className="border-b border-border last:border-0 hover:bg-surface">
                  <td className="px-4 py-2.5 text-text-secondary">
                    {new Date(entry.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5 text-text-primary">{entry.user_email}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">{entry.action}</td>
                  <td className="px-4 py-2.5 text-text-secondary">{entry.resource || "—"}</td>
                  <td className="px-4 py-2.5">
                    <span className={entry.result === "SUCCESS" ? "text-pass" : "text-critical"}>
                      {entry.result}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-text-tertiary">{entry.ip || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {loadedOnce && entries.length === 0 && (
        <p className="text-text-secondary">No events recorded yet.</p>
      )}

      {nextCursor && (
        <div className="mt-4">
          <Button variant="secondary" loading={isFetching} onClick={() => setCursor(nextCursor)}>
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}
