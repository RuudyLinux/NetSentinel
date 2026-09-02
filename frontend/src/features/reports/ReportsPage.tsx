import { useQuery } from "@tanstack/react-query";
import { Download, FileBarChart } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { EmptyState } from "../../components/ui/EmptyState";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { ReportSummary } from "../../types/api";

export function ReportsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => api.get<ReportSummary[]>("/reports"),
  });

  async function download(reportId: number) {
    const blob = await api.get<Blob>(`/reports/${reportId}`);
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
  }

  return (
    <div>
      <PageHeader title="Reports" subtitle="PDF audit reports generated for your fleet." />

      {isLoading && <p className="text-text-secondary">Loading…</p>}

      {!isLoading && data && data.length === 0 && (
        <EmptyState
          icon={FileBarChart}
          title="No reports yet"
          description="Generate a PDF report from any audit's detail page to see it here."
          action={
            <Link to="/audits">
              <Button>Go to Audits</Button>
            </Link>
          }
        />
      )}

      {data && data.length > 0 && (
        <div className="overflow-x-auto rounded-card border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-left text-text-tertiary">
              <tr className="border-b border-border">
                <th className="px-4 py-2 font-medium">Device</th>
                <th className="px-4 py-2 font-medium">Framework</th>
                <th className="px-4 py-2 font-medium">Generated</th>
                <th className="px-4 py-2 font-medium">Audit</th>
                <th className="px-4 py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {data.map((report) => (
                <tr key={report.id} className="border-b border-border last:border-0 hover:bg-surface">
                  <td className="px-4 py-2.5 font-medium text-text-primary">{report.device_name}</td>
                  <td className="px-4 py-2.5 text-text-secondary">
                    {report.framework} {report.framework_version}
                  </td>
                  <td className="px-4 py-2.5 text-text-secondary">
                    {new Date(report.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5">
                    <Link to={`/audits/${report.audit_run_id}`} className="text-sky-400 hover:underline">
                      View audit
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <Button variant="secondary" onClick={() => download(report.id)}>
                      <Download className="size-4" /> Download
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
