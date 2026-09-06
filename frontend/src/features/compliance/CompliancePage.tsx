import { useQuery } from "@tanstack/react-query";
import { ClipboardList } from "lucide-react";
import { Link } from "react-router-dom";
import { Card } from "../../components/ui/Card";
import { EmptyState } from "../../components/ui/EmptyState";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { FrameworkOut } from "../../types/api";

export function CompliancePage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["frameworks"],
    queryFn: () => api.get<FrameworkOut[]>("/frameworks"),
  });

  return (
    <div>
      <PageHeader
        title="Compliance"
        subtitle="Frameworks and rule packs loaded on this deployment."
      />

      {isLoading && <p className="text-text-secondary">Loading…</p>}
      {isError && <p className="text-text-secondary">Couldn't load frameworks. Try refreshing.</p>}

      {!isLoading && !isError && data && data.length === 0 && (
        <EmptyState
          icon={ClipboardList}
          title="No frameworks loaded"
          description="No rule packs are configured on this deployment yet."
        />
      )}

      {data && data.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {data.map((framework) => (
            <Link key={framework.framework} to={`/compliance/${framework.framework}`}>
              <Card className="p-5 transition-colors duration-150 hover:bg-surface-raised">
                <p className="text-lg font-semibold text-text-primary">{framework.framework}</p>
                <p className="text-sm text-text-secondary">Version {framework.framework_version}</p>
                <p className="mt-3 text-xs text-text-tertiary">{framework.rule_count} rules</p>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
