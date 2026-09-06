import { useQuery } from "@tanstack/react-query";
import { Check, X } from "lucide-react";
import { Card } from "../../components/ui/Card";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import { Permission } from "../../lib/permissions";
import type { RoleOut } from "../../types/api";

const ALL_PERMISSIONS = Object.values(Permission);

export function RolesPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.get<RoleOut[]>("/users/roles"),
  });

  return (
    <div>
      <PageHeader
        title="Roles & Permissions"
        subtitle="What each role can do — enforced server-side, this is a read-out of it."
      />
      {isLoading && <p className="text-text-secondary">Loading…</p>}
      {isError && <p className="text-text-secondary">Couldn't load roles. Try refreshing.</p>}
      {data && (
        <Card className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead className="bg-surface text-left text-text-tertiary">
              <tr className="border-b border-border">
                <th className="px-4 py-2 font-medium">Permission</th>
                {data.map((role) => (
                  <th key={role.name} className="px-4 py-2 text-center font-medium">
                    {role.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ALL_PERMISSIONS.map((permission) => (
                <tr key={permission} className="border-b border-border last:border-0">
                  <td className="px-4 py-2 font-mono text-xs text-text-secondary">{permission}</td>
                  {data.map((role) => (
                    <td key={role.name} className="px-4 py-2 text-center">
                      {role.permissions.includes(permission) ? (
                        <Check className="mx-auto size-4 text-pass" />
                      ) : (
                        <X className="mx-auto size-4 text-text-tertiary" />
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
