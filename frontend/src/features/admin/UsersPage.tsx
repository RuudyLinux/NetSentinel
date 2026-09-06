import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui/PageHeader";
import { api } from "../../lib/api";
import type { AdminUserOut } from "../../types/api";

export function UsersPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => api.get<AdminUserOut[]>("/users"),
  });

  return (
    <div>
      <PageHeader title="Users" subtitle="Accounts in your organization." />
      {isLoading && <p className="text-text-secondary">Loading…</p>}
      {isError && <p className="text-text-secondary">Couldn't load users. Try refreshing.</p>}
      {data && (
        <div className="overflow-x-auto rounded-card border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-left text-text-tertiary">
              <tr className="border-b border-border">
                <th className="px-4 py-2 font-medium">Email</th>
                <th className="px-4 py-2 font-medium">Role</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {data.map((user) => (
                <tr key={user.id} className="border-b border-border last:border-0 hover:bg-surface">
                  <td className="px-4 py-2.5 font-medium text-text-primary">{user.email}</td>
                  <td className="px-4 py-2.5 text-text-secondary">{user.role}</td>
                  <td className="px-4 py-2.5">
                    <span className={user.is_active ? "text-pass" : "text-text-tertiary"}>
                      {user.is_active ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-text-secondary">
                    {new Date(user.created_at).toLocaleDateString()}
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
