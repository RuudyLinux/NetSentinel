import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { api, tokens } from "./api";

export interface CurrentUser {
  id: number;
  email: string;
  role: string;
  permissions: string[];
}

interface AuthValue {
  user: CurrentUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["me"],
    queryFn: () => api.get<CurrentUser>("/users/me"),
    enabled: Boolean(tokens.access),
    retry: false,
  });

  const value: AuthValue = {
    user: data ?? null,
    loading: isLoading,
    async login(email, password) {
      const pair = await api.post<{ access_token: string; refresh_token: string }>("/auth/login", {
        email,
        password,
      });
      tokens.set(pair.access_token, pair.refresh_token);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    async logout() {
      const refresh = tokens.refresh;
      if (refresh) await api.post("/auth/logout", { refresh_token: refresh }).catch(() => undefined);
      tokens.clear();
      queryClient.clear();
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-slate-400">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

/** Hides UI a role cannot use. The server enforces the same rule — this is presentation. */
export function RequirePermission({ perm, children }: { perm: string; children: ReactNode }) {
  const { user } = useAuth();
  if (!user?.permissions.includes(perm)) return null;
  return <>{children}</>;
}
