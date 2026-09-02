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

// Set on a successful login, cleared only by an explicit logout or by RequireAuth
// consuming it once. Unlike `tokens`, this survives the silent tokens.clear() that
// api.ts's refresh-on-401 does on failure — so RequireAuth can tell "never signed
// in" apart from "was signed in, session died" and route to the right screen
// (section 16: never silently dump users at the login screen).
const HAD_SESSION_KEY = "netsentinel.hadSession";

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
      sessionStorage.setItem(HAD_SESSION_KEY, "1");
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    async logout() {
      const refresh = tokens.refresh;
      if (refresh) await api.post("/auth/logout", { refresh_token: refresh }).catch(() => undefined);
      tokens.clear();
      sessionStorage.removeItem(HAD_SESSION_KEY);
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

/** True when `user` holds at least one of `perms` (empty perms => always visible). */
export function hasPermission(user: CurrentUser | null, ...perms: string[]): boolean {
  if (perms.length === 0) return true;
  return perms.some((perm) => user?.permissions.includes(perm));
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-text-secondary">Loading…</div>;
  if (!user) {
    const hadSession = sessionStorage.getItem(HAD_SESSION_KEY) === "1";
    sessionStorage.removeItem(HAD_SESSION_KEY);
    return <Navigate to={hadSession ? "/auth/session-expired" : "/auth/login"} replace />;
  }
  return <>{children}</>;
}

/** Hides UI a role cannot use. The server enforces the same rule — this is presentation. */
export function RequirePermission({ perm, children }: { perm: string; children: ReactNode }) {
  const { user } = useAuth();
  if (!hasPermission(user, perm)) return null;
  return <>{children}</>;
}
