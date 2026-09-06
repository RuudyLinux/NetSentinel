import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { api, tokens } from "./api";
import { AuthContext, hasPermission, useAuth, type CurrentUser } from "./authHooks";

// Set on a successful login, cleared only by an explicit logout or by RequireAuth
// consuming it once. Unlike `tokens`, this survives the silent tokens.clear() that
// api.ts's refresh-on-401 does on failure — so RequireAuth can tell "never signed
// in" apart from "was signed in, session died" and route to the right screen
// (section 16: never silently dump users at the login screen).
const HAD_SESSION_KEY = "netsentinel.hadSession";

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  // `tokens.access` is a plain localStorage read, not React state — using it directly
  // as `enabled` freezes the query's enabled flag at whatever it was on the last render
  // this component happened to do. login()/logout() write localStorage from inside an
  // async function, which triggers no re-render, so the query never re-evaluates
  // `enabled` and invalidateQueries()/clear() have no active observer to act on — the
  // "me" fetch silently never (re)fires and `user` never updates. Track it in state
  // instead so login/logout can flip it and force the reactivity React Query needs.
  const [hasToken, setHasToken] = useState(() => Boolean(tokens.access));
  const { data, isLoading } = useQuery({
    queryKey: ["me"],
    queryFn: () => api.get<CurrentUser>("/users/me"),
    enabled: hasToken,
    retry: false,
  });

  const value = {
    user: data ?? null,
    loading: isLoading,
    async login(email: string, password: string) {
      const pair = await api.post<{ access_token: string; refresh_token: string }>("/auth/login", {
        email,
        password,
      });
      tokens.set(pair.access_token, pair.refresh_token);
      sessionStorage.setItem(HAD_SESSION_KEY, "1");
      setHasToken(true);
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    },
    async logout() {
      const refresh = tokens.refresh;
      if (refresh) await api.post("/auth/logout", { refresh_token: refresh }).catch(() => undefined);
      tokens.clear();
      sessionStorage.removeItem(HAD_SESSION_KEY);
      queryClient.clear();
      setHasToken(false);
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
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
