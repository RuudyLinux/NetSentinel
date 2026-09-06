import { createContext, useContext } from "react";

export interface CurrentUser {
  id: number;
  email: string;
  role: string;
  permissions: string[];
}

export interface AuthValue {
  user: CurrentUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthValue | null>(null);

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
