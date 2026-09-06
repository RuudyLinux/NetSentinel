import { useQuery } from "@tanstack/react-query";
import { Bell, LogOut, Menu, Radar, Search, X } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api } from "../../lib/api";
import { hasPermission, useAuth } from "../../lib/authHooks";
import { NAV_GROUPS } from "./nav";

const PAGE_TITLES: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Dashboard", subtitle: "Security posture overview" },
  "/devices": { title: "Devices", subtitle: "Manage and monitor discovered network infrastructure" },
  "/discovery": { title: "Discovery", subtitle: "Auto-detect your authorized network" },
  "/configurations": { title: "Configurations", subtitle: "Upload and manage device configuration" },
  "/audits": { title: "Audits", subtitle: "Compliance audits across your fleet" },
  "/findings": { title: "Findings", subtitle: "Every open and resolved finding across your fleet" },
  "/compliance": { title: "Compliance", subtitle: "Frameworks and rule packs loaded on this deployment" },
  "/ai-insights": { title: "AI Insights", subtitle: "Advisory only — deterministic rules remain authoritative" },
  "/reports": { title: "Reports", subtitle: "PDF audit reports generated for your fleet" },
  "/admin/users": { title: "Users", subtitle: "Accounts in your organization" },
  "/admin/roles": { title: "Roles & Permissions", subtitle: "What each role can do" },
  "/admin/audit-logs": { title: "Audit Logs", subtitle: "Security-relevant events for your organization" },
  "/admin/diagnostics": { title: "API Diagnostics", subtitle: "Check every endpoint this deployment exposes" },
};

function currentPageMeta(pathname: string) {
  if (PAGE_TITLES[pathname]) return PAGE_TITLES[pathname];
  if (pathname.startsWith("/audits/")) return { title: "Audit Detail", subtitle: "Findings and evidence" };
  if (pathname.startsWith("/devices/")) return { title: "Device Detail", subtitle: "" };
  if (pathname.startsWith("/findings/")) return { title: "Finding", subtitle: "" };
  if (pathname.startsWith("/compliance/")) return { title: "Framework", subtitle: "" };
  return { title: "NetSentinel AI", subtitle: "" };
}

function initials(email: string): string {
  return email.slice(0, 2).toUpperCase();
}

function Sidebar({ mobileOpen, onClose }: { mobileOpen: boolean; onClose: () => void }) {
  const { user, logout } = useAuth();

  return (
    <>
      {mobileOpen && (
        <div className="fixed inset-0 z-30 bg-black/50 md:hidden" onClick={onClose} aria-hidden="true" />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-62 shrink-0 flex-col border-r border-border bg-surface transition-transform duration-200 md:static md:translate-x-0 ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center gap-2 border-b border-border px-5">
          <Radar className="size-5 text-sky-500" aria-hidden="true" />
          <span className="text-sm font-semibold tracking-wide text-text-primary">NETSENTINEL AI</span>
          <button onClick={onClose} className="ml-auto text-text-tertiary md:hidden" aria-label="Close menu">
            <X className="size-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-5">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter((item) => hasPermission(user, ...(item.permission ? [item.permission] : [])));
            if (items.length === 0) return null;
            return (
              <div key={group.label}>
                <p className="px-3 text-xs font-semibold uppercase tracking-wider text-text-tertiary">
                  {group.label}
                </p>
                <div className="mt-2 space-y-0.5">
                  {items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.to === "/"}
                      onClick={onClose}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors duration-150 ${
                          isActive
                            ? "bg-sky-950/60 text-sky-300"
                            : "text-text-secondary hover:bg-surface-raised hover:text-text-primary"
                        }`
                      }
                    >
                      <item.icon className="size-4 shrink-0" aria-hidden="true" />
                      {item.label}
                    </NavLink>
                  ))}
                </div>
              </div>
            );
          })}
        </nav>

        <div className="border-t border-border p-3">
          <div className="flex items-center gap-2.5 rounded-md px-2 py-2">
            <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-sky-900 text-xs font-semibold text-sky-300">
              {user ? initials(user.email) : ""}
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm text-text-primary">{user?.email}</p>
              <p className="truncate text-xs text-text-tertiary">{user?.role}</p>
            </div>
            <button
              onClick={() => void logout()}
              aria-label="Sign out"
              className="text-text-tertiary hover:text-text-primary"
            >
              <LogOut className="size-4" />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}

function NotificationsButton() {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Notifications"
        className="rounded-md p-2 text-text-tertiary hover:bg-surface-raised hover:text-text-primary"
      >
        <Bell className="size-4" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-40 mt-2 w-72 rounded-card border border-border bg-surface p-4 shadow-xl">
            <p className="text-sm font-medium text-text-primary">Notifications</p>
            <p className="mt-2 text-sm text-text-tertiary">No new notifications.</p>
          </div>
        </>
      )}
    </div>
  );
}

function SystemStatus() {
  const { data } = useQuery({
    queryKey: ["healthz"],
    queryFn: () => api.get<{ status: string }>("/healthz"),
    refetchInterval: 30_000,
    retry: false,
  });
  const healthy = data?.status === "ok";
  return (
    <div className="hidden items-center gap-1.5 text-xs text-text-secondary sm:flex">
      <span className={`size-1.5 rounded-full ${healthy ? "bg-emerald-500" : "bg-amber-500"}`} aria-hidden="true" />
      {healthy ? "System Healthy" : "Checking…"}
    </div>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex size-8 items-center justify-center rounded-full bg-sky-900 text-xs font-semibold text-sky-300"
      >
        {user ? initials(user.email) : ""}
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-40 mt-2 w-56 rounded-card border border-border bg-surface p-2 shadow-xl">
            <div className="px-2 py-1.5">
              <p className="truncate text-sm text-text-primary">{user?.email}</p>
              <p className="text-xs text-text-tertiary">{user?.role}</p>
            </div>
            <button
              onClick={() => void logout()}
              className="mt-1 flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm text-text-secondary hover:bg-surface-raised hover:text-text-primary"
            >
              <LogOut className="size-4" /> Sign out
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export function AppShell() {
  const location = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const meta = currentPageMeta(location.pathname);

  return (
    <div className="flex min-h-screen">
      <Sidebar mobileOpen={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 shrink-0 items-center gap-4 border-b border-border px-4 sm:px-6">
          <button
            onClick={() => setMobileNavOpen(true)}
            aria-label="Open menu"
            className="text-text-tertiary md:hidden"
          >
            <Menu className="size-5" />
          </button>

          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-text-primary">{meta.title}</h2>
            <p className="hidden truncate text-xs text-text-tertiary sm:block">{meta.subtitle}</p>
          </div>

          <div className="ml-auto flex items-center gap-2 sm:gap-4">
            <div
              className="hidden items-center gap-2 rounded-md border border-border-strong bg-canvas px-3 text-text-tertiary opacity-60 sm:flex"
              title="Search arrives once devices and findings have dedicated pages"
            >
              <Search className="size-4" />
              <span className="py-2 text-sm">Search…</span>
            </div>
            <NotificationsButton />
            <SystemStatus />
            <UserMenu />
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-6 sm:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
