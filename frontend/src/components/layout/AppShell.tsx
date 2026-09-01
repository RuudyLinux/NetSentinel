import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../../lib/auth";

const LINKS = [
  { to: "/", label: "Dashboard" },
  { to: "/upload", label: "Upload" },
  { to: "/audits", label: "Audits" },
];

export function AppShell() {
  const { user, logout } = useAuth();
  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b border-slate-800 px-6 py-3">
        <div className="flex items-center gap-6">
          <span className="font-semibold tracking-tight">NetSentinel AI</span>
          <nav className="flex gap-4 text-sm">
            {LINKS.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end
                className={({ isActive }) =>
                  isActive ? "text-sky-400" : "text-slate-400 hover:text-slate-200"
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span>
            {user?.email} · {user?.role}
          </span>
          <button
            onClick={logout}
            className="rounded border border-slate-700 px-3 py-1 hover:bg-slate-800"
          >
            Sign out
          </button>
        </div>
      </header>
      <main className="p-6">
        <Outlet />
      </main>
    </div>
  );
}
