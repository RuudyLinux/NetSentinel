import {
  ClipboardList,
  FileBarChart,
  FileText,
  KeyRound,
  LayoutDashboard,
  Radar,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Users,
  type LucideIcon,
} from "lucide-react";
import { Permission } from "../../lib/permissions";

export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  /** Omitted => visible to any authenticated user. */
  permission?: Permission;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

/**
 * Sidebar structure (latest.md section 5): grouped, RBAC-filtered. Only groups
 * whose page exists today are listed — Risk/Drift/Remediation and most of
 * Administration (Organizations/Integrations/AI Providers/Retention/System
 * Settings) still have no backend and stay out until they do.
 */
export const NAV_GROUPS: NavGroup[] = [
  { label: "Overview", items: [{ label: "Dashboard", to: "/", icon: LayoutDashboard }] },
  {
    label: "Network",
    items: [
      { label: "Devices", to: "/devices", icon: Server, permission: Permission.DEVICE_READ },
      {
        label: "Discovery",
        to: "/discovery",
        icon: Radar,
        permission: Permission.CONFIG_UPLOAD,
      },
      {
        label: "Configurations",
        to: "/configurations",
        icon: FileText,
        permission: Permission.CONFIG_UPLOAD,
      },
    ],
  },
  {
    label: "Security",
    items: [
      { label: "Audits", to: "/audits", icon: ShieldCheck, permission: Permission.AUDIT_READ },
      { label: "Findings", to: "/findings", icon: ShieldAlert, permission: Permission.FINDING_READ },
    ],
  },
  {
    label: "Compliance",
    items: [
      {
        label: "Frameworks",
        to: "/compliance",
        icon: ClipboardList,
        permission: Permission.AUDIT_READ,
      },
    ],
  },
  {
    label: "AI Intelligence",
    items: [{ label: "AI Insights", to: "/ai-insights", icon: Sparkles }],
  },
  {
    label: "Reporting",
    items: [
      { label: "Reports", to: "/reports", icon: FileBarChart, permission: Permission.REPORT_READ },
    ],
  },
  {
    label: "Administration",
    items: [
      { label: "Users", to: "/admin/users", icon: Users, permission: Permission.USER_ADMIN },
      {
        label: "Roles & Permissions",
        to: "/admin/roles",
        icon: KeyRound,
        permission: Permission.USER_ADMIN,
      },
      {
        label: "Audit Logs",
        to: "/admin/audit-logs",
        icon: ScrollText,
        permission: Permission.USER_ADMIN,
      },
    ],
  },
];
