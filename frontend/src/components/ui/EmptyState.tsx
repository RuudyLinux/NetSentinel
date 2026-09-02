import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

/** Section 57: every major page needs a useful empty state, not a blank screen. */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-card border border-dashed border-border-strong px-6 py-16 text-center">
      <Icon className="mb-3 size-8 text-text-tertiary" aria-hidden="true" />
      <p className="text-sm font-medium text-text-primary">{title}</p>
      <p className="mt-1 max-w-sm text-sm text-text-secondary">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
