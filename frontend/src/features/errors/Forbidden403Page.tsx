import { ShieldAlert } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";

export function Forbidden403Page() {
  const navigate = useNavigate();
  const location = useLocation();
  const requiredPermission = (location.state as { requiredPermission?: string } | null)?.requiredPermission;

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-[420px] rounded-card border border-border bg-surface p-8 text-center">
        <ShieldAlert className="mx-auto mb-3 size-8 text-critical" aria-hidden="true" />
        <p className="text-sm font-semibold tracking-wide text-text-tertiary">403</p>
        <h1 className="mt-1 text-lg font-semibold text-text-primary">Access restricted</h1>
        <p className="mt-2 text-sm text-text-secondary">You don't have permission to access this resource.</p>
        {requiredPermission && (
          <p className="mt-2 text-xs text-text-tertiary">Required permission: {requiredPermission}</p>
        )}
        <Button className="mt-6 w-full" onClick={() => navigate("/")}>
          Return to Dashboard
        </Button>
      </div>
    </div>
  );
}
