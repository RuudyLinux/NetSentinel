import { Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";

export function SessionExpiredPage() {
  const navigate = useNavigate();
  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-[420px] rounded-card border border-border bg-surface p-8 text-center">
        <Clock className="mx-auto mb-3 size-8 text-warning" aria-hidden="true" />
        <h1 className="text-lg font-semibold text-text-primary">Your session expired</h1>
        <p className="mt-2 text-sm text-text-secondary">
          For your security, you need to sign in again.
        </p>
        <Button className="mt-6 w-full" onClick={() => navigate("/auth/login", { replace: true })}>
          Sign In Again
        </Button>
      </div>
    </div>
  );
}
