import { SearchX } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";

export function NotFound404Page() {
  const navigate = useNavigate();
  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-[420px] rounded-card border border-border bg-surface p-8 text-center">
        <SearchX className="mx-auto mb-3 size-8 text-text-tertiary" aria-hidden="true" />
        <p className="text-sm font-semibold tracking-wide text-text-tertiary">404</p>
        <h1 className="mt-1 text-lg font-semibold text-text-primary">This security endpoint doesn't exist</h1>
        <p className="mt-2 text-sm text-text-secondary">
          The resource you're looking for couldn't be found.
        </p>
        <Button className="mt-6 w-full" onClick={() => navigate("/")}>
          Back to Dashboard
        </Button>
      </div>
    </div>
  );
}
