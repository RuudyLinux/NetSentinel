import { Check, Radar } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { Input, PasswordInput } from "../../components/ui/Input";
import { useAuth } from "../../lib/authHooks";

type Status = "idle" | "submitting" | "success";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  // Ruling R13 (T16): demo accounts live under netsentinel.ai, not .local —
  // email-validator rejects .local as an RFC 6761 special-use domain.
  const [email, setEmail] = useState("admin@netsentinel.ai");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [status, setStatus] = useState<Status>("idle");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setStatus("submitting");
    try {
      await login(email, password);
      setStatus("success");
      window.setTimeout(() => navigate("/"), 400);
    } catch {
      // Do not reveal whether a specific account exists (section 12).
      setError("The email or password you entered is incorrect. Please check your credentials and try again.");
      setStatus("idle");
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-canvas px-4">
      {/* Subtle network-grid backdrop — CSS only, no imagery/particles (section 10). */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage:
            "linear-gradient(to right, var(--color-border-strong) 1px, transparent 1px), linear-gradient(to bottom, var(--color-border-strong) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
        aria-hidden="true"
      />

      <div className="relative w-full max-w-[420px]">
        <div className="mb-8 flex flex-col items-center text-center animate-[fade-up_0.35s_ease-out]">
          <Radar className="mb-3 size-8 text-sky-500" aria-hidden="true" />
          <h1 className="text-2xl font-semibold text-text-primary">Welcome back</h1>
          <p className="mt-1 text-sm text-text-secondary">Sign in to your security workspace</p>
        </div>

        <form
          onSubmit={submit}
          className="space-y-4 rounded-card border border-border bg-surface p-8 animate-[fade-scale_0.35s_ease-out]"
        >
          <Input
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            autoComplete="username"
            required
          />
          <PasswordInput
            label="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            autoComplete="current-password"
            required
          />

          <div className="flex items-center justify-end text-sm">
            <Link to="/auth/forgot-password" className="text-sky-400 hover:text-sky-300">
              Forgot password?
            </Link>
          </div>

          {error && (
            <p role="alert" className="rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
              Unable to sign in. {error}
            </p>
          )}

          <Button
            type="submit"
            className="w-full"
            loading={status === "submitting"}
            loadingLabel="Authenticating…"
            disabled={status === "success"}
          >
            {status === "success" ? (
              <>
                <Check className="size-4" /> Authentication successful
              </>
            ) : (
              "Sign In"
            )}
          </Button>

          <div className="flex items-center gap-3 text-xs text-text-tertiary">
            <div className="h-px flex-1 bg-border" />
            or
            <div className="h-px flex-1 bg-border" />
          </div>

          <Button
            type="button"
            variant="secondary"
            className="w-full"
            disabled
            title="Not configured for this deployment"
          >
            Continue with SSO
          </Button>
        </form>
      </div>
    </div>
  );
}
