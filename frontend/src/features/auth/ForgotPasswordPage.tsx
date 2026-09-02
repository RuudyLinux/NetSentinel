import { ArrowLeft, MailCheck } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { api } from "../../lib/api";

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await api.post("/auth/forgot-password", { email });
    } finally {
      // The response is identical whether the account exists or not — show the
      // same generic success state unconditionally (section 13).
      setSubmitting(false);
      setSent(true);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-[420px] rounded-card border border-border bg-surface p-8">
        <Link
          to="/auth/login"
          className="mb-6 flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary"
        >
          <ArrowLeft className="size-4" /> Back to sign in
        </Link>

        {sent ? (
          <div className="text-center">
            <MailCheck className="mx-auto mb-3 size-8 text-pass" aria-hidden="true" />
            <h1 className="text-lg font-semibold text-text-primary">Check your email</h1>
            <p className="mt-2 text-sm text-text-secondary">
              If an account is associated with that address, reset instructions have been sent.
            </p>
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <div>
              <h1 className="text-lg font-semibold text-text-primary">Reset your password</h1>
              <p className="mt-1 text-sm text-text-secondary">
                Enter your account email and we'll send reset instructions.
              </p>
            </div>
            <Input
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="username"
              required
            />
            <Button type="submit" className="w-full" loading={submitting} loadingLabel="Sending…">
              Send Reset Link
            </Button>
          </form>
        )}
      </div>
    </div>
  );
}
