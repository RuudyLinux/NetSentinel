import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../lib/auth";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  // Ruling R13 (T16): demo accounts live under netsentinel.ai, not .local —
  // email-validator rejects .local as an RFC 6761 special-use domain.
  const [email, setEmail] = useState("admin@netsentinel.ai");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await login(email, password);
      navigate("/");
    } catch {
      setError("Invalid email or password");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-8"
      >
        <div>
          <h1 className="text-2xl font-semibold">NetSentinel AI</h1>
          <p className="text-sm text-slate-400">Network security compliance auditor</p>
        </div>
        <input
          className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="Email"
          autoComplete="username"
        />
        <input
          className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          autoComplete="current-password"
        />
        {error && (
          <p role="alert" className="text-sm text-red-400">
            {error}
          </p>
        )}
        <button
          type="submit"
          className="w-full rounded bg-sky-600 py-2 font-medium hover:bg-sky-500"
        >
          Sign in
        </button>
      </form>
    </div>
  );
}
