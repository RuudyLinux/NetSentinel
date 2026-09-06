import { AlertTriangle, Check, Info, X, XCircle } from "lucide-react";
import { useCallback, useRef, useState, type ReactNode } from "react";
import { ToastContext, type ToastTone } from "../../lib/useToast";

interface ToastItem {
  id: number;
  tone: ToastTone;
  message: string;
}

const ICONS: Record<ToastTone, typeof Check> = {
  success: Check,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
};

const TONE_STYLES: Record<ToastTone, string> = {
  success: "border-pass-border text-pass",
  error: "border-critical-border text-critical",
  warning: "border-warning-border text-warning",
  info: "border-border-strong text-text-secondary",
};

// Toast lifetime, per latest.md section 48 ("approximately 3-5 seconds").
const AUTO_DISMISS_MS = 4000;

/** Bottom-right toast stack, auto-dismissed after AUTO_DISMISS_MS. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (message: string, tone: ToastTone = "info") => {
      const id = nextId.current++;
      setToasts((current) => [...current, { id, tone, message }]);
      window.setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col gap-2">
        {toasts.map((toast) => {
          const Icon = ICONS[toast.tone];
          return (
            <div
              key={toast.id}
              role="status"
              className={`pointer-events-auto flex items-center gap-2 rounded-card border bg-surface px-4 py-3 text-sm text-text-primary shadow-lg ${TONE_STYLES[toast.tone]}`}
            >
              <Icon className="size-4 shrink-0" aria-hidden="true" />
              <span>{toast.message}</span>
              <button
                onClick={() => dismiss(toast.id)}
                aria-label="Dismiss"
                className="ml-2 text-text-tertiary hover:text-text-secondary"
              >
                <X className="size-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
