import { Loader2 } from "lucide-react";
import { type ButtonHTMLAttributes, forwardRef } from "react";

type Variant = "primary" | "secondary" | "tertiary" | "destructive";

const VARIANT_STYLES: Record<Variant, string> = {
  primary: "bg-sky-600 text-white hover:bg-sky-500 active:bg-sky-700 disabled:bg-sky-900",
  secondary:
    "border border-border-strong bg-surface text-text-primary hover:bg-surface-raised active:bg-slate-700 disabled:text-text-tertiary",
  tertiary: "text-text-secondary hover:text-text-primary hover:bg-surface disabled:text-text-tertiary",
  destructive: "bg-red-600 text-white hover:bg-red-500 active:bg-red-700 disabled:bg-red-950",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  loading?: boolean;
  loadingLabel?: string;
}

/** Normal/hover/press/disabled/loading states per latest.md section 8. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "primary", loading, loadingLabel, disabled, className = "", children, ...rest }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={`inline-flex h-9 items-center justify-center gap-2 rounded-md px-4 text-sm font-medium transition-colors duration-150 ease-hover disabled:cursor-not-allowed ${VARIANT_STYLES[variant]} ${className}`}
      {...rest}
    >
      {loading && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
      {loading ? (loadingLabel ?? children) : children}
    </button>
  ),
);
Button.displayName = "Button";
