import type { HTMLAttributes } from "react";

/** Bordered panel, token radius. Base building block for cards/panels/modals. */
export function Card({ className = "", ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`rounded-card border border-border bg-surface ${className}`}
      {...rest}
    />
  );
}
