import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Sparkles, X } from "lucide-react";
import { Badge, type Tone } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { useToast } from "../../lib/useToast";
import { api } from "../../lib/api";
import { RequirePermission } from "../../lib/auth";
import { Permission } from "../../lib/permissions";
import type { UnknownConstructWithAi } from "../../types/api";

const STATUS_TONE: Record<string, Tone> = { pending: "neutral", approved: "pass", rejected: "critical" };

/**
 * Advisory AI interpretation of config lines the deterministic parser couldn't
 * classify. A suggestion here never changes the audit score or applies itself —
 * it's only ever recorded once a human with MAPPING_APPROVE approves it.
 */
export function UnknownConstructsPanel({ auditId }: { auditId: number }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const queryKey = ["unknown-constructs", auditId];

  const { data } = useQuery({
    queryKey,
    queryFn: () => api.get<UnknownConstructWithAi[]>(`/audits/${auditId}/unknown-constructs`),
  });

  const interpret = useMutation({
    mutationFn: (index: number) =>
      api.post(`/audits/${auditId}/unknown-constructs/${index}/interpret`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey }),
    onError: (error: Error) => toast.push(error.message, "error"),
  });

  const review = useMutation({
    mutationFn: ({ index, status }: { index: number; status: "approved" | "rejected" }) =>
      api.patch(`/audits/${auditId}/unknown-constructs/${index}/interpretation`, { status }),
    onSuccess: () => {
      toast.push("Saved", "success");
      queryClient.invalidateQueries({ queryKey });
    },
    onError: (error: Error) => toast.push(error.message, "error"),
  });

  if (!data || data.length === 0) return null;

  return (
    <Card className="p-5">
      <div className="flex items-center gap-2">
        <Sparkles className="size-4 text-text-tertiary" aria-hidden="true" />
        <p className="text-sm font-semibold text-text-primary">
          Unrecognized configuration ({data.length})
        </p>
      </div>
      <p className="mt-1 text-xs text-text-tertiary">
        Advisory only — a suggestion here never changes this audit's score or applies
        automatically. A human always approves or rejects it.
      </p>

      <div className="mt-4 space-y-3">
        {data.map((item) => (
          <div key={item.index} className="rounded-md border border-border p-3">
            <pre className="overflow-x-auto rounded bg-canvas p-2 font-mono text-xs text-text-secondary">
              {item.text}
            </pre>
            <p className="mt-1 text-xs text-text-tertiary">
              Line {item.lineno} · {item.block ?? "unknown block"}
            </p>

            {!item.interpretation && (
              <RequirePermission perm={Permission.MAPPING_SUGGEST}>
                <Button
                  variant="secondary"
                  className="mt-2"
                  loading={interpret.isPending}
                  loadingLabel="Asking AI…"
                  onClick={() => interpret.mutate(item.index)}
                >
                  <Sparkles className="size-4" /> Ask AI to interpret
                </Button>
              </RequirePermission>
            )}

            {item.interpretation && (
              <div className="mt-2 space-y-1.5 border-t border-border pt-2">
                <p className="text-sm text-text-secondary">{item.interpretation.interpretation}</p>
                <p className="text-xs text-text-tertiary">
                  Suggested control: {item.interpretation.suggested_parameter ?? "none identified"}
                  {item.interpretation.suggested_parameter !== null &&
                    ` = ${String(item.interpretation.suggested_value)}`}{" "}
                  · confidence {Math.round(item.interpretation.confidence * 100)}%
                </p>
                <div className="flex items-center gap-2">
                  <Badge tone={STATUS_TONE[item.interpretation.status]}>
                    {item.interpretation.status}
                  </Badge>
                  {item.interpretation.status === "pending" && (
                    <RequirePermission perm={Permission.MAPPING_APPROVE}>
                      <Button
                        variant="secondary"
                        loading={review.isPending}
                        onClick={() => review.mutate({ index: item.index, status: "approved" })}
                      >
                        <Check className="size-4" /> Approve
                      </Button>
                      <Button
                        variant="secondary"
                        loading={review.isPending}
                        onClick={() => review.mutate({ index: item.index, status: "rejected" })}
                      >
                        <X className="size-4" /> Reject
                      </Button>
                    </RequirePermission>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}
