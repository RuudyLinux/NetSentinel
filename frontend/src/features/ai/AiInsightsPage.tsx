import { Sparkles } from "lucide-react";
import { Card } from "../../components/ui/Card";
import { PageHeader } from "../../components/ui/PageHeader";

const PLANNED = [
  "AI Insights — evidence-backed interpretations of ambiguous configuration, with a confidence score.",
  "Training Center — approve, edit, or reject each suggested control mapping before it's used.",
  "Learned Mappings — the library of human-approved mappings built up over time.",
  "AI Evaluation — accuracy tracking against human review outcomes.",
];

/**
 * Phase 8: no AI provider is wired into the backend (checked — zero LLM/provider
 * code anywhere). Building a live version needs a real vendor/billing decision.
 * This is a deliberate, clearly-labeled placeholder — not a working feature — per
 * an explicit choice to ship the shell now and connect it later.
 */
export function AiInsightsPage() {
  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader title="AI Insights" subtitle="Advisory only — deterministic compliance rules remain authoritative." />
      <Card className="p-6 text-center">
        <Sparkles className="mx-auto mb-3 size-8 text-text-tertiary" aria-hidden="true" />
        <p className="text-sm font-medium text-text-primary">Not connected yet</p>
        <p className="mx-auto mt-2 max-w-md text-sm text-text-secondary">
          No AI provider is configured on this deployment. Once one is, this space
          fills with:
        </p>
        <ul className="mx-auto mt-4 max-w-md space-y-2 text-left text-sm text-text-secondary">
          {PLANNED.map((item) => (
            <li key={item} className="flex gap-2">
              <span className="text-text-tertiary">·</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
