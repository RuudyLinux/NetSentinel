import { Sparkles } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { PageHeader } from "../../components/ui/PageHeader";

const STILL_PLANNED = [
  "Learned Mappings — a library of approved mappings, reused automatically across future audits (today's approvals are recorded for evidence but don't yet feed back into re-parsing).",
  "AI Evaluation — accuracy tracking against human review outcomes.",
  "Broader AI interpretation — explaining a passing/failing rule result in plain language, not just unrecognized config lines.",
];

/**
 * Phase 8, live version: OpenRouter is now configured (NETSENTINEL_OPENROUTER_API_KEY).
 * The connected capability is scoped to interpreting config lines the deterministic
 * parser couldn't classify — see UnknownConstructsPanel on each audit's detail page.
 * Everything below is what's still not built, not a re-statement of what is.
 */
export function AiInsightsPage() {
  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader
        title="AI Insights"
        subtitle="Advisory only — deterministic compliance rules remain authoritative."
      />

      <Card className="p-6">
        <div className="flex items-center gap-2">
          <Sparkles className="size-5 text-sky-500" aria-hidden="true" />
          <p className="text-sm font-medium text-text-primary">Connected: unrecognized config interpretation</p>
        </div>
        <p className="mt-2 text-sm text-text-secondary">
          When an audit's config parser hits a line it doesn't recognize, an AI
          suggestion for what control it likely sets — with a confidence score and
          the exact config text as evidence — is available on that audit's detail
          page. A human with the right permission always approves, edits, or
          rejects it before it's recorded; nothing is applied automatically.
        </p>
        <Link to="/audits" className="mt-4 inline-block">
          <Button variant="secondary">Go to Audits</Button>
        </Link>
      </Card>

      <Card className="mt-4 p-6">
        <p className="text-sm font-medium text-text-primary">Still not built</p>
        <ul className="mt-3 space-y-2 text-sm text-text-secondary">
          {STILL_PLANNED.map((item) => (
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
