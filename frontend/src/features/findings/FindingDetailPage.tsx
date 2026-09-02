import { useParams } from "react-router-dom";
import { PageHeader } from "../../components/ui/PageHeader";
import { FindingPanel } from "./FindingPanel";

export function FindingDetailPage() {
  const { id } = useParams();
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="Finding" subtitle="What it is, why it matters, and how to fix it." />
      <FindingPanel findingId={Number(id)} />
    </div>
  );
}
