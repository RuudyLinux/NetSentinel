import { useQuery } from "@tanstack/react-query";
import { Radar, Server, UploadCloud } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { EmptyState } from "../../components/ui/EmptyState";
import { PageHeader } from "../../components/ui/PageHeader";
import { Badge } from "../../components/ui/Badge";
import { api } from "../../lib/api";
import { vendorCapability } from "../../lib/capabilities";
import type { DeviceOut } from "../../types/api";

export function DevicesPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["devices"],
    queryFn: () => api.get<DeviceOut[]>("/devices"),
  });

  return (
    <div>
      <PageHeader
        title="Devices"
        subtitle="Manage and monitor discovered network infrastructure."
        action={
          <Link to="/discovery">
            <Button>
              <Radar className="size-4" /> Discover Devices
            </Button>
          </Link>
        }
      />

      {isLoading && <p className="text-text-secondary">Loading…</p>}
      {isError && <p className="text-text-secondary">Couldn't load devices. Try refreshing.</p>}

      {!isLoading && !isError && (!data || data.length === 0) && (
        <EmptyState
          icon={Server}
          title="No devices yet"
          description="Discover your authorized network to automatically identify devices, or add one by connecting or uploading its configuration."
          action={
            <div className="flex justify-center gap-2">
              <Link to="/discovery">
                <Button>Start Discovery</Button>
              </Link>
              <Link to="/configurations">
                <Button variant="secondary">
                  <UploadCloud className="size-4" /> Upload Configuration
                </Button>
              </Link>
            </div>
          }
        />
      )}

      {data && data.length > 0 && (
        <div className="overflow-x-auto rounded-card border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface text-left text-text-tertiary">
              <tr className="border-b border-border">
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Vendor</th>
                <th className="px-4 py-2 font-medium">OS</th>
                <th className="px-4 py-2 font-medium">OS Version</th>
              </tr>
            </thead>
            <tbody>
              {data.map((device) => (
                <tr key={device.id} className="border-b border-border last:border-0 hover:bg-surface">
                  <td className="px-4 py-2.5">
                    <Link to={`/devices/${device.id}`} className="font-medium text-sky-400 hover:underline">
                      {device.name}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-text-secondary">
                    <span className="inline-flex items-center gap-1.5">
                      {device.vendor}
                      <Badge tone={vendorCapability(device.vendor).tone}>
                        {vendorCapability(device.vendor).label}
                      </Badge>
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-text-secondary">{device.os}</td>
                  <td className="px-4 py-2.5 text-text-secondary">{device.os_version ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
