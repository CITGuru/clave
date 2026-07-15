import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card } from "@/components/ui";
import { api, type Device } from "@/lib/api";

function statusClass(s: string): string {
  if (s === "active") return "bg-emerald-500/15 text-emerald-400";
  if (s === "locked") return "bg-amber-500/15 text-amber-400";
  if (s === "wiped") return "bg-red-500/15 text-red-400";
  return "bg-clave-border text-clave-muted";
}

export function Devices({ onError }: { onError: (msg: string) => void }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setDevices(await api.listDevices());
    } catch (e) {
      onError(String(e));
    }
  }, [onError]);

  useEffect(() => {
    void reload();
  }, [reload]);

  async function guard(fn: () => Promise<unknown>) {
    setBusy(true);
    try {
      await fn();
      await reload();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <div className="border-b border-clave-border px-4 py-3 text-sm font-semibold">
        Devices ({devices.length})
      </div>
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase text-clave-muted">
          <tr>
            <th className="px-4 py-2 font-medium">Device key</th>
            <th className="px-4 py-2 font-medium">Enrolled by</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.id} className="border-t border-clave-border/60">
              <td className="px-4 py-2 font-mono text-xs">{d.pubkey.slice(0, 16)}…</td>
              <td className="px-4 py-2 text-clave-muted">user {d.enrolled_by}</td>
              <td className="px-4 py-2">
                <Badge className={statusClass(d.status)}>{d.status}</Badge>
              </td>
              <td className="px-4 py-2 text-right">
                <div className="flex justify-end gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy || d.status === "wiped" || d.status === "locked"}
                    onClick={() => void guard(() => api.lockDevice(d.id))}
                  >
                    Lock
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={busy || d.status === "wiped"}
                    onClick={() => void guard(() => api.wipeDevice(d.id))}
                  >
                    Wipe
                  </Button>
                </div>
              </td>
            </tr>
          ))}
          {devices.length === 0 && (
            <tr>
              <td className="px-4 py-6 text-center text-clave-muted" colSpan={4}>
                No devices enrolled yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  );
}
