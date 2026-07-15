import { useCallback, useEffect, useState } from "react";

import { Badge, Button, Card, Input, Select } from "@/components/ui";
import { api, type Invitation, type Member, type Role } from "@/lib/api";

const ROLES: Role[] = ["Member", "Admin", "Owner"];

function statusClass(s: string): string {
  if (s === "Active") return "bg-emerald-500/15 text-emerald-400";
  if (s === "Suspended") return "bg-red-500/15 text-red-400";
  return "bg-clave-border text-clave-muted";
}

export function Members({ onError }: { onError: (msg: string) => void }) {
  const [members, setMembers] = useState<Member[]>([]);
  const [invites, setInvites] = useState<Invitation[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("Member");
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      setMembers(await api.listMembers());
      setInvites(await api.listInvitations());
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
    <div className="space-y-6">
      <Card className="p-4">
        <h2 className="mb-3 text-sm font-semibold">Invite a member</h2>
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (!email) return;
            void guard(async () => {
              await api.invite(email, role);
              setEmail("");
            });
          }}
        >
          <Input
            type="email"
            placeholder="name@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="min-w-64 flex-1"
          />
          <Select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
          <Button type="submit" disabled={busy || !email}>
            Send invite
          </Button>
        </form>
      </Card>

      <Card>
        <div className="border-b border-clave-border px-4 py-3 text-sm font-semibold">
          Members ({members.length})
        </div>
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-clave-muted">
            <tr>
              <th className="px-4 py-2 font-medium">Email</th>
              <th className="px-4 py-2 font-medium">Role</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.user} className="border-t border-clave-border/60">
                <td className="px-4 py-2">{m.email || `user ${m.user}`}</td>
                <td className="px-4 py-2">
                  <Select
                    value={m.role}
                    disabled={busy}
                    onChange={(e) =>
                      void guard(() => api.changeRole(m.user, e.target.value as Role))
                    }
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </Select>
                </td>
                <td className="px-4 py-2">
                  <Badge className={statusClass(m.status)}>{m.status}</Badge>
                </td>
                <td className="px-4 py-2 text-right">
                  {m.status === "Suspended" ? (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => void guard(() => api.restore(m.user))}
                    >
                      Restore
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={busy}
                      onClick={() => void guard(() => api.suspend(m.user))}
                    >
                      Suspend
                    </Button>
                  )}
                </td>
              </tr>
            ))}
            {members.length === 0 && (
              <tr>
                <td className="px-4 py-6 text-center text-clave-muted" colSpan={4}>
                  No members yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>

      {invites.length > 0 && (
        <Card>
          <div className="border-b border-clave-border px-4 py-3 text-sm font-semibold">
            Pending invitations ({invites.filter((i) => !i.accepted).length})
          </div>
          <ul className="divide-y divide-clave-border/60 text-sm">
            {invites.map((i) => (
              <li key={i.email} className="flex items-center justify-between px-4 py-2">
                <span>{i.email}</span>
                <span className="flex items-center gap-2 text-clave-muted">
                  <Badge className="bg-clave-border text-clave-muted">{i.role}</Badge>
                  {i.accepted ? "accepted" : "pending"}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
