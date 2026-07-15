export type Role = "Member" | "Admin" | "Owner";
export type MembershipStatus = "Invited" | "Active" | "Suspended";
export type DeviceStatus = "pending" | "active" | "locked" | "wiped";

export interface Me {
  user: number;
  workspace: number;
  role: Role;
}

export interface Member {
  user: number;
  email: string;
  role: Role;
  status: MembershipStatus;
}

export interface Invitation {
  workspace: number;
  email: string;
  role: Role;
  expires_at: number;
  accepted: boolean;
}

export interface Device {
  id: number;
  enrolled_by: number;
  status: DeviceStatus;
  pubkey: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

const BASE = import.meta.env.VITE_GATEWAY_URL ?? "";

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method,
    credentials: "include",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    throw new ApiError(res.status, (await res.text()) || res.statusText);
  }
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  me: () => req<Me>("GET", "/auth/me"),
  logout: () => req<void>("POST", "/auth/logout"),

  listMembers: () => req<Member[]>("GET", "/admin/members"),
  listInvitations: () => req<Invitation[]>("GET", "/admin/invitations"),
  invite: (email: string, role: Role) =>
    req<Invitation>("POST", "/admin/members/invite", { email, role }),
  changeRole: (user: number, role: Role) =>
    req<void>("POST", "/admin/members/role", { user, role }),
  suspend: (user: number) => req<void>("POST", "/admin/members/suspend", { user }),
  restore: (user: number) => req<void>("POST", "/admin/members/restore", { user }),

  listDevices: () => req<Device[]>("GET", "/admin/devices"),
  lockDevice: (device: number) =>
    req<void>("POST", "/admin/devices/lock", { device: String(device) }),
  wipeDevice: (device: number) =>
    req<void>("POST", "/admin/devices/wipe", { device: String(device) }),
};

export const LOGIN_URL = import.meta.env.VITE_CONSOLE_LOGIN_URL ?? "";
