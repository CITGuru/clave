import { invoke } from "@tauri-apps/api/core";

export type LaunchInfo = {
  executable: string;
  args?: string[];
  env: [string, string][];
  namespace_prefix: string | null;
};

/**
 * The outcome of a launch attempt:
 * - `launched` — the daemon spawned the app contained (`pid` is the real process id).
 * - `resolved` — no daemon running, so the spec was resolved but nothing spawned.
 * - `failed` — the app is unknown / not launchable, or the launch was refused.
 */
export type LaunchResult =
  | { kind: "launched"; pid: number }
  | { kind: "resolved"; spec: LaunchInfo }
  | { kind: "failed" };

/** Ask the daemon to spawn `appId` contained, falling back to resolving the spec when no daemon is
 * connected (the fallback never spawns). */
export async function launchApp(appId: string): Promise<LaunchResult> {
  const pid = await invoke<number | null>("launch_app", { appId });
  if (pid != null) return { kind: "launched", pid };

  const spec = await invoke<LaunchInfo | null>("launch_spec", { appId });
  if (spec) return { kind: "resolved", spec };

  return { kind: "failed" };
}
