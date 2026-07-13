import { invoke } from "@tauri-apps/api/core";

export type LaunchInfo = {
  executable: string;
  args?: string[];
  env: [string, string][];
  namespace_prefix: string | null;
};

export type LaunchResult =
  | { kind: "launched"; pid: number }
  | { kind: "resolved"; spec: LaunchInfo }
  | { kind: "failed" };

export async function launchApp(appId: string): Promise<LaunchResult> {
  const pid = await invoke<number | null>("launch_app", { appId });
  if (pid != null) return { kind: "launched", pid };

  const spec = await invoke<LaunchInfo | null>("launch_spec", { appId });
  if (spec) return { kind: "resolved", spec };

  return { kind: "failed" };
}
