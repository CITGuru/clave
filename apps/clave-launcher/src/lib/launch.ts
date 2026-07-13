import { invoke } from "@tauri-apps/api/core";

export type LaunchInfo = {
  executable: string;
  args?: string[];
  env: [string, string][];
  namespace_prefix: string | null;
};

export type LaunchResult =
  | { kind: "launched"; pid: number }
  | { kind: "failed"; error: string }
  | { kind: "no_daemon" };

export async function launchApp(appId: string): Promise<LaunchResult> {
  try {
    const pid = await invoke<number>("launch_app", { appId });
    return { kind: "launched", pid };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("daemon not running")) return { kind: "no_daemon" };
    return { kind: "failed", error: msg };
  }
}
