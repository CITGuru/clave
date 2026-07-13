import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  ChevronDown,
  ChevronRight,
  Loader2,
  Search,
  Shield,
  ShieldCheck,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { visualFor } from "@/lib/app-visual";
import { launchApp } from "@/lib/launch";

type AppInfo = { id: string; label: string };
type CapStatus = { capability: string; status: string };

const dot = (s: string): string =>
  s === "enforced"
    ? "bg-emerald-500"
    : s === "development-only"
      ? "bg-amber-500"
      : "bg-zinc-300";
const statusText = (s: string): string =>
  s === "enforced"
    ? "text-emerald-600"
    : s === "development-only"
      ? "text-amber-600"
      : "text-zinc-400";

export function CompactView() {
  const [apps, setApps] = useState<AppInfo[]>([]);
  const [posture, setPosture] = useState<CapStatus[]>([]);
  const [query, setQuery] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [showPosture, setShowPosture] = useState(false);
  const [launching, setLaunching] = useState<Set<string>>(new Set());

  useEffect(() => {
    invoke<AppInfo[]>("list_apps").then(setApps).catch(console.error);
    invoke<CapStatus[]>("enforcement").then(setPosture).catch(console.error);
  }, []);

  const filtered = useMemo(
    () =>
      apps.filter((a) =>
        a.label.toLowerCase().includes(query.trim().toLowerCase()),
      ),
    [apps, query],
  );
  const issues = posture.filter((c) => c.status === "development-only").length;

  function flashToast(msg: string) {
    setToast(msg);
    window.setTimeout(() => setToast(null), 2600);
  }

  async function launch(app: AppInfo) {
    if (launching.has(app.id)) return;
    setLaunching((s) => new Set(s).add(app.id));
    try {
      const res = await launchApp(app.id);
      if (res.kind === "launched") {
        flashToast(`Launched ${app.label} — contained · pid ${res.pid}`);
      } else if (res.kind === "no_daemon") {
        flashToast(`Start the daemon to launch ${app.label}`);
      } else {
        flashToast(`Couldn't launch ${app.label}: ${res.error}`);
      }
    } catch (e) {
      console.error(e);
      flashToast(`Couldn’t launch ${app.label}`);
    } finally {
      setLaunching((s) => {
        const n = new Set(s);
        n.delete(app.id);
        return n;
      });
    }
  }

  return (
    <div className="relative flex h-screen flex-col overflow-hidden bg-white text-zinc-900">
      <header className="flex items-center gap-2.5 px-4 pb-2 pt-4">
        <div className="grid h-8 w-8 place-items-center rounded-lg bg-blue-600 text-white shadow-sm">
          <Shield className="h-[18px] w-[18px]" strokeWidth={2.4} />
        </div>
        <div className="text-[15px] font-semibold tracking-tight">Clave</div>
      </header>

      <div className="px-4 pb-2">
        <div className="relative">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search"
            className="h-9 bg-white pr-9 text-[13px]"
          />
          <Search className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
        </div>
      </div>

      <main className="flex-1 overflow-y-auto px-2 pb-2">
        {filtered.map((app) => {
          const { src, Icon, bg } = visualFor(app.label);
          const busy = launching.has(app.id);
          return (
            <button
              key={app.id}
              type="button"
              disabled={busy}
              onClick={() => launch(app)}
              className="group flex w-full items-center gap-3 rounded-xl px-2 py-1.5 text-left transition-colors hover:bg-zinc-100 disabled:cursor-default"
            >
              <span
                className={cn(
                  "relative grid h-10 w-10 shrink-0 place-items-center rounded-[13px] text-white shadow-sm ring-1 ring-black/5",
                  bg,
                )}
              >
                {src ? (
                  <img
                    src={src}
                    alt=""
                    draggable={false}
                    className={cn(
                      "h-6 w-6 object-contain transition-opacity",
                      busy && "opacity-30",
                    )}
                  />
                ) : (
                  <Icon
                    className={cn("h-5 w-5 transition-opacity", busy && "opacity-30")}
                    strokeWidth={2}
                  />
                )}
                {busy && (
                  <span className="absolute inset-0 grid place-items-center">
                    <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2.4} />
                  </span>
                )}
              </span>
              <span className="min-w-0 flex-1 truncate text-[13px] font-medium">
                {app.label}
              </span>
              {busy ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-zinc-400" />
              ) : (
                <ChevronRight className="h-4 w-4 shrink-0 text-zinc-300 transition-colors group-hover:text-zinc-500" />
              )}
            </button>
          );
        })}
        {filtered.length === 0 && (
          <p className="px-3 py-10 text-center text-sm text-zinc-400">
            {apps.length === 0 ? "No work apps." : "No apps match your search."}
          </p>
        )}
      </main>

      <footer className="border-t border-zinc-200 px-2 py-1.5">
        <button
          type="button"
          onClick={() => setShowPosture((v) => !v)}
          className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-zinc-100"
        >
          <ShieldCheck className="h-4 w-4 text-zinc-500" />
          <span className="text-[12px] font-medium text-zinc-600">Compliance</span>
          <div className="ml-1 flex items-center gap-1">
            {posture.map((c) => (
              <span
                key={c.capability}
                className={cn("h-1.5 w-1.5 rounded-full", dot(c.status))}
              />
            ))}
          </div>
          {issues > 0 && (
            <span className="grid h-[18px] min-w-[18px] place-items-center rounded-full bg-zinc-200 px-1 text-[11px] font-semibold text-zinc-600">
              {issues}
            </span>
          )}
          <ChevronDown
            className={cn(
              "ml-auto h-4 w-4 text-zinc-400 transition-transform",
              showPosture && "rotate-180",
            )}
          />
        </button>
        {showPosture && (
          <div className="space-y-px px-2 pb-1 pt-1">
            {posture.map((c) => (
              <div
                key={c.capability}
                className="flex items-center gap-2 py-0.5 text-[11px]"
              >
                <span
                  className={cn("h-1.5 w-1.5 shrink-0 rounded-full", dot(c.status))}
                />
                <span className="flex-1 truncate text-zinc-600">
                  {c.capability}
                </span>
                <span className={cn("font-medium", statusText(c.status))}>
                  {c.status.replace(/-/g, " ")}
                </span>
              </div>
            ))}
          </div>
        )}
      </footer>

      {toast && (
        <div className="pointer-events-none absolute bottom-16 left-1/2 -translate-x-1/2 rounded-full bg-zinc-900 px-4 py-2 text-[13px] font-medium text-white shadow-lg">
          {toast}
        </div>
      )}
    </div>
  );
}
