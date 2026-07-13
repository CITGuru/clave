import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Bell,
  ChevronRight,
  Clock,
  Globe,
  HelpCircle,
  Inbox,
  LayoutGrid,
  Loader2,
  type LucideIcon,
  Menu,
  PanelLeftClose,
  Rocket,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Wifi,
  X,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { visualFor } from "@/lib/app-visual";
import { launchApp } from "@/lib/launch";

type AppInfo = { id: string; label: string };
type CapStatus = { capability: string; status: string };
type Section =
  | "launch"
  | "apps"
  | "websites"
  | "recent"
  | "notifications"
  | "help"
  | "connectivity"
  | "compliance"
  | "settings";

function AppTile({
  app,
  editing,
  busy,
  onLaunch,
  onRemove,
}: {
  app: AppInfo;
  editing: boolean;
  busy: boolean;
  onLaunch: (a: AppInfo) => void;
  onRemove: (id: string) => void;
}) {
  const { src, Icon, bg } = visualFor(app.label);
  return (
    <div className="group relative">
      <button
        type="button"
        disabled={editing || busy}
        onClick={() => onLaunch(app)}
        className={cn(
          "flex w-full flex-col items-center gap-2 rounded-xl p-2 text-center transition-colors",
          editing || busy ? "cursor-default" : "hover:bg-zinc-100",
        )}
      >
        <span
          className={cn(
            "relative grid h-16 w-16 place-items-center rounded-[20px] text-white shadow-sm ring-1 ring-black/5 transition-transform duration-150",
            editing
              ? "animate-pulse"
              : busy
                ? ""
                : "group-hover:scale-105 group-active:scale-95",
            bg,
          )}
        >
          {src ? (
            <img
              src={src}
              alt=""
              draggable={false}
              className={cn(
                "h-9 w-9 object-contain transition-opacity",
                busy && "opacity-30",
              )}
            />
          ) : (
            <Icon
              className={cn("h-8 w-8 transition-opacity", busy && "opacity-30")}
              strokeWidth={1.9}
            />
          )}
          {busy && (
            <span className="absolute inset-0 grid place-items-center">
              <Loader2 className="h-6 w-6 animate-spin" strokeWidth={2.4} />
            </span>
          )}
        </span>
        <span className="line-clamp-2 w-full text-[11px] font-medium leading-tight text-zinc-600">
          {app.label}
        </span>
      </button>
      {editing && (
        <button
          type="button"
          title={`Remove ${app.label}`}
          onClick={() => onRemove(app.id)}
          className="absolute right-2 top-2 z-10 grid h-5 w-5 place-items-center rounded-full bg-zinc-900/80 text-white shadow-sm transition-colors hover:bg-red-600"
        >
          <X className="h-3 w-3" strokeWidth={3} />
        </button>
      )}
    </div>
  );
}

function NavItem({
  icon: Icon,
  label,
  active,
  count,
  chevron,
  collapsed,
  onClick,
}: {
  icon: LucideIcon;
  label: string;
  active?: boolean;
  count?: number;
  chevron?: boolean;
  collapsed?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      title={collapsed ? label : undefined}
      onClick={onClick}
      className={cn(
        "relative flex w-full items-center rounded-lg py-2 text-[13px] font-medium transition-colors",
        collapsed ? "justify-center px-0" : "gap-2.5 pl-3 pr-2",
        active ? "bg-blue-50 text-blue-700" : "text-zinc-600 hover:bg-zinc-100",
      )}
    >
      {active && !collapsed && (
        <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-full bg-blue-600" />
      )}
      <Icon className="h-[18px] w-[18px] shrink-0" strokeWidth={2} />
      {!collapsed && (
        <>
          <span className="flex-1 text-left">{label}</span>
          {count != null && (
            <span
              className={cn(
                "grid h-[18px] min-w-[18px] place-items-center rounded-full px-1 text-[11px] font-semibold",
                active ? "bg-blue-600 text-white" : "bg-zinc-200 text-zinc-600",
              )}
            >
              {count}
            </span>
          )}
          {chevron && <ChevronRight className="h-4 w-4 text-zinc-400" />}
        </>
      )}
    </button>
  );
}

function Placeholder({
  title,
  icon: Icon,
  text,
}: {
  title: string;
  icon: LucideIcon;
  text: string;
}) {
  return (
    <div>
      {title && (
        <h1 className="text-[26px] font-semibold tracking-tight">{title}</h1>
      )}
      <div className="mt-12 flex flex-col items-center gap-3 text-center">
        <div className="grid h-12 w-12 place-items-center rounded-2xl bg-zinc-100 text-zinc-400">
          <Icon className="h-6 w-6" />
        </div>
        <p className="max-w-sm text-sm text-zinc-500">{text}</p>
      </div>
    </div>
  );
}

function Grid({
  items,
  editing,
  query,
  launching,
  onLaunch,
  onRemove,
}: {
  items: AppInfo[];
  editing: boolean;
  query: string;
  launching: Set<string>;
  onLaunch: (a: AppInfo) => void;
  onRemove: (id: string) => void;
}) {
  return items.length > 0 ? (
    <div className="grid gap-x-2 gap-y-7 [grid-template-columns:repeat(auto-fill,minmax(104px,1fr))]">
      {items.map((a) => (
        <AppTile
          key={a.id}
          app={a}
          editing={editing}
          busy={launching.has(a.id)}
          onLaunch={onLaunch}
          onRemove={onRemove}
        />
      ))}
    </div>
  ) : (
    <p className="py-16 text-center text-sm text-zinc-400">
      {query ? `No apps match “${query}”.` : "Nothing here yet."}
    </p>
  );
}

export function FullView({
  initialCollapsed = false,
  initialSection = "launch",
  initialEditing = false,
}: {
  initialCollapsed?: boolean;
  initialSection?: Section;
  initialEditing?: boolean;
} = {}) {
  const [apps, setApps] = useState<AppInfo[]>([]);
  const [posture, setPosture] = useState<CapStatus[]>([]);
  const [query, setQuery] = useState("");
  const [section, setSection] = useState<Section>(initialSection);
  const [toast, setToast] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(initialCollapsed);
  const [editing, setEditing] = useState(initialEditing);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [recents, setRecents] = useState<AppInfo[]>([]);
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
  const complianceIssues = posture.filter(
    (c) => c.status === "development-only",
  ).length;

  function flashToast(msg: string) {
    setToast(msg);
    window.setTimeout(() => setToast(null), 2800);
  }

  async function launch(app: AppInfo) {
    if (launching.has(app.id)) return;
    setLaunching((s) => new Set(s).add(app.id));
    try {
      const res = await launchApp(app.id);
      if (res.kind === "launched") {
        setRecents((r) => [app, ...r.filter((x) => x.id !== app.id)].slice(0, 12));
        flashToast(`Launched ${app.label} — contained · pid ${res.pid}`);
      } else if (res.kind === "resolved") {
        setRecents((r) => [app, ...r.filter((x) => x.id !== app.id)].slice(0, 12));
        flashToast(`${app.label} resolved — start the daemon to launch contained`);
      } else {
        flashToast(`Couldn’t launch ${app.label}`);
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

  function removeApp(id: string) {
    setHidden((h) => new Set(h).add(id));
  }

  const toggleCollapsed = () => setCollapsed((v) => !v);

  const footerIcons: { Icon: LucideIcon; title: string; onClick: () => void }[] = [
    { Icon: PanelLeftClose, title: "Collapse sidebar", onClick: toggleCollapsed },
    { Icon: Clock, title: "Recent", onClick: () => setSection("recent") },
    { Icon: Inbox, title: "Notifications", onClick: () => setSection("notifications") },
    { Icon: HelpCircle, title: "Help", onClick: () => setSection("help") },
  ];

  const gridApps =
    section === "launch" ? filtered.filter((a) => !hidden.has(a.id)) : filtered;

  return (
    <div className="flex h-screen overflow-hidden bg-white text-zinc-900">
      <aside
        className={cn(
          "flex shrink-0 flex-col border-r border-zinc-200 bg-zinc-50 transition-[width] duration-200",
          collapsed ? "w-16" : "w-56",
        )}
      >
        <div className={cn("flex flex-col gap-3 p-3", collapsed && "items-center")}>
          <div
            className={cn(
              "flex items-center",
              collapsed ? "justify-center" : "gap-2 px-1",
            )}
          >
            <button
              type="button"
              title="Toggle sidebar"
              onClick={toggleCollapsed}
              className="grid h-8 w-8 place-items-center rounded-md text-zinc-500 hover:bg-zinc-200/70"
            >
              <Menu className="h-[18px] w-[18px]" />
            </button>
            {!collapsed && (
              <div className="flex items-center gap-1.5 text-[13px] font-semibold text-zinc-700">
                <Shield className="h-4 w-4 text-blue-600" />
                Clave
              </div>
            )}
          </div>
          {!collapsed && (
            <div className="relative">
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search"
                className="h-9 bg-white pr-9 text-[13px]"
              />
              <Search className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
            </div>
          )}
          <nav className="flex flex-col gap-0.5 pt-1">
            <NavItem
              icon={Rocket}
              label="Launch"
              active={section === "launch"}
              collapsed={collapsed}
              onClick={() => setSection("launch")}
            />
            <NavItem
              icon={LayoutGrid}
              label="Apps"
              active={section === "apps"}
              collapsed={collapsed}
              onClick={() => setSection("apps")}
            />
            <NavItem
              icon={Globe}
              label="Websites"
              active={section === "websites"}
              chevron
              collapsed={collapsed}
              onClick={() => setSection("websites")}
            />
          </nav>
        </div>

        <div
          className={cn(
            "mt-auto flex flex-col gap-0.5 p-3",
            collapsed && "items-center",
          )}
        >
          <NavItem
            icon={Wifi}
            label="Connectivity"
            active={section === "connectivity"}
            collapsed={collapsed}
            onClick={() => setSection("connectivity")}
          />
          <NavItem
            icon={ShieldCheck}
            label="Compliance"
            active={section === "compliance"}
            count={complianceIssues || undefined}
            collapsed={collapsed}
            onClick={() => setSection("compliance")}
          />
          <NavItem
            icon={Settings}
            label="Settings"
            active={section === "settings"}
            collapsed={collapsed}
            onClick={() => setSection("settings")}
          />
          {!collapsed && (
            <div className="mt-2 flex items-center gap-1 border-t border-zinc-200 px-1 pt-2 text-zinc-400">
              {footerIcons.map(({ Icon, title, onClick }) => (
                <button
                  key={title}
                  type="button"
                  title={title}
                  onClick={onClick}
                  className="grid h-7 w-7 place-items-center rounded-md hover:bg-zinc-200/70 hover:text-zinc-600"
                >
                  <Icon className="h-[15px] w-[15px]" />
                </button>
              ))}
            </div>
          )}
        </div>
      </aside>

      <main className="relative flex-1 overflow-y-auto">
        <div className="px-8 py-7">
          {(section === "launch" || section === "apps") && (
            <>
              <h1 className="text-[26px] font-semibold tracking-tight">
                {section === "launch" ? "Launch" : "Apps"}
              </h1>
              <div className="mb-6 mt-3 flex items-center justify-between">
                <span className="text-[13px] text-zinc-500">
                  {section === "launch"
                    ? "Starred apps & websites"
                    : "All work apps"}
                </span>
                <button
                  type="button"
                  onClick={() => setEditing((v) => !v)}
                  className="text-[13px] font-medium text-blue-600 hover:underline"
                >
                  {editing ? "Done" : "Edit"}
                </button>
              </div>
              <Grid
                items={gridApps}
                editing={editing}
                query={query}
                launching={launching}
                onLaunch={launch}
                onRemove={removeApp}
              />
            </>
          )}

          {section === "recent" && (
            <>
              <h1 className="text-[26px] font-semibold tracking-tight">Recent</h1>
              <p className="mb-6 mt-3 text-[13px] text-zinc-500">
                Recently launched
              </p>
              {recents.length > 0 ? (
                <Grid
                  items={recents}
                  editing={editing}
                  query={query}
                  launching={launching}
                  onLaunch={launch}
                  onRemove={removeApp}
                />
              ) : (
                <Placeholder
                  title=""
                  icon={Clock}
                  text="Apps you launch will show up here."
                />
              )}
            </>
          )}

          {section === "websites" && (
            <Placeholder
              title="Websites"
              icon={Globe}
              text="Work web apps appear here once your policy defines them."
            />
          )}
          {section === "notifications" && (
            <Placeholder
              title="Notifications"
              icon={Bell}
              text="You’re all caught up — no new notifications."
            />
          )}
          {section === "help" && (
            <Placeholder
              title="Help"
              icon={HelpCircle}
              text="Clave keeps your work apps and data in a secure, contained workspace. Reach your admin for policy or access questions."
            />
          )}
          {section === "connectivity" && (
            <Placeholder
              title="Connectivity"
              icon={Wifi}
              text="Split-tunnel routing is managed by Clave — work traffic flows through the secure gateway, personal traffic goes direct."
            />
          )}
          {section === "compliance" && (
            <div>
              <h1 className="text-[26px] font-semibold tracking-tight">
                Compliance
              </h1>
              <p className="mb-6 mt-3 text-[13px] text-zinc-500">
                This device’s enforcement posture.
              </p>
              <div className="max-w-xl divide-y divide-zinc-100 overflow-hidden rounded-xl border border-zinc-200">
                {posture.map((c) => (
                  <div
                    key={c.capability}
                    className="flex items-center gap-3 px-4 py-3"
                  >
                    <span
                      className={cn(
                        "h-2 w-2 shrink-0 rounded-full",
                        c.status === "enforced"
                          ? "bg-emerald-500"
                          : c.status === "development-only"
                            ? "bg-amber-500"
                            : "bg-zinc-300",
                      )}
                    />
                    <span className="flex-1 text-[13px] text-zinc-700">
                      {c.capability}
                    </span>
                    <span
                      className={cn(
                        "text-[12px] font-medium",
                        c.status === "enforced"
                          ? "text-emerald-600"
                          : c.status === "development-only"
                            ? "text-amber-600"
                            : "text-zinc-400",
                      )}
                    >
                      {c.status.replace(/-/g, " ")}
                    </span>
                  </div>
                ))}
                {posture.length === 0 && (
                  <div className="px-4 py-6 text-center text-sm text-zinc-400">
                    No posture reported.
                  </div>
                )}
              </div>
            </div>
          )}
          {section === "settings" && (
            <Placeholder
              title="Settings"
              icon={Settings}
              text="Account, device, and policy settings."
            />
          )}
        </div>

        {toast && (
          <div className="pointer-events-none absolute bottom-5 left-1/2 -translate-x-1/2 rounded-full bg-zinc-900 px-4 py-2 text-[13px] font-medium text-white shadow-lg">
            {toast}
          </div>
        )}
      </main>
    </div>
  );
}
