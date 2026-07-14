import { useEffect, useState, type ReactNode } from "react";

import { Devices } from "@/components/Devices";
import { Members } from "@/components/Members";
import { Badge, Button, Card } from "@/components/ui";
import { ApiError, LOGIN_URL, api, type Me } from "@/lib/api";

type Tab = "members" | "devices";
type Auth = { state: "loading" } | { state: "in"; me: Me } | { state: "out" };

export default function App() {
  const [auth, setAuth] = useState<Auth>({ state: "loading" });
  const [tab, setTab] = useState<Tab>("members");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .me()
      .then((me) => setAuth({ state: "in", me }))
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) setAuth({ state: "out" });
        else setError(String(e));
      });
  }, []);

  if (auth.state === "loading") {
    return <Centered>Loading…</Centered>;
  }

  if (auth.state === "out") {
    return (
      <Centered>
        <Card className="max-w-sm p-6 text-center">
          <h1 className="text-lg font-semibold">Clave Console</h1>
          <p className="mt-2 text-sm text-clave-muted">You are not signed in.</p>
          {LOGIN_URL ? (
            <a href={LOGIN_URL}>
              <Button className="mt-4">Sign in with SSO</Button>
            </a>
          ) : (
            <p className="mt-4 text-xs text-clave-muted">
              Set <code>VITE_CONSOLE_LOGIN_URL</code> to your workspace SSO entry point.
            </p>
          )}
        </Card>
      </Centered>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-4 py-6">
      <header className="mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold">Clave Console</h1>
          <Badge className="bg-clave-border text-clave-muted">workspace {auth.me.workspace}</Badge>
          <Badge className="bg-clave-accent/15 text-clave-accent">{auth.me.role}</Badge>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            void api.logout().finally(() => setAuth({ state: "out" }));
          }}
        >
          Sign out
        </Button>
      </header>

      <nav className="mb-4 flex gap-1">
        {(["members", "devices"] as Tab[]).map((t) => (
          <Button
            key={t}
            variant={tab === t ? "default" : "outline"}
            size="sm"
            onClick={() => setTab(t)}
            className="capitalize"
          >
            {t}
          </Button>
        ))}
      </nav>

      {error && (
        <div className="mb-4 flex items-center justify-between rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          <span>{error}</span>
          <button className="text-red-300/70 hover:text-red-200" onClick={() => setError(null)}>
            ✕
          </button>
        </div>
      )}

      {tab === "members" ? <Members onError={setError} /> : <Devices onError={setError} />}
    </div>
  );
}

function Centered({ children }: { children: ReactNode }) {
  return <div className="flex h-full items-center justify-center text-clave-muted">{children}</div>;
}
