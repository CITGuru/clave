# clave-console

The Clave admin console — a Vite + React + TypeScript SPA over the gateway's control-plane API
(doc 15 §2). It drives the `/admin/*` surface: members (invite, change role, suspend/restore) and
devices (list, lock, wipe), guarded by the sealed-cookie session from `/auth/me`.

```sh
npm install
npm run dev      # proxies /auth, /admin, /enroll to VITE_GATEWAY_URL (default 127.0.0.1:8080)
npm run build    # tsc typecheck + production bundle
```

Configuration (Vite env):

| Var | Purpose |
|-----|---------|
| `VITE_GATEWAY_URL` | Gateway base URL for the dev proxy / API calls (default same-origin in prod) |
| `VITE_CONSOLE_LOGIN_URL` | Workspace SSO entry point shown on the signed-out screen |

Requests carry `credentials: "include"`, so the console and gateway must share a site (or the
gateway must send permissive CORS + `Set-Cookie` for the console origin).
