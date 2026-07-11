# Clave launcher — desktop app (Tauri)

The user-facing **Clave launcher** (doc 00 §5.2): it lists the work apps you can launch, resolves
each one's **contained launch spec** (executable + env pointing into the encrypted Clave Disk), and
shows the platform's enforcement posture. **Tauri** (Rust backend) + **React + Vite + Tailwind +
shadcn/ui** frontend.

## Status

- **Two views.** The primary window is a **full two-pane launcher**:
  a left nav rail — **Launch / Apps / Websites**, plus **Connectivity / Compliance / Settings** at
  the bottom — and a main **app grid** of brand-tiled work apps (light theme). A **compact** dark
  quick-launch panel (`src/components/compact-view.tsx`) is preserved for a minimized / menubar mode.
- **Browser preview.** `npm run dev`, then open `/preview.html`: it renders the real UI against a
  stubbed Tauri bridge (demo data, no Rust backend) — fast visual iteration without a full build.
- **Builds clean** (verified): the frontend (`tsc` + Vite) and the Rust backend (`cargo build`,
  Tauri v2) both compile; only *launching the window* needs a display. `src-tauri/icons/` holds
  **placeholder** icons (solid Clave blue) — replace with a real logo via `npm run tauri icon
  logo.png`. App tiles use brand-colored glyphs; drop in real app icons later.
- Built with the **Node + Tauri toolchain**, so it lives outside the Cargo workspace
  (`exclude`d in the root `Cargo.toml`) and is **not** compiled by `cargo test`. The backend reuses
  the workspace crates (`clave-core`, the OS adapter) via path dependencies.
- **Scaffold:** the backend commands use an embedded **demo policy** and a fixed mount point, and the
  actual **spawn + inject** — true containment, doc 00 §5.2 / doc 03 §2 — is the OS layer and is
  deferred. So "Launch" currently *resolves and shows* the spec (exactly what
  `clave-cli launch` prints) rather than spawning a contained process.
- In production these commands talk to the privileged `clave-daemon` over the authenticated IPC
  channel (doc 10 §3) instead of the demo policy, and reach the daemon's `launchable_apps` /
  `prepare_launch`.

## Develop

Requires Node 18+ and the Rust toolchain.

```sh
cd apps/clave-launcher
npm install
npm run tauri dev          # or: npx @tauri-apps/cli dev
```

Icons (for bundling): `npm run tauri icon path/to/logo.png` generates `src-tauri/icons/` to match
the `bundle.icon` paths in `src-tauri/tauri.conf.json`.

## Layout

- `src-tauri/` — Rust backend. Tauri commands (`list_apps`, `launch_spec`, `enforcement`) over
  `clave-core`'s launcher API (`AppRule::launch_spec`, the same logic behind `Daemon::launchable_apps`
  / `prepare_launch`).
- `src/` — React UI. `src/components/ui/` holds the shadcn components; `src/App.tsx` is the launcher.
