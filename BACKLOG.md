# Clave — Non-OS-Gated Backlog

Work that is **buildable and testable on any dev machine today** — no Windows host, no paid
Apple Developer / Endpoint Security / Network Extension entitlement, no kernel-driver signing.
For what is already built see [STATUS.md](STATUS.md); for the phased plan and the OS-gated /
signing-blocked work see [docs/13](docs/13-build-roadmap.md).

**Legend.** Size: **S** ≈ hours, **M** ≈ a few days, **L** ≈ a week+.
Status: `[ ]` not started · `[~]` in progress · `[x]` done.

---

## Central finding

The whole system runs on a **hardcoded demo policy + fixed key material**. Both daemon
binaries (`clave-daemon/src/{mac_main,win_main}.rs`) and the launcher backend
(`apps/clave-launcher/src-tauri/src/lib.rs`) build a `demo_policy()` (14 fixed apps,
`team_id: "DEMO000000"`, `Kek::from_bytes([0x4B;32])`, `LoopbackTunnel`, self-signed gateway).
The **real** enrollment → policy → sync → audit machinery is fully implemented and unit-tested
but **never called from a running binary**. Wiring that loop (§A) is the highest-leverage
non-OS-gated work — it turns a pile of tested components into a system that actually enrolls,
receives a real signed policy, and reports audit back.

---

## A. Close the real end-to-end loop — *pieces exist, just unwired*

- [x] **NG-1 — Wire enrollment + `GatewaySync` into the running daemon.** **L**
  Persist enrollment artifacts (signed policy bundle, wrapped/sealed volume key, pinned tenant
  key), load them on boot, replace `demo_policy()` + fixed keys, and spawn the periodic
  pull→apply→drain→ship task. `DeviceEnrollment::accept` and `GatewaySync::sync_once` are done and
  tested; only the TPM/SE unseal is OS-gated (a `Dev` path already exists).
  *Files:* `clave-daemon/src/{enroll.rs,lib.rs,mac_main.rs,win_main.rs}`.

- [x] **NG-2 — Device-side enrollment client (device-code flow).** **S/M** · *needs a store from NG-1*
  Call `/enroll/start` → open the system browser → poll `/enroll/poll`/`/enroll/complete`. Only the
  cryptographic acceptance of the `EnrollmentGrant` exists today; the HTTP orchestration does not.
  *Files:* `clave-daemon/src/enroll.rs`. Doc 15 §5 (Flow B), §9 step 5.

- [x] **NG-3 — Real networked `GatewayLink` over mTLS.** **M**
  Only `LoopbackLink` and in-memory `ChannelGatewayLink` exist; `clave-proto/src/mtls.rs` has the
  `client_config`/`server_config` building blocks but no networked transport rides them. This is the
  plumbing under NG-1 policy distribution and NG-7 audit drain. Doc 10 §2.
  *Files:* `clave-daemon`, `clave-proto/src/{mtls,transport}.rs`.

---

## B. Control plane / fleet management — *greenfield, all portable server work*

- [x] **NG-4 — Gateway admin API.** **L**
  Create invitations; list/suspend/restore members; change roles; list devices; lock/wipe a device.
  The DB schema (`membership`/`invitation`/`device`) and the pure `can()` authz gate exist; the CRUD
  service + HTTP surface do not (the router exposes only `/auth/*` and `/enroll/*`). Backend for NG-5.
  *Files:* `clave-gateway/src/{gateway,http,store,postgres}.rs`. Doc 15 §3, §7.

- [x] **NG-5 — Admin console web app (`apps/clave-console`).** **L** · *depends on NG-4*
  Does not exist. Login, members (invite/role/suspend), devices (list/lock/wipe), audit view.
  React/Vite/Shadcn/Tailwind per spec. *Files:* new `apps/clave-console`. Doc 15 §2, §9 step 4.

- [x] **NG-6 — Policy authoring + versioning + reissue.** **M/L**
  Today `MemPolicyIssuer::issue_initial_policy` only signs a static `PolicyBundle::restrictive_default()`
  (hard-coded at `server_main.rs:52`). Add an admin path to author/edit policy, version history,
  monotonic-version reissue to already-enrolled devices, and real rollback-protection high-water.
  *Files:* `clave-gateway/src/policy.rs`. Doc 10 §1–2, doc 15 §7.

- [x] **NG-7 — Audit ingest endpoint + persistence + query/report API.** **M** · *rides NG-3*
      *(endpoints + query + suppression alerts done; ledger runs in-memory against the new audit schema — the PgStore-backed ledger read/write is the remaining wiring.)*
  `AuditLedger::ingest` verifies the hash-chain and detects gaps/tamper (tested) but is in-memory,
  wired to no HTTP route, and not persisted to Postgres. Add the drain endpoint, audit tables, a
  query/report API for the console, and a suppression-alert surface. `Gateway::ingest_device_audit`
  exists but nothing calls it over the wire. *Files:* `clave-gateway/src/{audit_ingest,http,postgres}.rs`. Doc 10 §6.

- [x] **NG-8 — SCIM directory sync → membership suspend/restore.** **M**
  The `on_directory_event(ScimEvent) -> MembershipDelta` method (doc 15 §6) was dropped from the real
  `IdentityProvider` trait; `grep scim` is empty. Add `ScimEvent`/`MembershipDelta`, a webhook route,
  and the suspend/restore path. *Files:* `clave-gateway/src/{idp,http,workos}.rs`. Doc 15 §1, §6, §9 step 3.

- [x] **NG-9 — WorkOS session refresh + SSO-verified fidelity.** **S/M**
  `Session` stores `refresh_token` but nothing refreshes it — expiry just returns `SessionInvalid`.
  `map_method` hard-codes SSO `verified: true`, so an `SsoMode::Required` workspace can't tell genuine
  SSO apart. *Files:* `clave-gateway/src/{gateway,http,workos}.rs`. Doc 15 §4.1.

---

## C. Client / launcher / CLI UX — *portable*

- [ ] **NG-10 — Make learn mode reachable.** **M** *(CLI slice is S)*
  `LearnSession`/`synthesize()` → `LearnedProfile` is done + tested but has zero consumers. Add a
  `clave-cli learn <observations.json> <mount>` command, a daemon session that accumulates
  `Observation`s, and merge of the candidate profile back into a `PolicyBundle`. Only the observation
  *source* (ES-notify / Nt-hooks) is OS-gated. *Files:* `clave-core/src/learn.rs`, `clave-cli`. Doc 03 §6.

- [x] **NG-11 — Launcher enrollment/status panel + `LauncherRequest::Status`.** **M**
  The launcher surfaces per-capability enforcement only; Settings/Notifications/Help/Connectivity are
  `<Placeholder>`. Add a `Status` IPC request (daemon already has `policy_version()`,
  `volume_is_unlocked()`, `checkpoint()`) carrying enrolled device/tenant/policy-version/mount/last-sync,
  and a panel to show it. *Files:* `clave-ipc/src/lib.rs`, `clave-daemon/src/lib.rs`, `clave-launcher/src/components/full-view.tsx`.

- [x] **NG-12 — Web-app catalog + contained-browser launch (doc 17 Phase A).** **M**
  The launcher "Websites" tab is a `<Placeholder>`. The portable slice: a `WebPolicy`/`PersonaRule`/
  `WebAppRule` model, list work web apps, and spawn a contained browser via the existing
  `LaunchProfile::chromium()` + `--app=<url>` path. Doc 17 §8 Phase A is explicitly "Blocked on: —".
  (Persona-unlock/ES-gating/tier-2 delegated grants are OS- or NG-4-gated; out of this item.)
  *Files:* `clave-core/src/web.rs` (new), `PolicyBundle` field, `clave-launcher`.

- [x] **NG-13 — Launcher catalog persistence.** **S/M**
  Favorites/hidden/recents are ephemeral React state lost on reload; no add-app flow. Persist
  launcher-local state and, if edits should be authoritative, route them to a real store.
  *Files:* `clave-launcher/src/components/full-view.tsx`, `clave-launcher/src-tauri`.

- [ ] **NG-14 — Audit schema `app_id` + local export + rate-limit/coalesce.** **S/M**
  `AuditEvent` lacks the spec'd `app_id` (which work app triggered the event). No CLI/launcher command
  dumps or exports the local hash-chained spool. No rate-limit/coalesce, so a denied-clipboard loop
  floods the chain. *Files:* `clave-core/src/audit.rs`, `clave-proto/src/audit.rs`, `clave-cli`. Doc 10 §6.

- [ ] **NG-15 — CLI/dev policy authoring + validation subcommand.** **M**
  Every DLP knob serializes but there's no tool to compose/validate a `PolicyBundle` — the CLI only
  consumes a hand-written `policy.json`. (Production authoring belongs in the console, NG-6; this is the
  local/dev slice.) *Files:* `clave-cli`. Doc 05, doc 10 §1.

---

## Suggested sequencing

1. **NG-1** — highest leverage; unlocks honest demos of everything downstream.
2. **NG-3** then **NG-7** — the real transport and audit drain that sit under NG-1.
3. **NG-4 → NG-5** — the fleet-management control plane (biggest greenfield value).
4. Quick wins any time: **NG-10** (CLI `learn`), **NG-14** (audit `app_id`), **NG-13** (catalog persistence).

---

## Explicitly out of scope here (OS-gated — tracked in [STATUS.md](STATUS.md) / [docs/13](docs/13-build-roadmap.md))

Shim injection / `Nt*` hooks; ES `AUTH_OPEN`/`AUTH_EXEC` gating; WFP / Network-Extension enforcement;
`SetWindowDisplayAffinity` cross-process capture exclusion; Windows minifilter; TPM / Secure-Enclave
unseal on a signed binary; WinFsp mount; doc 16 Increments 2–3 (IPsec / explicit-proxy data planes);
doc 17 Phases B/C/E (SE-gated persona unlock, ES-gated profile dir, screen/input isolation).
