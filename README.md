# Clave

**Clave** is a local secure enclave for BYOD ("bring-your-own-PC") work. Clave lets a company run its work applications as ordinary **native processes on an employee's unmanaged personal computer**, while sealing them inside a company-controlled boundary — an encrypted, redirected filesystem plus an emulated registry/namespace, and a kernel/user-mode interception layer that enforces a **work zone** across clipboard, input, screen capture, files, and network.

It does this **without machine virtualization** — no VDI, no hypervisor, no streamed desktop, no backend compute — so apps stay fast and native. Work data lives encrypted at rest on the **Clave Disk** and can be remotely locked or crypto-shredded; the employee's personal apps and data are never touched.

Architecture and subsystem design live in [`docs/`](docs/README.md).

## Status

- **Phase 1 (portable core) — complete.** Policy brain, IPC contracts, and the daemon skeleton, all tested on any machine with no driver/entitlements/signing.
- **Phase 2 (network split-tunnel) — in progress.** Shared routing + the **boringtun
  WireGuard data plane** (done, behind the `wireguard` feature: in-memory handshake +
  encrypted round-trip tested). Remaining: the real OS enforcement (Swift Network Extension;
  Windows WFP), which needs entitlements / a Windows host — see per-crate READMEs and
  [doc 12](docs/12-signing-distribution-deployment.md).
- **Phase 3 (encrypted Clave Disk) — crypto core complete.** The portable encrypting layer in
  `clave-volume`: the **AES-256-XTS** block cipher, the **KEK→DEK** key hierarchy with AES-KW
  wrapping, the hardware-key-store and backing-container seams, and **crypto-shred remote wipe** —
  all fail-closed and tested here. The daemon **owns this volume as a subsystem** (like it owns
  `SplitRouter`): unlock/lock, gated read/write, and remote-wipe drive the real crypto core via
  daemon events, end-to-end against the mock platform. Remaining: the OS mount (WinFsp on Windows;
  encrypted APFS/sparsebundle on macOS), the TPM / Secure Enclave behind the key store, and the
  Windows minifilter — see [doc 04](docs/04-encrypted-volume.md) and [doc 13](docs/13-build-roadmap.md).
- **Gateway control plane (`clave-proto`) — complete.** Remote **wipe**, remote **lock**, and
  **policy updates** are authenticated: a detached **Ed25519** signature over a canonical envelope,
  verified against the **pinned** tenant key, with **monotonic-counter anti-replay** and a
  freshness window (doc 04 §6, doc 10 §2). The daemon's `apply_gateway_command` is the only path
  that can change device posture; forged or replayed commands change nothing. Outbound, the
  device-signed, **hash-chained audit spool** drains tamper-evidently to the gateway, which
  detects any suppression or rewrite (doc 10 §6).

The split-tunnel data plane is wired into the daemon's flow path (`SplitRouter`); an authenticated
Unix-socket IPC transport carries the shim↔daemon contracts; the encrypted Clave Disk's crypto
core (`clave-volume`) is driven by the daemon — encrypting at rest, gating non-supervised callers,
and crypto-shredding on wipe; remote wipe/lock/policy commands are Ed25519-verified and
replay-protected, with a device-signed, hash-chained audit spool; and a portable `GatewaySync`
loop drives the pull→apply→drain→ship exchange over a `GatewayLink` seam, with a real
**mutual-TLS** link (`clave-proto`'s `mtls` feature: a rustls connector/acceptor — each side presents
a cert and verifies the peer against pinned roots — producing the `TlsStream` the framed `transport`
pump runs over). Every OS capability reports an `EnforcementStatus` — `Enforced` vs a
`DevelopmentOnly` stand-in vs `Unavailable` — so a production build can't silently ship a dev-only
fallback (doc 14 §5.3). The macOS adapter (`clave-mac`) is now a real `MacPlatform` reporting that
honest posture — the ES-fed supervisor and shared split-tunnel classifier are wired (`DevelopmentOnly`
until entitled), the rest `Unavailable` — plus the ES `AUTH_OPEN` volume gate over the C ABI; the
Windows adapter (`clave-win`) is the same `WindowsPlatform` shape, and the daemon binary links the
right one per target. Exec authorization is now a real decision: `classify_exec` matches a binary's
**code-signature** against the signed app allow-list (doc 02 §3.2), so only vetted apps (or children
of supervised processes) join the work zone, and each rule carries a `LaunchProfile` that resolves
the app's HOME/temp **inside** the encrypted Clave Disk (doc 03 §6, doc 04 §5). `classify_path`
rounds out the portable classifier trio (flow / exec / path): it tells the FS-redirection hook and
the minifilter/ES gate whether a path is work-data, system-COW, or pass-through (doc 03 §3.3); a
**learn mode** synthesizes candidate profiles from an app's observed footprint (doc 03 §6); the
**`clave-cli`** diagnostics binary surfaces the enforcement posture and dry-runs the classifiers;
and the gateway sync loop has a **live framed transport** (`clave-proto`'s `transport` feature) that
mTLS wraps in production. **`proptest`** property tests pin the security-critical invariants (the
`decide`/classifier logic, XTS + AES-KW round-trips, the audit chain, panic-free verification of
untrusted bytes) across all inputs (doc 11 §6), and a fault-injection test confirms the volume is
fail-closed under a mid-write "pull-the-plug" (doc 04 §7). The **Clave launcher** core is here too:
`Daemon::launchable_apps` lists the allow-listed work apps and `prepare_launch` resolves each one's
contained spawn spec — executable + env pointing into the encrypted disk (doc 00 §5.2). The
**Tauri desktop app** (`apps/clave-launcher/`, Rust + React/Tailwind/shadcn) now reaches these over
the authenticated `clave-ipc` link (`LauncherClient` ↔ the daemon's `handle_launcher_request`, doc
10 §3), falling back to a demo policy when no daemon is running; the OS spawn+inject is the remaining
layer. `clave-cli apps`/`launch` drive the same core from the terminal. The control-plane
**gateway** (`clave-identity` + `clave-gateway`, doc 15) rounds out enrollment: console login,
device-enrollment handshake, **device registration**, and the two doc 15 §9 step 5 enrollment
artifacts a device receives on approval (the shared wire contract is `clave-proto`'s
`EnrollmentGrant`): its **tenant-signed initial policy bundle** (`PolicyIssuer` → a `SignedCommand`
its pinned-key `GatewayVerifier` accepts) and its **wrapped volume key** (`VolumeKeyService` → the
Clave Disk DEK delivered to the device, either AES-KW-wrapped to a symmetric KEK for the dev
bootstrap or, in production, **sealed to the device's X25519 hardware public key** via an
ECIES sealed-box (`clave-volume`'s `seal_dek`, so the gateway holds nothing that can open it), doc 04
§2). The device side closes the loop: **`clave-daemon`'s enrollment client** (`DeviceEnrollment::accept`)
pins the tenant key, verifies the policy through it, and opens the volume key with its hardware key —
producing exactly the material `Daemon::new` is built from. All over an Axum edge with sealed-cookie
sessions — portable over in-memory seams, with real **Postgres** + **WorkOS** adapters
(`--features server`) exercised against a live database. **255 tests** pass; `cargo clippy
--all-targets` is clean.

## Crate map

| Crate | Phase | Role | Builds/tests here? |
|-------|:-----:|------|:------------------:|
| `clave-platform` | 1 | The seam: portable value types + the 7 OS-capability traits + the **`EnforcementStatus`** posture model (doc 14 §5.3) | ✅ |
| `clave-core` | 1 | Policy brain: zone registry, `decide()`, DLP matrices, `classify_flow` / **`classify_exec`** (allow-list + `LaunchProfile`) / **`classify_path`**, **learn mode**, audit | ✅ |
| `clave-ipc` | 1 | Message contracts + postcard framing + **authenticated UDS transport** (server/handshake/peer-auth); the daemon↔shim link **and** the daemon↔launcher-UI link (`LauncherClient`/`serve_launcher`) | ✅ |
| `clave-proto` | 1 | **Signed gateway control plane**: Ed25519 `SignedCommand` (policy/lock/wipe) with pinned-key verify + anti-replay + freshness; tamper-evident device-signed **audit spool**; the **`EnrollmentGrant`** wire contract (doc 15 §9 step 5); `GatewayLink` seam + framed `transport` + real **mutual-TLS** link (features) | ✅ |
| `clave-identity` | — | Control-plane **identity brain** (doc 15): pure, fail-closed `authorize_login`/`authorize_enrollment`/`accept_invitation` (no I/O) | ✅ |
| `clave-gateway` | — | Control-plane **gateway** (doc 15): console login, device enrollment + **registration** + **signed initial-policy** (`PolicyIssuer`) + **wrapped-volume-key** (`VolumeKeyService`) issuance, sealed-cookie sessions over Axum; in-memory seams + real **Postgres**/**WorkOS** adapters (features) | ✅ |
| `clave-cli` | 1 | Admin/diagnostics: enforcement posture, `classify_exec`/`classify_path` dry-runs, launcher `apps`/`launch` | ✅ |
| `clave-testkit` | 1 | In-memory `MockPlatform` + recording audit sink | ✅ |
| `clave-daemon` | 1 | Hosts the core; tokio loop; **flow data plane** (`SplitRouter`) + **IPC bridge** (`handle_shim_msg`) + launcher bridge; **device-side enrollment client** (`DeviceEnrollment::accept` — pin tenant key, verify policy, open volume key) | ✅ |
| `clave-net` | 2 | **`SplitRouter`** flow routing + `Tunnel` seam + loopback; **boringtun WireGuard** data plane (feature `wireguard`) | ✅ |
| `clave-volume` | 3 | **Encrypted Clave Disk crypto core**: AES-256-XTS block layer, KEK/DEK hierarchy + AES-KW, `KeyStore`/`BackingStore` seams, crypto-shred wipe, **X25519 enrollment sealed-box** (`seal_dek`/`open_dek`) | ✅ |
| `clave-mac` | 2 | macOS adapter: **`MacPlatform`** (honest `EnforcementStatus`) + ES/NE C ABI incl. `AUTH_OPEN` volume gate (+ Swift ES/NE scaffolds in `swift/`) | ✅ Rust core |
| `clave-win` | 2 | Windows adapter: **`WindowsPlatform`** (honest `EnforcementStatus`) + shared `route()` (+ `cfg(windows)` WFP/minifilter scaffold) | ✅ Rust core |

`clave-core` is `#![forbid(unsafe_code)]` and depends only on `clave-platform` traits — the
security-critical logic runs and tests with no OS; the `clave-volume` and `clave-proto` crypto
cores are `#![forbid(unsafe_code)]` too (pure-Rust AES/XTS/AES-KW and Ed25519). `unsafe` is
confined to the OS adapters (`clave-mac` FFI).

## Build & test

```sh
cargo test                       # 255 tests, all crates
cargo clippy --all-targets       # clean
cargo run -p clave-daemon        # on macOS: selects clave-mac, prints its enforcement posture
cargo build -p clave-mac --release   # also emits libclave_mac.a for the Swift extensions
cargo test -p clave-net --features wireguard   # real WireGuard handshake + encrypted round-trip
cargo test -p clave-proto --features transport # framed gateway transport over a stream
cargo test -p clave-proto --features mtls       # real mutual-TLS handshake + signed-command round-trip
cargo test -p clave-gateway                    # control plane over in-memory seams (login/enroll/sessions)
cargo run  -p clave-cli -- enforcement         # this OS adapter's honest enforcement posture
cargo run  -p clave-cli -- apps policy.json    # launcher catalog from a policy bundle
cd apps/clave-launcher && npm install && npm run tauri dev   # the desktop launcher (Tauri; needs Node)
cargo test -p clave-volume       # encrypted-disk crypto core: XTS, key wrap, crypto-shred wipe
cargo test -p clave-proto        # signed gateway commands + tamper-evident audit spool

# Gateway against a live Postgres (the only place the PgStore SQL actually runs):
docker compose -f crates/clave-gateway/docker-compose.yml up -d db
CLAVE_TEST_DATABASE_URL=postgres://clave:clave@localhost:5432/clave \
  cargo test -p clave-gateway --features postgres --test postgres_store
```

## What needs more than this Mac

The WireGuard data plane is **done** (boringtun, behind the `wireguard` feature). What
remains needs platform-specific approvals/hosts:

| Next step | Needs |
|-----------|-------|
| macOS enforcement (`clave-mac/swift/`) | ES + Network Extension entitlements (Apple approval), notarization — [doc 12 §2](docs/12-signing-distribution-deployment.md) |
| Windows enforcement (`clave-win` `cfg(windows)`) | a Windows checkout; later EV-cert + driver signing — [doc 12 §1](docs/12-signing-distribution-deployment.md) |
| Clave Disk mount + hardware key (`clave-{win,mac}` `volume.rs`) | WinFsp / encrypted-APFS mount over the `clave-volume` core + TPM / Secure Enclave key store; Windows minifilter (attestation-signed) — [doc 04](docs/04-encrypted-volume.md), [doc 12](docs/12-signing-distribution-deployment.md) |

See the [build roadmap](docs/13-build-roadmap.md) for full sequencing.
