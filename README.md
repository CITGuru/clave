# Clave

Clave is a local secure enclave for BYOD ("bring-your-own-PC") work. It lets a company run its work apps as ordinary **native processes on an employee's unmanaged personal computer**, while sealing them inside a company-controlled boundary: an encrypted, redirected filesystem plus an emulated registry/namespace, and a kernel/user-mode interception layer that enforces a **work zone** across clipboard, input, screen capture, files, and network.

It does this **without machine virtualization** — no VDI, no hypervisor, no streamed desktop, no backend compute — so apps stay fast and native. Work data lives encrypted at rest on the **Clave Disk** and can be remotely locked or crypto-shredded; the employee's personal apps and data are never touched.

![Clave architecture](assets/clave-desktop.png)

## How it works

```
        ONE NATIVE OS (Windows / macOS) — no hypervisor, no guest OS
 ┌──────────────────────────────┬───────────────────────────────────┐
 │       PERSONAL ZONE          │   SECURE ENCLAVE ("Work Zone")    │
 │  (unsupervised resources)    │   Clave Edge around each window   │
 │  - personal apps             │   - work apps run NATIVELY        │
 │  - user's ISP connection     │   - Clave Disk (encrypted volume) │
 │  - private, invisible to IT  │   - emulated registry/namespace   │
 └──────────────┬───────────────┴────────────────┬──────────────────┘
                │                                │
        ┌───────┴────────────────────────────────┴─────────┐
        │   Daemon (Rust core) + driver / system extension │
        │   intercepts: clipboard · input · screen capture │
        │   · file I/O · network routing · window geometry │
        └──────────────────────────────────────────────────┘
```

- **Work apps run natively**, wrapped in application-subsystem virtualization (emulated registry/namespace + an encrypted, redirected filesystem) instead of a VM.
- **A zone boundary** is enforced across clipboard, input, screen capture, files, and network by a privileged **daemon** plus a per-app **shim**.
- **Work data is encrypted at rest** on the Clave Disk (AES-256-XTS), unlocked by a hardware-rooted key, and can be remotely **locked** or **crypto-shredded**.
- **A company gateway** provisions signed policy and keys and provides static-IP network egress; commands are Ed25519-signed and replay-protected.

The security-critical logic lives in one portable core that runs and is fully tested on any machine, with no drivers, entitlements, or code signing needed. Everything OS-specific is kept in thin per-platform adapters.

## Crate map


| Crate            | Role                                                                                                                   |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `clave-platform` | The seam: portable value types + the OS-capability traits + the `EnforcementStatus` posture model                      |
| `clave-core`     | Policy brain: zone registry, `decide()`, DLP matrices, flow/exec/path classifiers, learn mode, audit                   |
| `clave-ipc`      | Message contracts + postcard framing + authenticated UDS transport (daemon↔shim and daemon↔launcher-UI)                |
| `clave-proto`    | Signed gateway control plane: Ed25519 `SignedCommand`, tamper-evident audit spool, enrollment wire contract, mTLS link |
| `clave-identity` | Control-plane identity brain: pure, fail-closed login/enrollment authorization (no I/O)                                |
| `clave-gateway`  | Control-plane gateway: console login, device enrollment/registration, signed policy + wrapped-key issuance (Axum)      |
| `clave-cli`      | Admin/diagnostics: enforcement posture, classifier dry-runs, launcher `apps`/`launch`                                  |
| `clave-testkit`  | In-memory `MockPlatform` + recording audit sink                                                                        |
| `clave-daemon`   | Hosts the core; tokio loop; flow data plane + IPC bridge + launcher bridge + device-side enrollment client             |
| `clave-daemon-host` | macOS-only `#[no_mangle]` FFI shim: the signed `ClaveDaemonHost` app's entry into `clave-daemon` (kept out of `clave-daemon`, which forbids unsafe code) |
| `clave-net`      | `SplitRouter` flow routing + `Tunnel` seam + boringtun WireGuard data plane (feature `wireguard`)                      |
| `clave-volume`   | Encrypted Clave Disk crypto core: AES-256-XTS, KEK/DEK hierarchy, crypto-shred wipe, X25519 enrollment sealed-box      |
| `clave-mac`      | macOS adapter: `MacPlatform` + ES C ABI + `hdiutil` Clave Disk mount + Secure-Enclave key sealing (+ the Xcode hosts)  |
| `clave-win`      | Windows adapter: `WindowsPlatform` + shared routing (+ WFP/minifilter scaffold)                                        |

## Requirements

- **Rust** (stable) with Cargo.
- **Node** (for the Tauri desktop launcher only).
- **Docker** (for the live-Postgres gateway tests only).

## Build & run

```sh
cargo test                       # run the full test suite across all crates
cargo clippy --all-targets       # lint

cargo run -p clave-daemon        # start the daemon (on macOS: selects clave-mac, prints its enforcement posture)
cargo run -p clave-cli -- enforcement        # this OS adapter's honest enforcement posture
cargo run -p clave-cli -- apps policy.json   # launcher catalog from a policy bundle

# Desktop launcher (Tauri; needs Node):
cd apps/clave-launcher && npm install && npm run tauri dev
```

On macOS the daemon runs under one of two profiles, each with its own Clave Disk. `cargo run` is the unsigned **dev** profile (plain-Keychain disk). The **signed host** — the only build that can reach the Secure Enclave — is an Xcode target:

```sh
cd crates/clave-mac/macos
xcodebuild -project ClaveES.xcodeproj -scheme ClaveDaemonHost \
  -configuration Release -derivedDataPath build -allowProvisioningUpdates build
open build/Build/Products/Release/ClaveDaemonHost.app
```

### Feature-gated pieces

```sh
cargo build -p clave-mac --release              # also emits libclave_mac.a for the Swift extensions
cargo test  -p clave-net    --features wireguard  # real WireGuard handshake + encrypted round-trip
cargo test  -p clave-proto  --features transport  # framed gateway transport over a stream
cargo test  -p clave-proto  --features mtls       # real mutual-TLS handshake + signed-command round-trip
cargo test  -p clave-gateway                      # control plane over in-memory seams (login/enroll/sessions)

# Gateway against a live Postgres (the only place the PgStore SQL actually runs):
docker compose -f crates/clave-gateway/docker-compose.yml up -d db
CLAVE_TEST_DATABASE_URL=postgres://clave:clave@localhost:5432/clave \
  cargo test -p clave-gateway --features postgres --test postgres_store
```

## Documentation

- **[Architecture & subsystem design](docs/README.md)** — the full engineering docs.
- **[Implementation status](STATUS.md)** — what's built, what's wired, and what still needs platform approvals or hosts.

