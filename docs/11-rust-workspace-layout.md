# 11 — Rust Workspace Layout, FFI & Build

How to physically organize the code so the portable core stays portable, the OS glue stays
contained, and the kernel/extension pieces (which can't be pure Rust) are cleanly isolated.

---

## 1. Cargo workspace

```
clave/
├── Cargo.toml                  # [workspace]
├── crates/
│   ├── clave-core/              # PORTABLE. policy, zone model, crypto, DLP, audit. no OS calls.
│   │   └── #![forbid(unsafe_code)]   (except the few vetted crypto spots, feature-gated)
│   ├── clave-ipc/               # PORTABLE. serde/postcard message enums, framing, versioning
│   ├── clave-proto/             # PORTABLE. gateway wire types, signing/verify
│   │
│   ├── clave-platform/          # trait definitions (doc 00 §4) — the seam
│   │
│   ├── clave-win/               # WINDOWS user-mode: impl traits via `windows` crate
│   │   ├── supervisor.rs        #   talks to driver over IOCTL
│   │   ├── volume.rs            #   WinFsp callbacks
│   │   ├── clipboard.rs         #   broker
│   │   ├── net.rs               #   WFP control / WinDivert proto + wintun + boringtun
│   │   ├── screen.rs            #   affinity orchestration
│   │   └── overlay.rs           #   layered window + SetWinEventHook
│   ├── clave-shim-win/          # WINDOWS cdylib injected into work apps (hooks)
│   │
│   ├── clave-mac/               # MACOS user-mode: impl traits via objc2/security-framework
│   │   ├── supervisor.rs        #   FFI to the ES Swift host
│   │   ├── volume.rs            #   hdiutil/DiskImages + Keychain/SE
│   │   ├── net.rs               #   FFI to the NE provider
│   │   └── overlay.rs           #   NSWindow + AX
│   │
│   ├── clave-daemon/            # the privileged service binary (tokio). links clave-{win|mac}
│   └── clave-cli/               # admin/diagnostics
│
├── native/
│   ├── win-driver/             # C/WDK OR windows-drivers-rs: process-notify, minifilter,
│   │                           #   registry callback, WFP callout, (opt) kbd filter
│   ├── mac-es-extension/       # Swift System Extension host (ES client) + links libclave_core.a
│   └── mac-ne-extension/       # Swift Network Extension provider + links libclave_core.a
│
├── xtask/                      # build orchestration (cargo xtask build --release --os windows)
└── docs/                       # this documentation set (this folder)
```

Principles:

- **`clave-core` compiles on your dev laptop** (any OS) with no driver, no extension, no admin.
  ~70% of logic is unit-testable here.
- **All `unsafe` lives in `clave-win` / `clave-mac` / `clave-shim-win`.** The core is
  `#![forbid(unsafe_code)]`. This concentrates the audit surface.
- **`clave-platform`** holds only trait definitions + portable value types, so `clave-core`
  never depends on an OS crate.

---

## 2. The crate dependency graph

```
            clave-core ──depends on──► clave-platform (traits) ◄── clave-win impls
               ▲   ▲                                          ◄── clave-mac impls
               │   └──────────────── clave-ipc, clave-proto
   clave-daemon ┘ links the right impl crate per target via cfg:
       #[cfg(windows)] use clave_win as plat;
       #[cfg(target_os="macos")] use clave_mac as plat;
```

`clave-core` has **zero** knowledge of which platform it runs on — it receives a
`dyn Platform`. Swapping in a `MockPlatform` gives you full integration tests with no OS.

---

## 3. FFI bridges (the unavoidable non-Rust seams)

| Seam | Tool | Notes |
|------|------|-------|
| Rust ↔ Win32/WFP/WinFsp | **`windows` / `windows-sys`** (official MS) | Covers essentially all user-mode Windows. No bridge needed. |
| Rust ↔ Windows kernel driver | **`windows-drivers-rs`** (KMDF) *or* C/WDK + a C ABI | Minifilter support in the Rust framework is still thin; many ship the driver in C and keep brains in the daemon. |
| Rust ↔ macOS Obj-C frameworks | **`objc2`**, `core-foundation`, `security-framework`, `system-configuration` | Idiomatic-ish; good for AppKit/Keychain/SC. |
| Rust ↔ Endpoint Security | **Swift host → C ABI → Rust staticlib** | ES is entitlement-gated and C; write a thin Swift/ObjC host, link `libclave_core.a`, call `extern "C"` Rust. No direct Rust ESF bindings. |
| Rust ↔ Network Extension | **Swift provider → C ABI → Rust staticlib** | Same pattern; the NE provider is a Swift app extension. |
| Rust ↔ Swift (rich types) | **`swift-bridge`** or hand-written `extern "C"` | For the ES/NE bridges keep the C ABI tiny (pass tokens as byte arrays, decisions as ints). |
| Rust ↔ C headers | **`bindgen`** | For WinFsp/WDK headers if not covered by a crate. |

### 3.1 The Rust ↔ Swift ABI for ES/NE (keep it boring)

```rust
// clave-core exposes a tiny C surface for the Swift extensions:
#[no_mangle] pub extern "C" fn clave_core_on_exec(path: *const c_char, tok: *const u8, ppid: u32)
    -> ExecDecision { /* … */ }
#[no_mangle] pub extern "C" fn clave_core_zone_contains(tok: *const u8) -> bool { /* … */ }
#[no_mangle] pub extern "C" fn clave_core_handle_work_flow(/* opaque flow ptr */) { /* … */ }

#[repr(C)] pub struct ExecDecision { pub allow: bool, pub joins_zone: bool }
```

Rules: pass POD across the boundary (byte arrays for audit tokens, ints for verdicts), never
Rust `String`/`Vec` ownership; do all allocation-heavy work on the Rust side behind the call.

---

## 4. Building the non-Rust pieces

`xtask` (a Rust binary in the workspace) orchestrates the multi-toolchain build so CI has one
entrypoint:

```
cargo xtask build --os windows --release
   ├─ cargo build -p clave-daemon -p clave-win -p clave-shim-win --target x86_64-pc-windows-msvc
   ├─ msbuild native/win-driver  (WDK)  → clave.sys   (+ inf)
   ├─ sign:  signtool /sign ... clave.sys clave-daemon.exe clave-shim-win.dll   (doc 12)
   └─ package: WiX/MSIX installer

cargo xtask build --os macos --release
   ├─ cargo build -p clave-daemon -p clave-mac --target {aarch64,x86_64}-apple-darwin (universal)
   ├─ staticlib: cargo build -p clave-core --crate-type staticlib → libclave_core.a
   ├─ xcodebuild native/mac-es-extension native/mac-ne-extension (links libclave_core.a)
   ├─ codesign --options runtime  (hardened runtime, entitlements)  (doc 12)
   ├─ notarytool submit + staple
   └─ pkgbuild/productbuild → .pkg (+ MDM config profile)
```

- **`clave-core` as `staticlib`** for macOS extensions; as `rlib` for the daemon. A
  feature/`crate-type` matrix in `Cargo.toml`.
- **Driver build** is MSBuild/WDK even if you later move pieces to `windows-drivers-rs`
  (the framework still builds through the WDK toolchain).

---

## 5. `no_std` and the kernel piece

If/when you write driver code in Rust (`windows-drivers-rs`), it is **`#![no_std]`** with a
custom allocator over the WDK pool APIs. Keep that crate **minimal** — just the
process-notify/minifilter/WFP callout shells that call a tiny, `no_std`-compatible slice of
shared logic (e.g. the `SetContains` membership check). Do **not** try to run the full
`clave-core` in the kernel; ship policy decisions to the daemon and cache only the hot
membership/redirect tables in the driver.

```
kernel (no_std, tiny):  membership set + redirect table + "ask user mode" upcall
user mode (std, big):   clave-core policy brain
```

---

## 6. Testing strategy by layer

| Layer | How to test | Runs where |
|-------|-------------|------------|
| `clave-core` decisions | unit + **property tests** (proptest) + golden replays | dev laptop, CI, any OS |
| `clave-ipc` parsers | **`cargo fuzz`** on every message enum (untrusted shim input) | CI |
| Platform traits | `MockPlatform` impl → integration test the daemon end-to-end | dev laptop |
| Windows driver/minifilter | WDK + Driver Verifier + **HLK** tests in a VM | Windows VM/CI |
| macOS ES/NE | sign with dev entitlements, run on a real Mac (extensions need real hardware/entitlements) | Mac CI runner |
| Full system | the per-subsystem test plans (docs 02–09) on a clean VM/device matrix | device lab |

> The split pays off here: the security-critical decision logic is tested *without* the
> painful signed-driver/entitlement loop, and the OS glue is thin enough to test in VMs.

---

## 7. Key crates checklist

- Core: `serde`, `postcard`, `zeroize`, `arc-swap`, `dashmap`, `proptest`, `thiserror`.
- Crypto: `aes`, `xts-mode`, `aes-gcm`/`chacha20poly1305`, `ed25519-dalek` (bundle signing),
  `ring`/`rustls` (gateway mTLS), `boringtun` (WireGuard).
- Windows: `windows`, `windows-sys`, `retour` or `minhook-sys`, `winfsp` (or `dokan`),
  `wintun`, `windivert`, `windows-drivers-rs` (driver), `wdk-sys`.
- macOS: `objc2`, `core-foundation`, `core-graphics`, `security-framework`,
  `system-configuration`, `libproc`; Swift side: `EndpointSecurity`, `NetworkExtension`.
- Build: `xtask` pattern, `cargo-bundle`/`cargo-wix`/WiX, `bindgen`, `swift-bridge`.

Proceed to [12 — Signing, Distribution & Deployment](12-signing-distribution-deployment.md).
