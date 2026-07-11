# 00 — Architecture Overview

This document fixes the vocabulary, the component inventory, the privilege/trust model, and
the lifecycle that every later subsystem document assumes.

---

## 1. Design philosophy

Four invariants drive every decision in this system:

1. **Native execution.** Work apps run on the local CPU/GPU as ordinary processes. No
   streamed pixels, no guest OS, no backend compute. This is the entire performance and
   cost argument against VDI/DaaS.
2. **Isolation by interception, not by hypervisor.** Because there is no second OS,
   isolation is achieved by *intercepting operations* at OS chokepoints (syscalls, filter
   drivers, framework callbacks) and by *virtualizing the subsystems an app touches*
   (registry, object namespace, filesystem). See [03](03-app-subsystem-virtualization.md).
3. **The privileged layer is the source of truth.** User-mode hooks are convenient but
   defeatable by a hostile in-zone app. Every security decision must be *answerable* from
   a kernel driver (Windows) or a system extension (macOS) using a kernel-authoritative
   identity (PID for Windows, audit token for macOS). See [01](01-threat-model.md).
4. **Personal stays private.** The company manages only the enclave. Personal files,
   browsing, apps, and input are never read, logged, or shipped. This is a hard product
   constraint *and* a privacy-law constraint (GDPR/works-council in EU deployments).

---

## 2. The two trust levels (read this twice)

A hypervisor gives you **two independent kernels**: compromising the guest does not give
you the host. This system does **not** have that. Work apps and personal apps share **one
kernel**. Therefore:

```
        TRUE VM / VDI                          THIS SYSTEM
   ┌───────────┐ ┌───────────┐           ┌─────────────────────────┐
   │ guest OS  │ │ host OS   │           │     single host OS      │
   │ (work)    │ │ (personal)│           │  work  ▒▒▒  personal     │
   ├───────────┤ ├───────────┤           │   apps ▒▒▒   apps        │
   │ guest     │ │ host      │           ├─────────────────────────┤
   │ kernel    │ │ kernel    │           │      one kernel         │
   ├───────────┴─┴───────────┤           ├─────────────────────────┤
   │      hypervisor         │           │      one hardware       │
   └─────────────────────────┘           └─────────────────────────┘
   isolation = hardware boundary         isolation = software interception
```

**Consequence:** this design is strong against *userland* adversaries — a curious user,
malware running as the user in the personal zone, accidental data leakage, a malicious
*work* app trying to exfiltrate — and is **weaker than a VM against a full kernel-level
compromise of the host**. A kernel rootkit on the host sits at the same trust level as your
own driver. The threat model ([01](01-threat-model.md)) makes this explicit per subsystem.
Set this expectation with security stakeholders early; do not let sales imply VM-grade
isolation.

---

## 3. Component inventory

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  CLOUD                                                                          │
│  ┌───────────────┐   policy + keys (mTLS)   ┌──────────────────────────────┐   │
│  │ Policy/Identity│◄────────────────────────│ Network Gateway (static IP)  │   │
│  │   Service      │                          │ WireGuard endpoint           │   │
│  └───────────────┘                          └──────────────────────────────┘   │
└───────────────▲───────────────────────────────────────────▲────────────────────┘
                │                                              │ encrypted tunnel
════════════════╪══════════════════════════════════════════════╪═══════════ device ══
                │                                              │
┌───────────────┴──────────────────────────────────────────────┴────────────────┐
│  PRIVILEGED LAYER (runs as SYSTEM / root)                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │ clave-daemon (Rust)  — hosts clave-core                                     │   │
│  │   policy engine · zone membership · crypto/keys · DLP decisions · audit   │   │
│  └───────┬───────────────┬───────────────┬───────────────┬──────────────────┘   │
│          │ IOCTL/ESF      │ FS callbacks  │ WFP/NE        │ control IPC          │
│  ┌───────▼──────┐ ┌───────▼──────┐ ┌──────▼───────┐ ┌─────▼──────────────────┐   │
│  │ kernel driver│ │ encrypted    │ │ net filter / │ │ overlay UI process     │   │
│  │ (Win) /      │ │ volume FS    │ │ tunnel data  │ │ (Clave Edge, prompts) │   │
│  │ ES+NE (mac)  │ │ (WinFsp/APFS)│ │ plane        │ │                        │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────────┐
│  USER LAYER (runs as the user)                                                     │
│   work app  ── shim (Win DLL hooks / mac helper) ──►  talks to daemon over IPC     │
│   work app  ── shim ──►                                                            │
│   personal app  (untouched, no shim, no border)                                    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Component responsibilities

| Component | Privilege | Language | Responsibility |
|-----------|-----------|----------|----------------|
| **clave-core** | n/a (library) | Rust, `#![forbid(unsafe)]` where possible | Policy evaluation, zone model, crypto primitives, DLP rule engine, gateway protocol, audit serialization. **No OS calls.** |
| **clave-daemon** | SYSTEM / root | Rust | Hosts `clave-core`; owns the supervised-PID set; brokers all privileged operations; talks to gateway; supervises driver/extensions. |
| **Kernel driver** (Win) | kernel | C/WDK or `windows-drivers-rs` | Process-creation callbacks, minifilter for FS redirection, registry callbacks, WFP callout, keyboard filter. The Windows source of truth. |
| **System extensions** (mac) | root (user space) | Swift/ObjC host + Rust staticlib | Endpoint Security client (exec/file auth), Network Extension provider. The macOS source of truth. |
| **Shim** | user | Rust `cdylib` (Win) | Injected into each work app; installs syscall hooks; sets per-window screen-capture affinity; gates clipboard reads. **Convenience layer, not trusted.** |
| **Encrypted volume FS** | SYSTEM / root | Rust (WinFsp) / native (APFS) | The Clave Disk; encrypts at rest; gates opens by caller identity. |
| **Overlay UI** | user | Rust (`windows`/`objc2`) | Draws Clave Edge, shows policy prompts, status. |
| **Gateway** | cloud | (out of scope) | Static-IP egress, WireGuard endpoint, policy/key distribution. |

---

## 4. Shared-core / platform-adapter split

`clave-core` must never call an OS API directly. It depends only on **traits** that the
platform crates implement. This keeps ~70% of the logic portable and unit-testable on a
dev laptop with no driver installed.

```rust
// clave-core/src/platform.rs  — the seam between portable logic and OS mechanism
pub trait Platform: Send + Sync + 'static {
    type Supervisor:  ProcessSupervisor;
    type Volume:      VolumeMount;
    type Clipboard:   ClipboardBroker;
    type Network:     NetworkTunnel;
    type Screen:      ScreenGuard;
    type Overlay:     WindowOverlay;
    type Input:       InputGuard;

    fn supervisor(&self) -> &Self::Supervisor;
    fn volume(&self)     -> &Self::Volume;
    fn clipboard(&self)  -> &Self::Clipboard;
    fn network(&self)    -> &Self::Network;
    fn screen(&self)     -> &Self::Screen;
    fn overlay(&self)    -> &Self::Overlay;
    fn input(&self)      -> &Self::Input;
}

/// Authoritative process identity. On Windows this wraps a PID + a creation
/// time (to defeat PID reuse). On macOS it wraps the audit token.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcId {
    Windows { pid: u32, create_time: u64 },
    Macos   { audit_token: [u32; 8] },
}

pub enum Decision { Allow, Deny, Watermark, Prompt }
```

Each subsequent document specifies one of these traits and both implementations.

---

## 5. Process & data lifecycle

### 5.1 Enrollment (once per device)
1. User installs the package; daemon + driver/extensions register and load.
2. Daemon performs device attestation and user auth against the gateway (mTLS).
3. Gateway returns: signed **policy bundle**, the **volume key** (wrapped to the device's
   hardware root — TPM/Secure Enclave), and **WireGuard** config.
4. Daemon provisions the encrypted volume, unwraps the key into the hardware-backed store,
   and arms the kernel/extension layer with the current policy.

### 5.2 Launching a work app
```
user clicks "Excel (Work)" in the Clave launcher
        │
        ▼
daemon: CreateProcess(suspended)  ──►  add PID to supervised set (driver notified)
        │                                        │
        ▼                                        ▼
inject shim DLL (Win) / mark audit token (mac)   driver: assign to Job/Silo, arm FS+registry
        │                                            redirection for this PID
        ▼
resume process ──► app boots, sees emulated registry + redirected FS (Clave Disk)
        │
        ▼
overlay UI begins tracking the app's windows ──► draws Clave Edge
        │
        ▼
network flows from this PID classified → tunnel;  clipboard/screen/input gated by zone
```

### 5.3 A guarded operation (example: paste)
```
work app copies → broker tags clipboard payload "zone=work", real bytes kept in enclave
user switches to personal browser, hits Ctrl+V
        │
        ▼
shim hook in browser? (no shim in personal app) — so enforcement falls to the broker:
the global clipboard holds only a token; GetClipboardData in an unsupervised PID returns
the token, broker refuses to render the real bytes → paste yields nothing / a deny notice
        │
        ▼
audit event emitted: {action: paste, src_zone: work, dst_zone: personal, decision: Deny}
```

### 5.4 Lock / logout / wipe
- **Lock:** volume key evicted from memory; encrypted volume unmounted; tunnel torn down.
- **Remote wipe:** gateway signals daemon → destroy the wrapped volume key in the hardware
  store and unlink the container. Personal data is untouched because it was never inside
  the enclave. See [04](04-encrypted-volume.md#remote-wipe).

---

## 6. Why each OS forces a different shape

| Concern | Windows | macOS |
|---------|---------|-------|
| Kernel extensibility | Full: load your own KMDF driver / minifilter | None: kexts deprecated; use user-space System Extensions only |
| App-subsystem virtualization | Strong: inject + hook `Nt*`, virtualize registry/namespace/FS | Weak: SIP + library validation block injection into signed apps |
| Authoritative identity at a syscall | PID via driver callbacks | `audit_token` via Endpoint Security |
| Network per-app routing | WFP callout (`CONNECT_REDIRECT`) | `NETransparentProxyProvider` |
| Screen-capture exclusion of 3rd-party windows | Possible via injection (`SetWindowDisplayAffinity`) | Not possible to set on others' windows; reactive only |
| Encrypted volume | WinFsp user-mode FS | Native encrypted APFS/sparsebundle |

The recurring theme: **Windows lets you reach into other processes and the kernel; macOS
deliberately does not.** Plan for a richer Windows enforcement surface and a
monitor/authorize-centric macOS surface. This asymmetry is quantified per subsystem and
summarized in [01 §6](01-threat-model.md).

---

## 7. What "done" looks like (acceptance criteria for the architecture)

- A work app launched by the daemon **cannot** read a file outside the Clave Disk's allowed
  set, and a personal app **cannot** read the Clave Disk at all — enforced by the
  driver/ESF, verified with the user-mode hooks disabled.
- Copy from a work app → paste into a personal app **fails** (Windows: hard; macOS:
  best-effort, documented).
- A screen capture of the desktop **excludes/watermarks** work windows (Windows: reliable;
  macOS: reactive).
- Work network flows egress the corporate **static IP**; personal flows egress the user's
  ISP; DNS for work names does not leak to the personal resolver.
- Every work window carries the **Clave Edge**, correctly z-ordered and multi-monitor/DPI
  aware.
- Pulling the package / killing the daemon **does not** expose the Clave Disk plaintext
  (key lives in hardware store, volume unmounts on daemon exit).

Proceed to [01 — Threat Model & Security Model](01-threat-model.md).
