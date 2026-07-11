# Clave — Local Secure Enclave Engineering Documentation

**Clave** is the project codename for a **local secure enclave** ("BYOD
workspace") — a reference design and implementation guide in **Rust** for **Windows** and
**macOS**.

The goal of the system documented here: run a company's work applications **natively**
on an employee's unmanaged personal computer, inside a **company-controlled, encrypted,
policy-enforced boundary** — *without* machine virtualization (no VDI, no hypervisor, no
streamed desktop, no backend compute).

> **One-sentence definition.** Work apps run as ordinary native processes, but they are
> wrapped in *application-subsystem virtualization* (emulated registry/namespace +
> encrypted, redirected filesystem) and a *kernel-mode/user-mode interception layer*
> that enforces a zone boundary across clipboard, input, screen capture, files, and
> network — plus a continuously-tracked overlay frame for the visual boundary.

---

## How to read this set

Read in order if you are new to the problem. Jump by subsystem if you are implementing.

| # | Document | What it covers |
|---|----------|----------------|
| — | [README.md](README.md) | This index, glossary pointer, conventions |
| 00 | [Architecture Overview](00-architecture-overview.md) | Component inventory, trust levels, shared-core/adapter split, process lifecycle |
| 01 | [Threat Model & Security Model](01-threat-model.md) | Assets, adversaries, trust boundaries, what is *enforceable* vs *best-effort* per OS, the kernel-authoritative principle |
| 02 | [Process Supervision](02-process-supervision.md) | Defining the zone: process-creation callbacks, Job Objects/Silos, Endpoint Security `AUTH_EXEC`, the supervised-PID set |
| 03 | [App-Subsystem Virtualization](03-app-subsystem-virtualization.md) | The "no VM" trick: registry/namespace/filesystem virtualization, DLL injection + syscall hooks, the Sandboxie model, why it does not transfer to macOS |
| 04 | [Encrypted Volume ("Clave Disk")](04-encrypted-volume.md) | AES-XTS block crypto, key hierarchy, hardware root (TPM/Secure Enclave), WinFsp/Dokany, encrypted APFS/sparsebundle, remote wipe |
| 05 | [Clipboard & Data-Transfer DLP](05-clipboard-dlp.md) | Clipboard broker, delayed rendering, format tagging, per-process hooks, drag-and-drop, the macOS pre-paste gap |
| 06 | [Input Isolation](06-input-isolation.md) | Anti-keylogger between zones, keyboard filter driver, low-level-hook detection, the honest limits |
| 07 | [Screen-Capture Protection](07-screen-capture-protection.md) | `WDA_EXCLUDEFROMCAPTURE`, `NSWindow.sharingType`, owning-thread problem, reactive detection, watermarking |
| 08 | [Network Split-Tunnel](08-network-split-tunnel.md) | Per-flow classification, WFP `CONNECT_REDIRECT` callout, `NETransparentProxyProvider`, boringtun data plane, static egress IP, DNS-leak prevention |
| 09 | [Visual Border Overlay](09-visual-border-overlay.md) | Layered window + `SetWinEventHook`, NSWindow + Accessibility observers, z-order sync, multi-monitor/DPI |
| 10 | [Policy Engine & IPC](10-policy-engine-and-ipc.md) | Policy schema, distribution/signing, daemon design, IPC peer authentication, audit/telemetry |
| 11 | [Rust Workspace Layout](11-rust-workspace-layout.md) | Cargo workspace, crate graph, FFI bridges (cxx/swift-bridge/bindgen), no_std driver, build orchestration, test strategy |
| 12 | [Signing, Distribution & Deployment](12-signing-distribution-deployment.md) | Driver signing (EV/WHQL), Apple entitlement approval, notarization, MDM (Intune/Jamf), TCC prompts |
| 13 | [Build Roadmap](13-build-roadmap.md) | Phased plan that de-risks the signing/entitlement walls first; MVP scoping |
| 14 | [Production & Development Platform Requirements](14-production-and-development-platform-requirements.md) | Production approvals, entitlements, driver signing, and development-mode workarounds for Apple and Windows |
| 15 | [Identity & Enrollment Auth](15-identity-and-enrollment-auth.md) | Console login, device-enrollment handshake, device registration, sealed-cookie sessions |
| 16 | [Third-Party Network Providers](16-third-party-network-providers.md) | Pluggable work-zone egress (Zscaler, Cisco, …): vendors-as-data, `ForwardMode` dispatch, IPsec/explicit-proxy/DNS seams |
| A | [Appendix A — Windows Primitives](appendix-a-windows-primitives.md) | API/crate reference tables |
| B | [Appendix B — macOS Primitives](appendix-b-macos-primitives.md) | API/crate reference tables |
| C | [Appendix C — References & Reading List](appendix-c-references.md) | Open-source blueprints, OS docs |
| — | [GLOSSARY.md](GLOSSARY.md) | Terms and acronyms |

---

## Conventions used throughout

- **"Supervised" / "work" / "in-zone"** are synonyms for a process, window, file, or flow
  governed by the enclave. **"Unsupervised" / "personal" / "out-of-zone"** is everything else.
- **"Daemon"** = the privileged background service (`Windows Service` on Windows,
  `launchd` root daemon on macOS) that hosts the shared Rust core.
- **"Shim"** = the small code injected into / hosted alongside each work app (a DLL on
  Windows; a framework helper / network-extension provider on macOS).
- **"Gateway"** = the company-side cloud endpoint that provisions policy and keys and
  provides the static-IP network egress.
- Code is illustrative Rust unless marked otherwise. It favors clarity over completeness;
  `unsafe`, error handling, and lifetimes are elided where they would obscure the mechanism.
  Anything marked `// SKETCH` is structure-only.
- **Honesty markers.** Look for **⚠ ENFORCEABLE-ONLY-WITH-DRIVER**, **◐ BEST-EFFORT**, and
  **✗ NOT-ENFORCEABLE-ON-THIS-OS** call-outs. The macOS story is *materially weaker* than
  Windows for several subsystems and the docs say so explicitly rather than papering over it.

---

## The five-second mental model

```
        ONE NATIVE OS (Windows / macOS) — no hypervisor, no guest OS
 ┌──────────────────────────────┬───────────────────────────────────┐
 │       PERSONAL ZONE          │   SECURE ENCLAVE ("Work Zone")     │
 │  (unsupervised resources)    │   Clave Edge around each window    │
 │  - personal apps             │   - work apps run NATIVELY         │
 │  - user's ISP connection     │   - Clave Disk (encrypted volume)   │
 │  - private, invisible to IT  │   - emulated registry/namespace    │
 └──────────────┬───────────────┴──────────────┬────────────────────┘
                │                                │
        ┌───────┴────────────────────────────────┴────────┐
        │   Daemon (Rust core) + driver / system extension │
        │   intercepts: clipboard · input · screen capture │
        │   · file I/O · network routing · window geometry │
        └──────────────────────────────────────────────────┘
```

---

## Status of this documentation

This is a **design reference**, not a shipped product. Code skeletons compile-in-spirit
but are not a working build. Every external API named here is real and current as of the
2023–2026 platform generations (Windows 10 2004+/Windows 11; macOS 13 Ventura+ with the
Endpoint Security and Network Extension frameworks). Where an API is private/unsupported
(e.g. `sandbox_init` profiles), it is flagged as such.

Start with [00-architecture-overview.md](00-architecture-overview.md).
