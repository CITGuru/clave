# 01 — Threat Model & Security Model

This document is the contract that every subsystem is measured against. If a later
document claims to "block" something, this document says *against which adversary* and
*with what residual risk*.

---

## 1. Assets (what we protect)

| Asset | Where it lives | Why it matters |
|-------|----------------|----------------|
| Work files | Encrypted volume (Clave Disk) | Primary IP / regulated data |
| Credentials & session tokens | Browser profile + app profiles inside the volume | Lateral access to SaaS, email |
| Work clipboard contents | Transient, broker-held | DLP exfil vector |
| Keystrokes into work apps | Transient | Passwords, sensitive text |
| Screen contents of work windows | Transient, on display | Screenshot exfil; shoulder-surf via remote tools |
| Work network traffic | In flight | Confidentiality + the static-IP identity used for conditional access |
| Policy & volume keys | Hardware store (TPM/Secure Enclave) + daemon memory | Root of the whole scheme |

**Explicit non-assets (privacy guarantees):** personal files, personal browsing history,
personal app data, personal keystrokes/screen, personal network traffic. The system must be
*structurally incapable* of shipping these, not merely "configured not to."

---

## 2. Adversaries

| # | Adversary | Capability | In scope? |
|---|-----------|-----------|-----------|
| A1 | **Curious/negligent user** | Runs as themselves; may try to copy work data out, take screenshots, save to personal disk, email to self | ✅ Primary |
| A2 | **Commodity malware in personal zone** | Userland code running as the user (infostealer, RAT) trying to read work data or keylog | ✅ Primary |
| A3 | **Malicious work app / compromised work supply chain** | Code *inside* the zone trying to exfiltrate via clipboard/network/file | ✅ Primary |
| A4 | **Network attacker** | On-path between device and gateway | ✅ (mTLS + WireGuard) |
| A5 | **Thief with the powered-off device** | Physical possession, attempts offline disk read | ✅ (encryption at rest) |
| A6 | **Privileged local attacker (admin/root)** | User has administrative rights and actively attacks the enclave | ◐ Partial — see §4 |
| A7 | **Kernel rootkit on the host** | Code at ring-0 / with `kext`-equivalent power | ✗ Out of scope — same trust level as our driver |
| A8 | **Hardware/DMA/cold-boot attacker** | Bus interposers, DMA, cold-boot RAM extraction | ✗ Out of scope (mitigated only by platform: VT-d/IOMMU, encrypted RAM) |

The honest center of gravity: **A1–A5 are the design target.** A6 is partially addressed.
A7–A8 are conceded — and a VM/VDI would also struggle with A8, while a VM *would* beat us
on A7-against-the-guest. State this in every stakeholder conversation.

---

## 3. Trust boundaries

```
   ┌─────────────────────── TRUSTED ───────────────────────┐
   │ hardware root (TPM / Secure Enclave)                   │  ← root of trust
   │ kernel driver (Win) / system extensions (mac)          │  ← enforcement truth
   │ clave-daemon (SYSTEM/root) + clave-core                  │  ← policy brain
   └───────────────────────────┬────────────────────────────┘
                               │  IPC boundary (authenticated, see §5)
   ┌───────────────────────────┴──── SEMI-TRUSTED ──────────┐
   │ shim inside each work app                              │  ← convenience, assume hostile-capable
   │ overlay UI process                                     │
   └───────────────────────────┬────────────────────────────┘
                               │  zone boundary (the product)
   ┌───────────────────────────┴──────── UNTRUSTED ─────────┐
   │ work app code itself (A3)   │  personal apps (A1/A2)    │
   └─────────────────────────────┴──────────────────────────┘
```

Two boundaries do the heavy lifting:

1. **The IPC boundary** between the semi-trusted shim and the trusted daemon. The daemon
   must **never** trust a claim from the shim about *which zone a process is in* — it
   re-derives identity from the kernel/ESF. The shim can request and report, not decide.
2. **The zone boundary** between work and personal resources, enforced at OS chokepoints.

---

## 4. The privileged-attacker problem (A6) and the kernel-authoritative principle

If the user is a local administrator (common on BYO-PC), they can:

- unload your user-mode hooks,
- attach a debugger to a work app,
- run their own driver,
- read another process's memory (with `SeDebugPrivilege` / as root).

You cannot *fully* defeat A6 without a VM. What you can do — and **must** do — is ensure
that **defeating a hook does not defeat a guarantee**. This is the **kernel-authoritative
principle**:

> Every enforced guarantee must terminate in a check made by the kernel driver (Windows) or
> a system extension (macOS), keyed on a kernel-supplied identity, **not** on a user-mode
> hook and **not** on a claim from the shim.

Worked examples:

| Guarantee | ✗ Hook-only (defeatable by A6) | ✅ Kernel-authoritative |
|-----------|-------------------------------|------------------------|
| Personal app can't read Clave Disk | Shim refuses `CreateFile` | **Minifilter/ESF** denies `IRP_MJ_CREATE`/`AUTH_OPEN` by caller PID/token |
| Work flow must use tunnel | Shim binds socket to tunnel | **WFP callout/NE** redirects by PID/audit token at connect |
| Only work apps in supervised set | Shim self-reports | **Process-create callback** assigns membership at exec |

Where a guarantee is *only* available as a hook (e.g. some clipboard reads, see
[05](05-clipboard-dlp.md)), it is explicitly labeled **◐ BEST-EFFORT** and treated as a DLP
speed-bump against A1/A2, not a control against A3/A6.

---

## 5. IPC authentication (closing the boundary in §3)

Any process can try to open the daemon's pipe/socket and impersonate a work app. The daemon
authenticates peers cryptographically and by code identity:

- **Windows:** obtain the client PID from the named-pipe (`GetNamedPipeClientProcessId`),
  then verify the image with **`WinVerifyTrust`** (Authenticode) and confirm the PID is in
  the supervised set (driver-backed). Optionally require a per-launch nonce handed to the
  shim at injection time.
- **macOS:** XPC connection → read `audit_token` from the message
  (`xpc_connection_get_audit_token`), validate the peer's code signature with
  **`SecCodeCheckValidity`** against a pinned requirement (Team ID + signing ID), and
  confirm the token is in the supervised set.

Never use PID alone (PID reuse) or the connecting process name (spoofable). The
`ProcId` type in [00 §4](00-architecture-overview.md) carries creation-time/audit-token
precisely to defeat reuse.

---

## 6. Enforceability matrix (the honest scorecard)

Legend: **✅ Enforceable** (kernel-authoritative, holds against A3/A6) · **◐ Best-effort**
(hook/monitor; holds against A1/A2, defeatable by A3/A6) · **✗ Not enforceable** on this OS.

| Control | Windows | macOS | Notes |
|---------|:------:|:-----:|-------|
| Zone membership at process birth | ✅ | ✅ | Win: PsSetCreateProcessNotifyRoutineEx2; mac: ESF AUTH_EXEC |
| Personal app cannot read Clave Disk | ✅ | ✅ | Minifilter / ESF AUTH_OPEN |
| Work app cannot write outside enclave | ✅ | ◐→✅ | Win: minifilter; mac: ESF AUTH_OPEN gates writes but can't *redirect* |
| Registry/namespace isolation | ✅ | n/a | macOS has no registry; isolation is FS+sandbox |
| Clipboard work→personal block | ✅ (hard) | ◐ | mac: no pre-paste interception; monitor/sanitize only |
| Drag-and-drop work→personal block | ✅ | ◐ | same as clipboard |
| Keylogging of work apps by personal apps | ◐ (✅ with kbd filter driver) | ◐ | GetAsyncKeyState polling is the residual hole; mac gated by Input-Monitoring TCC |
| Screenshot excludes work windows | ✅ (via injection) | ◐ (reactive) | Win: WDA_EXCLUDEFROMCAPTURE; mac: can't set sharingType on 3rd-party windows |
| Work flow forced through tunnel | ✅ | ✅ | WFP / NETransparentProxy |
| DNS-leak prevention for work | ✅ | ✅ | resolver bound to tunnel |
| Static-IP conditional access | ✅ | ✅ | gateway egress |
| Data-at-rest confidentiality (A5) | ✅ | ✅ | AES-XTS, hardware-wrapped key |
| Resist hook removal (A6) | ◐ | ◐ | mitigated by kernel-authoritative checks, not eliminated |
| Resist kernel rootkit (A7) | ✗ | ✗ | conceded; out of scope |

**Reading the matrix:** the columns with the most ◐ on macOS — clipboard, screenshot,
keylogging — are exactly the user-experience-visible DLP features. Product/marketing must
not over-promise these on macOS. They are real deterrents against honest users and
commodity malware, and not controls against a determined in-zone adversary.

---

## 7. STRIDE pass (condensed)

| Threat | Vector | Mitigation | Residual |
|--------|--------|-----------|----------|
| **S**poofing | Personal proc impersonates work app to daemon | IPC code-signature + supervised-set check (§5) | A6 with valid signed work binary can still talk — but only as a work app, which is allowed |
| **T**ampering | A6 unloads hooks / patches shim | Kernel-authoritative checks (§4); driver self-protection (ObRegisterCallbacks to block handle open to protected procs) | Hooks degrade gracefully; guarantees hold |
| **R**epudiation | User denies exfil attempt | Tamper-evident audit log shipped to gateway (append-only, signed) | Log can be suppressed by A6 locally; gateway sees gaps |
| **I**nfo disclosure | Read Clave Disk / clipboard / screen | Encryption + zone-gated opens + capture exclusion | macOS clipboard/screen = ◐ |
| **D**oS | Kill daemon to disable enforcement | Fail-closed: volume unmounts, tunnel drops, work apps lose access (not silently insecure) | User loses work access (acceptable); cannot leak by killing |
| **E**levation | Work app exploits driver to ring-0 | Minimal kernel attack surface; fuzz the IOCTL/callout interface; Rust for memory safety | A real driver 0-day = full compromise (true of any EDR) |

**Fail-closed is a security requirement, not a UX preference.** Every enforcement point must
default to *deny / no-access* when the daemon or driver is absent, not to *allow*. A killed
daemon must make the Clave Disk inaccessible, not unprotected-but-readable.

---

## 8. Anti-tamper requirements (self-protection)

The driver/extension must protect the enforcement components themselves:

- **Windows:** register **`ObRegisterCallbacks`** to strip dangerous access rights
  (`PROCESS_VM_WRITE`, `PROCESS_TERMINATE`) when a handle to the daemon or a work process is
  opened by a non-trusted process; mark the daemon as a **protected process light (PPL)** if
  you can meet the signing bar; watch for hook removal and re-arm.
- **macOS:** the System Extension lifecycle is managed by the OS and cannot be killed by the
  user without removing the (MDM-locked) configuration profile; ESF clients are restarted by
  the OS. Use **`com.apple.developer.endpoint-security.client`** + MDM `NSExtension`
  management so the user cannot unload it without unenrolling.

> Anti-tamper raises the cost for A6; it does not change the A7 concession. Document the
> difference so it is not mistaken for VM-grade isolation.

---

## 9. Privacy enforcement (the non-assets)

Privacy is a *security control against your own company*, and regulators treat it that way.
Concrete measures:

- **No global hooks on personal processes.** The shim is injected *only* into supervised
  processes. Personal apps are never instrumented.
- **Screen/keyboard capture is scoped to work windows by construction** — the capture-block
  path operates on the supervised window set; there is no code path that records personal
  windows.
- **Split tunnel routes only supervised flows** (see [08](08-network-split-tunnel.md));
  personal traffic never enters the corporate tunnel, so the company never sees personal
  browsing.
- **Audit events carry zone + action, never personal content.** The audit schema
  ([10](10-policy-engine-and-ipc.md)) forbids personal-path fields.
- Ship a **data-flow attestation** doc to customers' works councils showing these are
  structural, not configurable.

Proceed to [02 — Process Supervision](02-process-supervision.md).
