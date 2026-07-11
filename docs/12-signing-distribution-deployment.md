# 12 — Signing, Distribution & Deployment

The code is the easy part. The **signing and entitlement walls are the schedule risk** — they
are multi-week, partly outside your control, and gate whether the product can run on a customer
machine *at all*. Treat this document as a critical-path dependency, not an afterthought. Start
these processes on day one (see [13](13-build-roadmap.md)).

---

## 1. Windows: code & driver signing

### 1.1 User-mode binaries (daemon, shim, UI)

- **Authenticode** sign with an **OV or EV code-signing certificate**. EV gives instant
  SmartScreen reputation; OV builds reputation over time/installs.
- Sign every PE: `clave-daemon.exe`, `clave-shim-win.dll`, `clave-win.dll`, the WinFsp FS DLL, the
  installer. Unsigned binaries trip SmartScreen and many EDRs.
- The shim is **injected into other processes** → it *will* be scrutinized by AV/EDR. Sign it,
  and pursue allow-listing relationships (see §1.3).

### 1.2 The kernel driver (`clave.sys`) — the hard wall

Kernel-mode drivers on Windows 10/11 x64 require Microsoft's signature, obtained via the
**Windows Hardware Developer Program (Partner Center / "Hardware Dashboard")**:

1. **EV certificate** to establish the dashboard account (hardware-token-backed).
2. **Attestation signing** (for simple drivers) — Microsoft counter-signs after automated
   checks. Faster path, no full HLK.
3. **WHQL / HLK** (Windows Hardware Lab Kit) testing for broader compatibility certification —
   slower, more thorough; required for certain driver classes and for the Windows Update
   distribution path.
4. Microsoft returns a **counter-signed** driver that the OS will load. **Without this the
   driver will not load** on a stock Secure-Boot machine.

Implications:

- The driver path is **weeks of lead time** and requires the EV cert *before* you can even
  submit. Acquire the cert and open the dashboard account immediately.
- Every driver revision re-submits. Plan a signing cadence; don't iterate the driver casually.
- A **minifilter** also needs an allocated **altitude** from Microsoft (a filter-load-order
  number) — request it early (it's a form, not a build).
- If you ship a **keyboard filter** (doc 06) it's in the input path → highest scrutiny and
  stability bar.

### 1.3 EDR / AV coexistence

Your product *looks like* malware to other security tools (injection, hooks, a filter driver).
Mitigate proactively:

- Submit binaries to major AV/EDR vendors for **allow-listing**; join their partner programs.
- Avoid the most-flagged techniques where a supported API exists (e.g. APC injection over
  `CreateRemoteThread`; supported `SetWindowDisplayAffinity` over screen-scraping tricks).
- Be ready to give customers **EDR exclusion guidance** for your install paths and processes.

---

## 2. macOS: Developer ID, entitlements, notarization

### 2.1 Signing & hardened runtime

- **Developer ID Application** certificate signs the daemon, the app, and both System
  Extensions; **Developer ID Installer** signs the `.pkg`.
- **Hardened Runtime** (`--options runtime`) is required for notarization and for the
  entitlements below.
- **Notarization**: `notarytool submit` → Apple scans → `stapler staple`. Un-notarized
  software is blocked by Gatekeeper on customer Macs.

### 2.2 The entitlement wall (the macOS equivalent of driver signing)

The high-value frameworks are **entitlement-gated, and the entitlements require Apple's
explicit approval of your company** — this is the macOS schedule risk:

| Capability | Entitlement | Approval |
|------------|-------------|----------|
| Endpoint Security client (doc 02/04) | `com.apple.developer.endpoint-security.client` | **Apple must approve** your request (a form + justification); can take weeks |
| System Extension | `com.apple.developer.system-extension.install` | Part of the Developer ID flow |
| Network Extension (doc 08) | `com.apple.developer.networking.networkextension` (e.g. `app-proxy-provider`, `content-filter-provider`) | Request via the dev portal |

- **Without the ES entitlement, you cannot ship the file/exec authorization core on macOS.**
  Request it on day one; it is the long pole.
- System Extensions run in **user space** (no kext), are **managed by the OS**, and on managed
  devices are **MDM-deployable and locked** so the user can't disable them.

### 2.3 TCC permissions (user-facing prompts)

Several subsystems need user-granted **TCC** permissions, which you should pre-grant via MDM on
managed devices and design onboarding around on BYO devices:

| Subsystem | TCC permission |
|-----------|----------------|
| Clave Edge (doc 09) | **Accessibility** (read other apps' window geometry) |
| Screen-capture detection / blanking (doc 07) | **Screen Recording** |
| Input-tap detection (doc 06) | **Input Monitoring** |
| Full-disk reach for ES file gating | **Full Disk Access** (often) |

On unmanaged BYO-PC these are user prompts — design a clear, trust-building onboarding. On
MDM-managed devices, push **PPPC (Privacy Preferences Policy Control)** profiles to pre-approve
them.

---

## 3. Deployment

### 3.1 Managed (MDM) — the enterprise default

| | Windows | macOS |
|---|---------|-------|
| MDM | Intune, others | Jamf, Intune, Kandji |
| Push the agent | Win32 app / MSIX | `.pkg` + config profile |
| Pre-approve | driver/EDR exclusions | System Extension allow + PPPC (TCC) + NE config |
| Lock it down | tamper protection, prevent uninstall | profile locks System Extensions on |

MDM is where this product is *pleasant* to deploy: extensions pre-approved, TCC pre-granted,
the static-IP network profile pushed, uninstall locked. Document a turnkey MDM playbook per
platform.

### 3.2 Unmanaged BYO-PC — the harder, on-brand case

The whole premise is *unmanaged personal devices*, so you must also handle the no-MDM path:

- A guided installer that walks the user through each consent (UAC elevation + driver install
  on Windows; System Extension approval + each TCC prompt on macOS).
- Clear, minimal, *honest* permission explanations (privacy-sensitive users will read them).
- Graceful degradation messaging when a permission is declined (e.g. "Clave Edge needs
  Accessibility to draw the frame").

### 3.3 Update mechanism

- **Daemon/shim/UI:** standard auto-update (signed, staged, rollback-capable).
- **Driver (Win):** re-signed via the dashboard each revision → update less often; stage
  carefully (a bad driver bricks boot — ship with a watchdog/rollback and test on the HLK).
- **Extensions (mac):** updated via the app/`.pkg`; the OS manages extension replacement.

---

## 4. The realistic timeline of the walls (plan around these)

```
Day 0  ── acquire EV cert (Win) ───────────────────────────────► (token shipping: ~days)
Day 0  ── open Partner Center / Hardware Dashboard ────────────► account approval
Day 0  ── request ES entitlement (mac) ────────────────────────► Apple approval: WEEKS
Day 0  ── request NE entitlement + minifilter altitude ────────► forms
   │
   ├─ build user-mode + core in parallel (no signing needed for dev)
   │
Week N ── first driver attestation submission ─────────────────► counter-signed driver
Week N ── ES entitlement granted → ship file/exec gating on mac
   │
   └─ AV/EDR allow-listing submissions (ongoing)
```

**The two long poles are the Apple ES entitlement approval and the Windows driver signing
account/cert.** Both must be kicked off **before** you write the code that depends on them, or
they become the critical path at the worst time. This is why [13](13-build-roadmap.md)
sequences a signing-light vertical slice first.

---


Proceed to [13 — Build Roadmap](13-build-roadmap.md).
