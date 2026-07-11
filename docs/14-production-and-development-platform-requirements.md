# 14 — Production & Development Platform Requirements

This document is the platform-readiness checklist for Clave. It answers two questions:

1. What must be approved, signed, entitled, packaged, or deployed before Clave can run on a
   normal customer machine?
2. How do we keep developing while those approvals are pending?

The short version: **production requires Apple and Microsoft approval paths; development can
prototype most behavior with mocks, user-mode stand-ins, and deliberately weakened lab machines.**
Do not confuse those dev shortcuts with shippable security posture.

---

## 1. Production: macOS

Target: macOS 13+ Ventura, Apple Silicon and Intel, Developer ID distribution outside the Mac App
Store.

### 1.1 Apple accounts, certificates, and signing

Required before customer deployment:

- Apple Developer Program membership under the company, not an individual's personal account.
- Developer ID Application certificate for the app, daemon bundle, helpers, and System Extensions.
- Developer ID Installer certificate for the `.pkg`.
- Hardened Runtime enabled for shipped binaries.
- Notarization with `notarytool`, followed by stapling the notarization ticket.
- Provisioning profiles that authorize each restricted entitlement used by the containing app and
  extensions.

Production packaging should be a signed and notarized `.pkg` that installs:

- the user-facing app or menu bar controller;
- the privileged `launchd` daemon;
- the Endpoint Security System Extension;
- the Network Extension System Extension;
- configuration profiles for System Extension approval, Network Extension configuration, and TCC
  pre-approval when deployed through MDM.

### 1.2 Restricted entitlements and capabilities

| Clave subsystem | Apple primitive | Production entitlement / capability | Approval path |
|-----------------|-----------------|--------------------------------------|---------------|
| Process supervision and file authorization | Endpoint Security `AUTH_EXEC`, `AUTH_OPEN`, notify events | `com.apple.developer.endpoint-security.client` | Restricted entitlement. Request from Apple with a security-product justification. Can be approved for development first, then Developer ID distribution later. |
| System Extension install | `OSSystemExtensionRequest` | `com.apple.developer.system-extension.install` | Enable on the containing app's Developer ID App ID and provisioning profile. |
| Split tunnel / per-app network routing | `NETransparentProxyProvider` or `NEAppProxyProvider` as a System Extension | `com.apple.developer.networking.networkextension` with Developer ID System Extension values such as `app-proxy-provider-systemextension`, `packet-tunnel-provider-systemextension`, `content-filter-provider-systemextension`, or `dns-proxy-systemextension` as needed | Enable Network Extension capability for the Developer ID app and extension App IDs; regenerate provisioning profiles. |
| Hardware-rooted key storage | Keychain + Secure Enclave / LocalAuthentication | Keychain access groups, Team ID entitlements, hardened runtime | Standard Developer ID provisioning, but test the exact access-control flags on real hardware. |
| Privileged helper / daemon | `launchd` root daemon, helper tools | signed helper bundle; optionally SMAppService / launchd packaging | No special restricted entitlement by itself, but must be signed, notarized, and installed with admin authorization. |
| Overlay window tracking | Accessibility API | TCC Accessibility grant | User prompt or MDM PPPC profile. |
| Screen-capture detection / own-window exclusion | ScreenCaptureKit / CoreGraphics / `NSWindow.sharingType` | TCC Screen Recording grant for detection | User prompt or MDM PPPC profile. |
| Input monitoring / tap detection | CoreGraphics event tap introspection | TCC Input Monitoring grant | User prompt or MDM PPPC profile. |
| Full-disk reach for ES file decisions | Endpoint Security over protected locations | Full Disk Access often required in practice | MDM PPPC profile strongly preferred. |

Important constraint: **Endpoint Security and Network Extension are not just code-signing details.**
If the entitlement is missing from the provisioning profile, the framework call fails even if the
binary is signed.

### 1.3 MDM profiles for enterprise deployment

For a normal enterprise rollout, assume MDM is the happy path. Prepare profiles for:

- System Extension allow-listing by Team ID and bundle ID.
- Network Extension / Transparent Proxy configuration.
- PPPC grants for Accessibility, Screen Recording, Input Monitoring, and Full Disk Access where
  allowed by Apple policy.
- Login item / launchd daemon management.
- Tamper-resistance settings: prevent user removal of the System Extensions and configuration
  profiles on managed devices.

For unmanaged BYOD, the installer must walk the user through each consent with direct, honest
copy. A privacy-sensitive user will read every prompt.

### 1.4 macOS production blockers

- No Endpoint Security entitlement means no production-grade macOS process supervision or file
  authorization.
- No Network Extension entitlement means no production-grade per-app transparent proxy.
- No notarization means Gatekeeper blocks or heavily warns on install.
- No TCC/PPPC strategy means the overlay, screen, and input features degrade or fail at onboarding.
- Disabling SIP is **not** a production path.

---

## 2. Development: macOS

Development should be split into three tracks.

### 2.1 Track A: portable development with no entitlements

Use this for most core work:

- `MockPlatform` for process membership, volume mount state, clipboard, network, screen, overlay,
  and input behavior.
- `clave-core`, `clave-daemon`, `clave-volume`, `clave-net`, `clave-ipc`, and `clave-proto` tests.
- Launcher-seeded zone membership instead of Endpoint Security.
- Loopback / boringtun tests instead of a real Network Extension.
- Sparsebundle/APFS scripts only for mount lifecycle experiments, not policy enforcement.

This is the fastest path and should stay the default CI path.

### 2.2 Track B: entitlement-backed development

Use this once Apple grants development entitlements:

- Create explicit macOS App IDs for:
  - containing app;
  - Endpoint Security System Extension;
  - Network Extension System Extension;
  - privileged helper / daemon if packaged separately.
- Enable the relevant capabilities in Certificates, Identifiers & Profiles.
- Generate development provisioning profiles and install them locally.
- Use manual signing in Xcode or equivalent `codesign` steps so each binary gets the expected
  entitlement set.
- Verify entitlements with:

```sh
codesign -d --entitlements - path/to/Clave.app
codesign -d --entitlements - path/to/Extension.systemextension
```

For System Extension iteration:

```sh
systemextensionsctl developer on
systemextensionsctl list
```

Expect repeated approval and reset cycles while developing. Test on real Macs, not only CI,
because TCC, System Extensions, Secure Enclave, and Network Extension behavior are hardware and
OS-policy sensitive.

### 2.3 Track C: weakened lab Macs

Use this only for experiments that are impossible or painfully slow under normal macOS policy.

From Recovery, a lab Mac can disable SIP:

```sh
csrutil disable
reboot
```

Re-enable it when done:

```sh
csrutil enable
reboot
```

Disabling SIP may help with local experiments around private APIs, legacy kernel-extension
research, AMFI/library-validation edge cases, or debugging OS-policy interactions. It is useful
for learning where the walls are.

It is **not** a substitute for production entitlements:

- Do not build product behavior that requires SIP to be off.
- Do not assume an Endpoint Security or Network Extension prototype is shippable until it runs on a
  stock SIP-enabled Mac with the correct provisioning profile.
- Keep SIP-disabled machines out of normal CI and customer demos unless the demo is explicitly
  labeled as a lab-only experiment.

### 2.4 macOS development fallback plan

If Apple approval is pending:

- Build the daemon, policy engine, audit, volume crypto, IPC, and WireGuard data plane normally.
- Keep the macOS adapter behind traits and feature flags.
- Use launcher-seeded process membership for demos.
- Use a local proxy or app-configured proxy for network demos until the NE entitlement arrives.
- Do not promise file authorization or exec authorization on macOS until Endpoint Security is
  approved and running on stock machines.

---

## 3. Production: Windows

Target: Windows 10 2004+ and Windows 11 x64, Secure Boot enabled, normal code integrity policy.

### 3.1 Company account, certificates, and signing

Required before customer deployment:

- Company Microsoft Partner Center account with the Hardware Developer Program enabled.
- EV code-signing certificate to establish the hardware dashboard account.
- Authenticode signing for every user-mode binary:
  - service / daemon;
  - UI;
  - shim DLL;
  - WinFsp filesystem components;
  - installer;
  - updater.
- Microsoft-signed kernel drivers through the Hardware Dashboard.
- Installer that installs drivers, services, firewall/network components, and WinFsp dependencies
  with rollback.

### 3.2 Kernel components and Microsoft approval paths

| Clave subsystem | Windows primitive | Production signing / approval |
|-----------------|-------------------|-------------------------------|
| Process supervision | process/thread creation callback driver, inverted-call `DeviceIoControl` channel | Microsoft-signed kernel driver via attestation or HLK/WHQL. |
| File authorization / Clave Disk gate | minifilter driver | Microsoft-signed driver plus Microsoft-assigned minifilter altitude. Request altitude early. |
| Network split tunnel | WFP callout driver at ALE connect / redirect layers | Microsoft-signed kernel driver. HLK is the stronger production path; attestation may be acceptable for early distribution if driver class allows it. |
| Optional input isolation | keyboard class upper-filter driver | Microsoft-signed driver, high stability and review burden. Treat as optional hardening. |
| Anti-tamper | `ObRegisterCallbacks`, service watchdog, protected process options where attainable | Microsoft-signed driver for kernel callbacks; additional product/legal review for PPL ambitions. |

Production driver paths:

- **Attestation signing:** faster, no HLK test pass, Microsoft signs through the dashboard. Useful
  for earlier controlled distribution.
- **HLK / WHQL:** slower, requires test logs, better for broad customer confidence and Windows
  Update distribution.

Do not plan production around unsigned drivers, test-signed drivers, or disabling Secure Boot.

### 3.3 Windows production deployment

Prepare:

- MSI/MSIX or enterprise installer with elevation.
- Driver installation and update flow with rollback.
- Windows Service registration and restart policy.
- Named-pipe security descriptors for IPC.
- WinFsp runtime installation or bundling strategy.
- EDR/AV allow-listing submissions for:
  - shim DLL and injection behavior;
  - kernel drivers;
  - service binaries;
  - installer and updater.
- Intune deployment guide and EDR exclusion guidance for enterprise customers.

### 3.4 Windows production blockers

- No Hardware Dashboard account means no production kernel drivers.
- No Microsoft-signed minifilter means no kernel-authoritative file gate.
- No Microsoft-signed WFP/process driver means production split-tunnel and process supervision are
  limited to weaker user-mode stand-ins.
- No EDR allow-listing plan means field deployments will be noisy and brittle.

---

## 4. Development: Windows

Development should use VMs and disposable test hardware. Never weaken your daily personal machine
unless you are deliberately doing kernel-driver work.

### 4.1 Track A: user-mode development with no driver signing

Use this for most iteration:

- `MockPlatform` and portable crate tests.
- WinDivert for user-mode network interception prototypes.
- Wintun plus boringtun for the tunnel data plane.
- WinFsp/Dokany user-mode filesystem experiments.
- Launcher-seeded process membership and Job Objects for early supervision.
- Shim and hook development in unsigned or locally signed user-mode binaries on dev VMs.

This supports a credible demo before production kernel signing is ready, but it is not the final
enforcement layer.

### 4.2 Track B: test-signed driver development

Use this for WFP callouts, minifilters, process callbacks, and optional keyboard filters.

On a dedicated Windows test machine or VM:

```bat
bcdedit.exe -set TESTSIGNING ON
```

Then reboot. If Windows reports that the value is protected by Secure Boot policy, disable Secure
Boot in firmware/UEFI first, then run the command again. On some machines, BitLocker must be
suspended before changing boot settings.

To leave test mode:

```bat
bcdedit.exe -set TESTSIGNING OFF
```

Then reboot.

Practical requirements:

- Install the Windows SDK and WDK.
- Use a self-created test certificate and sign every driver binary; modern Windows still expects a
  signature in test mode.
- Keep kernel debugging enabled on driver VMs.
- Snapshot VMs before installing drivers.
- Expect Memory Integrity / HVCI to add constraints; test with it both off for early debugging and
  on before production hardening.
- Use a temporary development altitude only on isolated machines; request the real minifilter
  altitude from Microsoft early and switch to it before production validation.

### 4.3 Track C: pre-production signed-driver validation

Before customer pilots:

- Submit the minifilter and first WFP/process driver through attestation signing.
- Install only Microsoft-signed builds on Secure Boot enabled machines.
- Run the same test matrix with HVCI / Memory Integrity on.
- Exercise install, upgrade, rollback, uninstall, crash recovery, and daemon-kill behavior.
- Capture EDR false positives and begin vendor allow-listing.

---

## 5. Cross-platform readiness checklist

### 5.1 Day-zero external requests

Start these immediately:

- Apple Developer ID setup.
- Apple Endpoint Security entitlement request.
- Apple Network Extension capability request for Developer ID System Extensions.
- Microsoft EV code-signing certificate purchase.
- Microsoft Hardware Developer Program registration.
- Microsoft minifilter altitude request.
- EDR/AV partner or allow-listing intake research.

### 5.2 Minimum lab matrix

| Purpose | macOS | Windows |
|---------|-------|---------|
| Portable CI | any macOS/Linux runner for Rust tests | any Windows/Linux runner for Rust tests |
| OS adapter dev | real SIP-enabled Mac with development profiles | Windows VM with SDK/WDK |
| Lab-only bypass testing | SIP-disabled disposable Mac | Secure Boot disabled, test-signing-enabled VM |
| Pre-production validation | stock SIP-enabled Mac, notarized/dev-signed package, MDM profile if applicable | Secure Boot enabled machine with Microsoft-signed drivers |
| Customer pilot | managed and unmanaged Macs | Windows 10 2004+ and Windows 11 with common EDRs |

### 5.3 Feature gating in code and product

Every platform capability should report one of:

- `Enforced`: running on stock OS with required approval/signing.
- `DevelopmentOnly`: running with mocks, launch seeding, test signing, disabled SIP, disabled Secure
  Boot, or local-only profiles.
- `Unavailable`: entitlement, driver, TCC grant, or OS primitive missing.

The product should surface this clearly. Internally, tests should fail if a production build
silently falls back to development-only enforcement.

### 5.4 Release rule

A Clave build is production-ready for a platform only when it passes on a stock machine:

- macOS: SIP enabled, correct entitlements in provisioning profiles, signed, notarized, TCC/MDM
  flow validated.
- Windows: Secure Boot enabled, Microsoft-signed drivers, Authenticode-signed user-mode binaries,
  EDR/AV behavior understood.

Anything else is a lab build, even if the demo works.

---

## 6. Relationship to the roadmap

This document refines the walls called out in [12](12-signing-distribution-deployment.md) and the
sequencing in [13](13-build-roadmap.md):

- Use mocks and user-mode stand-ins to keep development moving.
- Start Apple and Microsoft approval paths immediately.
- Promote each subsystem from development-only to production only when it works on a stock OS.
- Be explicit in docs, UI, and sales material about which controls are enforceable and which are
  best-effort on each platform.
