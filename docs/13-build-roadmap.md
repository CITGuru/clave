# 13 — Build Roadmap

A phased plan that **de-risks the signing/entitlement walls and the hardest subsystems first**,
delivers demoable value early, and defers the lowest-ROI / highest-stability-risk pieces. Each
phase has an explicit exit criterion.

---

## 0. Day-one, in parallel with everything (do not serialize these)

These have lead times measured in weeks and block later phases. Kick them off immediately
(see [12](12-signing-distribution-deployment.md)):

- [ ] Acquire **EV code-signing cert** (Windows) + open **Partner Center / Hardware Dashboard**.
- [ ] Request the **Apple Endpoint Security entitlement** (the long pole) + Developer ID.
- [ ] Request **Network Extension entitlement** and a **minifilter altitude**.
- [ ] Stand up the **gateway** skeleton (WireGuard endpoint with a static IP, policy-signing key).
- [ ] Stand up CI with a **Windows VM runner** and a **real-Mac runner** (extensions need real
      hardware + entitlements).

> If you remember one thing from this whole set: **start the Apple ES entitlement and the
> Windows driver-signing account on day zero.** They are the critical path and they don't care
> how fast you code.

---

## Phase 1 — Portable core + mock platform (no OS, no signing)

**Goal:** prove the brain in isolation, fast, on any laptop.

- [ ] `clave-core`: policy model, `decide()`, zone registry, DLP matrices, audit schema.
- [ ] `clave-ipc`/`clave-proto`: message enums, signing/verify, framing.
- [ ] `MockPlatform`: in-memory implementations of every trait.
- [ ] Property tests on `decide()`; fuzz the IPC parsers; golden replays.

**Exit:** full daemon runs end-to-end against `MockPlatform`; the decision logic is exhaustively
tested **without a single driver or entitlement**. ~70% of the security-critical code is now
done and verified on a dev machine.

---

## Phase 2 — Vertical slice: Network Split-Tunnel (the signing-light de-risker)

**Goal:** ship one real, demoable, **✅-enforceable-on-both-OSes** subsystem that also forces
you through a slice of the signing pipeline. See [08](08-network-split-tunnel.md).

- [ ] Windows: **WinDivert** user-mode classifier → `wintun` + `boringtun` → gateway static IP.
      (Defer the WFP callout *driver* to Phase 5; WinDivert proves the value now.)
- [ ] macOS: **`NETransparentProxyProvider`** (needs the NE entitlement — Phase 0) → boringtun.
- [ ] Encrypted volume **minimal**: encrypted sparsebundle (mac) / WinFsp volume (win), mount on
      unlock — enough to hold a profile.
- [ ] Process supervision **minimal**: launcher-seeded zone membership (doc 02), no driver yet
      on Windows (use a user-mode toolhelp tracker as a stand-in), real ES on mac if entitlement
      landed (else a stub).

**Exit:** a work browser egresses the **corporate static IP** with SaaS conditional-access
working; personal browser goes direct and is unseen. This is your **first customer demo** and
it validated the NE entitlement + tunnel data plane without needing a signed kernel driver.

---

## Phase 3 — Encrypted Clave Disk + kernel-authoritative file gating

**Goal:** real data-at-rest + the first kernel-authoritative control. See
[04](04-encrypted-volume.md).

- [ ] Hardware-rooted keys: TPM (win) / Secure Enclave + Keychain (mac).
- [ ] Full WinFsp encrypting FS (win) / encrypted APFS-or-sparsebundle with ES `AUTH_OPEN`
      gating (mac).
- [ ] **Windows minifilter** (first signed kernel component) enforcing "personal can't read the
      disk, work can't write cleartext outside it." Submit for attestation signing (Phase 0
      account now pays off).
- [ ] Remote wipe (crypto-shred).

**Exit:** personal app **cannot** read the Clave Disk and a thief with the powered-off disk gets
nothing — both verified with user-mode hooks disabled (kernel-authoritative). Remote wipe
destroys the enclave and leaves personal data intact.

---

## Phase 4 — App-subsystem virtualization + process supervision (the hard Windows core)

**Goal:** native work apps actually contained. See [02](02-process-supervision.md),
[03](03-app-subsystem-virtualization.md).

- [ ] Windows **process-notify driver** (Job Objects, supervised set, inverted-call to daemon).
- [ ] **Shim injection** (suspended-create + APC) + `Nt*` hooks: registry COW, namespace
      prefixing, FS redirection. Minifilter backstops (Phase 3) make it fail-closed.
- [ ] macOS: per-app container/HOME launch profiles + ES inheritance + allow-list gating
      (the doc 03 §5 substitute for injection).
- [ ] Stand up the **app-compat matrix + "learn" mode** (doc 03 §6) — this is where the long
      tail of effort lives.

**Exit:** Office, Chrome/Edge, Slack, Acrobat boot inside the zone, persist only to the Clave
Disk, run as two independent instances (work + personal) on Windows, and leak nothing on exit.

---

## Phase 5 — DLP surface: clipboard, screen capture, border, hardening

**Goal:** the user-visible controls + production-grade enforcement. See docs
[05](05-clipboard-dlp.md), [07](07-screen-capture-protection.md), [09](09-visual-border-overlay.md).

- [ ] Clipboard broker + per-process gate (win, hard) / monitor-tag-sanitize (mac, ◐).
- [ ] Screen-capture exclusion via shim `SetWindowDisplayAffinity` (win, ✅) / ES exec-deny +
      reactive (mac, ◐).
- [ ] **Clave Edge** overlay (both).
- [ ] Promote the Windows net classifier from **WinDivert → WFP callout driver** for production.
- [ ] **Anti-tamper** (doc 01 §8): `ObRegisterCallbacks`, watchdog re-arm, PPL if attainable.

**Exit:** copy work→personal blocked (win hard / mac best-effort + audited); screenshots exclude
work windows (win) / are deterred+audited (mac); every work window framed; killing the daemon
fails closed.

---

## Phase 6 — Optional hardening (per-customer, decided deliberately)

**Goal:** close the residual ◐ holes for customers who need (and will tolerate the stability
cost of) them.

- [ ] Windows **keyboard filter driver** (doc 06) for input isolation — only if a regulated
      customer requires it; high stability/scrutiny cost.
- [ ] **Server Silos** instead of Job-Objects + hooks (doc 02/03) for stronger kernel-level
      namespace isolation — evaluate against the app-compat matrix.
- [ ] WHQL/HLK certification for broader driver distribution.

**Exit:** a documented, customer-selectable hardening tier; the default product stays at the
Phase 5 enforcement level with honest ◐ labels.

---

## Sequencing rationale (why this order)

| Decision | Why |
|----------|-----|
| Core + mock **first** | Tests the security brain with zero signing friction; 70% of risk retired cheaply. |
| **Network** as the first real slice | ✅ on both OSes, supported APIs, mostly shared Rust, demoable value, exercises NE entitlement — high reward / low risk. |
| Encrypted disk + **minifilter before** the big driver | First kernel-authoritative win; smaller, simpler signed component to cut teeth on the driver pipeline. |
| App-virtualization **mid**, not first | Highest effort + app-compat long tail; do it once the supporting kernel/FS layers exist to back it fail-closed. |
| DLP surface **late** | Depends on injection (screen/clipboard) and the overlay; lower marginal risk once the core boundary exists. |
| Input filter **last/optional** | Worst stability-risk-to-value ratio; many customers won't justify it. |

---

## Definition of done (product-level)

The architecture acceptance criteria in [00 §7](00-architecture-overview.md) all pass on a
clean device matrix:

- Windows 10 2004+ / Windows 11 (x64) — full enforcement tier.
- macOS 13+ (Apple Silicon + Intel) — monitor/authorize tier with honest ◐ labels on
  clipboard, screen, input.
- Both: encrypted-at-rest, static-IP egress, fail-closed on daemon kill, remote wipe, Blue
  Border, privacy-by-schema audit.

---

## Risk register (top 5)

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Apple ES entitlement delayed/denied | Med | **Blocks mac core** | Apply day 0; have a contractor-only fallback feature scope; engage Apple DTS |
| Windows driver signing slips | Med | Blocks kernel-authoritative controls | EV cert + dashboard day 0; minifilter (small) before big driver |
| App-compat long tail (Phase 4) | **High** | Schedule overrun | "Learn" mode + per-app profiles + regression harness; budget generously |
| AV/EDR flags the shim/driver | High | Field failures | Allow-listing partnerships; supported APIs; exclusion guidance |
| macOS DLP under-delivers vs Windows | **High (certain)** | Customer trust | Honest ◐ labeling in product + sales; lead with network + at-rest (✅) on mac |

---

This completes the main sequence. See the appendices for quick-reference primitive tables and
the reading list:

- [Appendix A — Windows Primitives](appendix-a-windows-primitives.md)
- [Appendix B — macOS Primitives](appendix-b-macos-primitives.md)
- [Appendix C — References & Reading List](appendix-c-references.md)
- [Glossary](GLOSSARY.md)
