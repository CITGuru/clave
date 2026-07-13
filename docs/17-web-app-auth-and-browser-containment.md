# 17 — Web-App Auth & Browser Containment

How work **websites** join the enclave, and how a user reaches them **without handling a
credential**. This document defines the *persona profile* (a contained browser data root), the
**web-app rule** that opens a URL inside one, and the **auth tiers** that supply the persona's
session.

The one-sentence version: **the browser profile *is* the credential.** Clave does not vault
passwords and does not replay cookies between machines — it binds a session to a contained,
hardware-sealed profile on the enrolled device, and grants or shreds *that*.

---

## 1. The problem

Two user stories, one mechanism.

| Story | What the company wants |
|---|---|
| **Employee SSO.** The company already federates its SaaS through an IdP (Okta / Azure AD / Google, fronted by WorkOS — see [doc 15](15-identity-and-enrollment-auth.md)). | The employee opens work web apps and is already signed in, inside the work zone. |
| **Contractor / VA.** A virtual assistant must operate `support@` in Gmail and issue refunds in Stripe. | The VA can *use* the accounts without ever learning a password, and access dies the moment the device is revoked. |

Both reduce to: *a browser is authenticated to a work app, and the human driving it never holds
the secret.*

### 1.1 What we deliberately do **not** build

**✗ NOT-VIABLE — cross-device cookie replay.** The obvious design — capture a session server-side,
inject the cookie into the user's browser — is precisely the infostealer pattern, and the large
providers defend against it. A session presented from a new device/IP fingerprint is challenged;
Chrome's **Device Bound Session Credentials** (DBSC) explicitly binds cookies to a TPM-resident key
so a lifted cookie is inert off-device. Building on cookie replay means building against the
direction of the platform, and it fails *progressively* — the worst failure mode, because it looks
like it works.

**✗ NOT-PREFERRED — password vault + form autofill.** Typing a secret into the page's DOM makes it
readable from devtools and from the page itself. Where a credential must be replayed at all, it is
replayed **once**, into a contained profile, under [§5](#5-tier-3--assisted-bootstrap) — never as a
routine per-login autofill.

The inversion that makes this tractable: **do not move the secret to the device — mint the session
*on* the device, once, and contain it.** DBSC then works *for* us: the profile is device-bound
precisely because it was born on the enrolled, hardware-rooted device. Clave already has the
hardware key custody DBSC wants (Secure Enclave / TPM — [doc 04 §2](04-encrypted-volume.md)).

---

## 2. The persona profile

> **Persona** — a browser data root (cookie jar, storage, extensions) that lives inside the Clave
> Disk and represents **one identity**. It is the unit of authentication, isolation, and
> revocation.

### 2.1 The unit is the identity, not the app

The instinct is one profile per web app. **That breaks SSO.** Federation exists so that *one* IdP
session cookie is reused across many service providers. Give Gmail and Notion separate cookie jars
and the IdP session cannot carry between them — the user re-authenticates to the IdP for every app,
which is the opposite of the product.

So:

| Persona | Holds | Example |
|---|---|---|
| The user's **work identity** | The IdP session; every federated app rides it | `work` — the VA signed into WorkOS as themselves |
| Each **shared / delegated account** | That account's session only | `ops-stripe`, `support-mailbox` |

Federated apps **share** the work persona (SSO does its job). Each shared account is its **own**
persona so it never commingles with the user's identity and can be revoked independently.

The auth tier ([§3](#3-auth-tiers)) is therefore a property of the **persona**, not of the app —
a cleaner policy object, and it maps one-to-one onto revocation.

### 2.2 A profile is a `--user-data-dir`, not a Chrome "profile"

⚠ **Chrome's person-picker profiles are not a security boundary.** Multiple Chrome profiles inside
one user-data-dir share a process and a data root; Chrome does not treat them as an isolation
boundary. The persona must be a distinct **`--user-data-dir`**.

`clave-core` already emits exactly this — `ContainerKind::Chromium`
(`crates/clave-core/src/app.rs`) resolves a launch to:

```
--user-data-dir=<mount>/<user>/profiles/<sub>
--no-first-run
--no-default-browser-check
```

…rooted **inside the Clave Disk**. Chromium, Edge, and Brave take `--user-data-dir`; Firefox takes
`-profile`. The `ContainerKind` enum is the seam for that per-engine difference.

### 2.3 What makes it a boundary

`--user-data-dir` alone is *separation*, not containment — the cookie jar is a file any local
process can read (Chrome's Safe Storage key is reachable from the user's own login keychain). What
upgrades it to a boundary is Clave's own layer, all of which already exists:

| Property | Mechanism |
|---|---|
| At rest, the cookie jar is ciphertext | The profile dir is inside the Clave Disk ([doc 04](04-encrypted-volume.md)) |
| A non-supervised process cannot open it | ES `AUTH_OPEN` gate over the profile path ([doc 02](02-process-supervision.md), [doc 04 §4.2](04-encrypted-volume.md)) |
| Revocation is instant and total | Crypto-shred the persona's dir / the container DEK ([doc 04 §6](04-encrypted-volume.md)) |
| The gateway cannot impersonate the user | The DEK is sealed to the **device's** hardware key; the gateway holds nothing that can open it |

That last row is the property worth defending in a sales conversation: **the gateway can grant and
revoke, but it can never *impersonate*.**

---

## 3. Auth tiers

Every persona declares **how its session comes to exist**. Prefer the lowest number that the target
app supports — the tiers are ordered by how much real secret ever exists outside the IdP.

| Tier | Name | Who authenticates | What Clave holds | Use when |
|---|---|---|---|---|
| 1 | **Federated** | The user, as themselves, to the IdP | *Nothing* | The app supports SAML/OIDC SSO |
| 2 | **Delegated** | An admin, once, granting scoped access | A scoped, revocable token — not a credential | The app has native delegation (Google delegated mailbox / domain-wide delegation; Stripe team roles) |
| 3 | **Assisted bootstrap** | An admin, once, *on the user's device* | A device-bound session in the contained profile | Neither of the above exists (long-tail SaaS with one shared login) |

**Tier 1 is the goal state and handles the entire employee-SSO story with zero credential
handling.** The user signs into WorkOS in the work persona; every federated app SSOs off that
session.

**Tier 2 is the right answer for the two apps most often cited** — Gmail and Stripe both have
sanctioned delegation (Google delegated mailboxes / domain-wide delegation; Stripe team members with
scoped roles). Where native delegation exists it beats anything Clave can do with sessions:
revocation is "delete the grant," the audit trail is the provider's own, and shared-credential
access arguably violates the provider's terms. **Tier 3 is a fallback, not the headline.**

---

## 4. Policy schema

Web apps extend the policy bundle alongside `AppPolicy`, mirroring `AppRule`
(`crates/clave-core/src/app.rs`).

```rust
// SKETCH — crates/clave-core/src/web.rs

pub struct ProfileId(pub String);

/// A contained browser data root representing one identity. The unit of auth and revocation.
pub struct PersonaRule {
    pub profile_id: ProfileId,
    pub display_name: String,
    /// Which browser engine hosts this persona (selects --user-data-dir vs -profile).
    pub engine: BrowserEngine,
    /// How this persona's session comes to exist.
    pub auth: AuthTier,
    /// Hardening applied to the profile — see §6. Not optional in production.
    pub hardening: ProfileHardening,
}

pub enum AuthTier {
    /// The user signs into the IdP as themselves; federated apps ride that session.
    Federated,
    /// An admin's one-time grant; Clave holds a scoped, revocable token.
    Delegated { grant_ref: String },
    /// An admin authenticates once, on this device, behind a protected surface (§5).
    AssistedBootstrap,
}

/// A work website. Opens `url` inside `profile`.
pub struct WebAppRule {
    pub app_id: AppId,
    pub display_name: String,
    pub url: String,
    pub profile: ProfileId,
}

pub struct WebPolicy {
    pub personas: Vec<PersonaRule>,
    pub web_apps: Vec<WebAppRule>,
}
```

`WebPolicy` joins `PolicyBundle` (`crates/clave-core/src/policy.rs`) as a `#[serde(default)]`
field, so it rides the **existing tenant-signed distribution path** — the gateway's `PolicyIssuer`
signs it, the device's pinned-key `GatewayVerifier` accepts it ([doc 10 §2](10-policy-engine-and-ipc.md)).
**The admin toggle is not a new subsystem**: enabling a web app for a role is a policy edit that
syncs down the channel that already exists.

### 4.1 Launch resolution

A `WebAppRule` resolves to a `LaunchSpec` exactly as a native `AppRule` does — the executable is the
browser, the profile dir is the persona's, and the URL is an argument:

```
executable: <the allow-listed browser binary>
args:       --user-data-dir=<mount>/<user>/profiles/<persona>
            --app=<url>
            --no-first-run --no-default-browser-check
```

`--app=<url>` gives a chromeless app window — no address bar to navigate out of the work app with,
and the window is one the Clave Edge overlay can frame ([doc 09](09-visual-border-overlay.md)) like
any other work window.

The browser binary itself must be in the signed app allow-list (`BinaryMatch`) and is launched
**supervised**, so its children and its file access are in-zone.

---

## 5. Tier 3 — assisted bootstrap

The hard case, stated honestly: *someone still has to authenticate.* For an app with no SSO and no
delegation, a human who **knows** the credential must sign in once — and the user must not learn it.

Everyone else solves this by **shipping pixels from a remote browser** (Teleport / Guacamole /
CyberArk-style RBI): the session lives on a server, the user gets a video stream. That is a
separate hosting product, and it contradicts Clave's entire thesis (no VDI, no streamed desktop, no
backend compute — [doc 00](00-architecture-overview.md)).

Clave can do it **locally**, because it already owns the containment layer:

1. The launcher opens the app's login page in the persona profile **on the user's device**.
2. Clave marks that window **screen-capture-excluded** ([doc 07](07-screen-capture-protection.md))
   and **input-isolated** ([doc 06](06-input-isolation.md)) — the user's own screen recorder and
   keyloggers cannot observe it.
3. The admin authenticates into that surface (in person, or via a remote-assist channel).
4. The session mints **on the enrolled device**, in the contained profile, sealed to the device's
   hardware key. DBSC binding, if the provider uses it, binds to *this* device — correctly.
5. The credential is never persisted. The **profile** is the durable artifact.

Thereafter the session renews silently, and revocation is a crypto-shred.

> ⚠ **Tier 3 is gated on subsystems that are not yet enforced.** Per `STATUS.md`, screen-capture
> protection and input isolation are currently `Unavailable` on macOS. Assisted bootstrap is
> **not implementable** until those land — its entire security argument rests on them. Tiers 1 and 2
> have no such dependency and can ship first.

### 5.1 Residual risk to state plainly

If a persona holds a live session to the company's most sensitive SaaS, **the device becomes a
high-value target**. This is inherent to the problem, not to this design — but the mitigation must
be stated, not implied:

- The session is sealed to the device's hardware key; **a gateway breach yields no sessions.**
- Every bootstrap and every launch is an auth event and lands in the **hash-chained audit spool**
  ([doc 10 §6](10-policy-engine-and-ipc.md)) — tamper-evident, and the gateway detects suppression.
- Revocation is **remote wipe**, which already exists and is already Ed25519-authenticated.

**◐ BEST-EFFORT — TOTP.** If Clave were also to hold TOTP seeds for a tier-3 persona, it would hold
*full account-takeover capability* for that account. That concentration is a real posture change and
must be an explicit, per-persona admin decision — not a default.

---

## 6. Hardening the profile

⚠ **Without this section, the containment is decorative.** A contained profile that the user can
sign into their *personal* Google account will have its cookies and saved passwords **synced
straight out** to that account by Chrome Sync. Devtools can read the cookie jar directly.

Command-line flags **cannot** be trusted for this — the user can relaunch the browser themselves
with different flags. Enforcement must come from **managed preferences**, which apply machine-wide
regardless of `--user-data-dir`:

| Control | macOS (`/Library/Managed Preferences/com.google.Chrome.plist`) | Why |
|---|---|---|
| `BrowserSignin = 0` | Sign-in disabled | Blocks attaching the profile to a personal account |
| `SyncDisabled = true` | Chrome Sync off | **The exfiltration channel.** Closes cookie/password sync-out |
| `DeveloperToolsAvailability = 2` | Devtools disallowed | Devtools reads the cookie jar |
| `PasswordManagerEnabled = false` | No saved passwords | The profile is the credential; nothing else should persist one |
| `ExtensionInstallForcelist` | Pins the Clave extension | The daemon channel (§6.1) |
| `URLBlocklist` / `URLAllowlist` | Scope the persona | A tier-3 persona should reach *its app*, not the open web |

The Windows equivalents are the same policies under
`HKLM\SOFTWARE\Policies\Google\Chrome` — see [appendix A](appendix-a-windows-primitives.md).

Deployment of the managed-preferences file is an MDM/installer concern
([doc 12](12-signing-distribution-deployment.md)).

### 6.1 The daemon channel

Where the browser must talk to the daemon (bootstrap orchestration, session-state signals), use a
**Clave-signed extension over native messaging** — the same trust shape as the existing `clave-ipc`
peer-authenticated link ([doc 10 §3](10-policy-engine-and-ipc.md)).

⚠ **Do not drive the browser over a remote-debugging port.** An open CDP port is a standing local
vulnerability: any process on the box can attach and lift every cookie in the profile, which
defeats the entire boundary this document builds.

---

## 7. What this unlocks beyond auth

Auth is the wedge; **containment is the product.** Once a work website runs in a Clave-managed
persona profile, the rest of the enclave applies to it for free:

| Subsystem | What it now covers |
|---|---|
| [Clipboard DLP](05-clipboard-dlp.md) | Copy-out from the web app is brokered, not free |
| [Screen capture](07-screen-capture-protection.md) | The work window is capture-excluded |
| [Split tunnel](08-network-split-tunnel.md) | The web app's traffic egresses the company's static IP |
| [Clave Edge](09-visual-border-overlay.md) | The window is visibly in-zone |
| [Clave Disk](04-encrypted-volume.md) | Downloads land inside the encrypted volume |

A VA's Stripe session is not merely *authenticated* — it is in the work zone, with copy-out
brokered, downloads encrypted, and traffic egressing the company's IP.

---

## 8. Build order

Sequenced so that **the tier-1 story ships with zero credential handling**, and nothing early
depends on the unenforced subsystems.

| Phase | Work | Delivers | Blocked on |
|---|---|---|---|
| **A** | `WebPolicy` / `PersonaRule` / `WebAppRule` in `clave-core`; resolve web apps through the existing `prepare_launch`; fill in the launcher's **Websites** section (today a placeholder in `full-view.tsx`) | **Tier 1 SSO, end to end.** No secret ever touches Clave | — |
| **B** | Managed-preferences hardening (§6); ES `AUTH_OPEN` gate over the profile dir; per-persona crypto-shred | The profile becomes a **boundary**, not just separation | ES entitlement ([doc 14](14-production-and-development-platform-requirements.md)) |
| **C** | Clave-signed extension + native-messaging channel (§6.1) | Bootstrap orchestration; session-state signals | Phase A |
| **D** | Tier 2 delegated grants (Google DWD, Stripe roles) at the gateway | The **VA story**, via the *sanctioned* provider path | Gateway admin surface |
| **E** | Tier 3 assisted bootstrap (§5) | The long-tail fallback | **Screen-capture protection + input isolation** — currently `Unavailable` |

Phase A is a small extension of machinery that already exists: `ContainerKind::Chromium` already
emits the contained `--user-data-dir`, `classify_path` already places it in the work zone, and
`PolicyBundle` already syncs tenant-signed from the gateway. The **Websites** section in the
launcher is already there, waiting for a model to render.
