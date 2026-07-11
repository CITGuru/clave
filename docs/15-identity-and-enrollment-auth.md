# 15 — Identity, Workspaces & Enrollment Auth

How a human proves who they are to Clave's **control plane** — to manage a workspace from the
admin console, and to enroll a device. This is the **gateway's identity layer**, the
`Policy/Identity Service` that [doc 00 §3](00-architecture-overview.md) draws in the cloud and
marks `(out of scope)` for the device workspace. This document brings it in scope.

The product requirement: **email login on a work email that has been invited to the workspace,
with the option to bring your own SSO (Okta/Entra/Google).**

---

## 1. The one trust principle (read this first)

Clave is a device-level security product. Its runtime posture is anchored on things the kernel
and hardware vouch for — the **pinned tenant key**, the **hardware-rooted device key**, and the
**signed, versioned policy bundle** ([doc 10 §2](10-policy-engine-and-ipc.md)). Human identity
does **not** join that trust root.

> **User identity gates _enrollment_ and _console access_. It never becomes a _runtime_ trust
> anchor.** A stolen session token cannot change device posture; only a signed gateway command
> against the pinned key can. This keeps the threat model in [doc 01](01-threat-model.md) intact
> while still requiring a real human to sign in.

Consequence for deprovisioning: when SCIM (or an admin) removes a user, their membership goes
**suspended**; the device cannot *refresh* policy or *re-enroll*, and stale policy fails closed on
`not_after` ([doc 10 §2](10-policy-engine-and-ipc.md)) — no scramble to revoke a long-lived token.

---

## 2. Components

```
┌──────────────────────────── CLOUD ────────────────────────────────────────────┐
│  apps/clave-console (React/Vite/Shadcn)   ──HTTPS──►  crates/clave-gateway      │
│     admin UI: members, devices, policy, audit          Axum + Postgres (sqlx)    │
│                                                            │                     │
│                                   ┌────────────────────────┼──────────────┐     │
│                                   ▼ IdentityProvider seam   ▼ clave-identity│     │
│                              WorkOS (AuthKit / SSO / SCIM)  (portable authz)│     │
│                                   │ Org = workspace                          │     │
└───────────────────────────────────┼──────────────────────────────────────────┘
                                     │ enrollment artifacts (clave-proto)
════════════════════════════════════╪════════════════════════════════════ device ══
                                     ▼
                           clave-daemon  (device-code enrollment → policy + wrapped key)
```

| Piece | Lives in | Role |
|-------|----------|------|
| **`clave-identity`** | `crates/clave-identity` | **Portable, `#![forbid(unsafe_code)]`, no-I/O** authorization brain: who may log in / accept an invite / enroll. Pure + proptested, like `clave-core::decide`. |
| **`clave-gateway`** | `crates/clave-gateway` | Axum service + Postgres. Owns the schema, the WorkOS integration, the console session, the device-code enrollment endpoints, audit ingestion, and signing gateway commands. |
| **`clave-console`** | `apps/clave-console` | React/Vite/Shadcn/Tailwind admin app. |
| **WorkOS** | external | AuthKit (email magic-link / password), SSO (Okta/Entra/Google via OIDC/SAML), Directory Sync (SCIM). One WorkOS **Organization per workspace**. |

**Why WorkOS, not hand-rolled SAML.** "Bring your own Okta" is a long tail of SAML/OIDC/SCIM
edge cases. WorkOS productizes exactly email-invite + per-org IdP connections + directory
deprovisioning. We keep it behind an `IdentityProvider` trait so tests (and a future
self-hosted IdP) don't depend on it.

**Synergy:** the same Okta tenant already does network **conditional access** via the static
egress IP ([doc 08 §154](08-network-split-tunnel.md)). Login SSO + IP conditional access = one
identity story per customer.

---

## 3. Data model (Postgres)

```sql
-- A workspace IS a tenant. workspace.id is the value used as clave_proto::TenantId
-- when the gateway issues a policy bundle to an enrolled device.
workspace(
  id              bigint primary key,
  name            text not null,
  workos_org_id   text unique,              -- WorkOS Organization
  allowed_domains text[] not null default '{}',  -- empty => pure invite-only
  sso_mode        text not null default 'optional', -- 'optional' | 'required'
  created_at      timestamptz not null default now()
)

app_user(
  id            bigint primary key,
  email         citext unique not null,     -- normalized, case-insensitive
  name          text,
  workos_user_id text unique,               -- null until first WorkOS login
  created_at    timestamptz not null default now()
)

membership(                                  -- the "invited to the workspace" gate
  workspace_id  bigint references workspace(id),
  user_id       bigint references app_user(id),
  role          text not null,              -- 'owner' | 'admin' | 'member'
  status        text not null,              -- 'invited' | 'active' | 'suspended'
  invited_by    bigint references app_user(id),
  joined_at     timestamptz,
  primary key (workspace_id, user_id)
)

invitation(                                  -- pending invite before the user exists
  id            bigint primary key,
  workspace_id  bigint references workspace(id),
  email         citext not null,
  role          text not null,
  expires_at    timestamptz not null,
  accepted      boolean not null default false
)

device(                                      -- binds device -> user -> workspace
  id             uuid primary key,
  workspace_id   bigint references workspace(id),
  enrolled_by    bigint references app_user(id),
  device_pubkey  bytea not null,            -- Ed25519, the runtime trust anchor
  status         text not null,             -- 'pending' | 'active' | 'locked' | 'wiped'
  policy_version bigint,
  enrolled_at    timestamptz not null default now(),
  last_seen      timestamptz
)
```

The Postgres rows hydrate the pure `clave-identity` value types (`Workspace`, `Membership`,
`Invitation`); the gateway calls the pure functions to decide, then persists the result.

---

## 4. Flow A — admin console login (browser)

```
admin opens console ─► WorkOS AuthKit hosted UI
        │                  • work email → magic-link / password, OR
        │                  • "Sign in with SSO" → workspace's Okta connection
        ▼
WorkOS returns auth code ─► gateway exchanges → {workos_user_id, email, org,
        │                                          access_token (short JWT), refresh_token}
        ▼
gateway: clave_identity::authorize_login(email, method, &workspace, membership)
        │   Deny(NotAMember | Suspended | DomainNotAllowed | SsoRequired) → 403
        ▼ Allow{role}
gateway seals {access_token, refresh_token} into an httpOnly+Secure+SameSite cookie.
```

The membership check is **authoritative**: even a successfully WorkOS-authenticated user is
rejected unless they are an `active` member (or accept a valid invitation). Domain policy is
enforced as defense in depth.

### 4.1 Who issues the session

**WorkOS does the console authentication too.** It is not just for SSO — AuthKit issues the
session tokens for *every* sign-in method:

| Concern | Owner |
|---------|-------|
| Authentication (login UI, email magic-link / password / SSO→Okta), and the **token lifecycle** (short-lived access **JWT** + rotating **refresh token**) | **WorkOS** |
| **Authorization** — the invited-only / role / suspension decision (`clave-identity` over our `membership` table, source of truth, synced from SCIM) | **gateway** |
| **Session carrier** — sealing WorkOS's tokens into the cookie and validating each request | **gateway** |

So we do **not** hand-roll credential issuance: WorkOS mints the access JWT + refresh token; we
verify the JWT against WorkOS's **JWKS**, refresh when it expires, and re-run the cheap
**active-membership** check per request so a SCIM-suspended user is locked out immediately, not
only at the next refresh. There is no official WorkOS **Rust** SDK, so the gateway calls the
WorkOS REST API directly and owns the cookie itself.

Default carrier: a **sealed cookie** (encrypt {access, refresh} into one httpOnly cookie —
WorkOS-idiomatic, no session table). Swap to **opaque server-side sessions** only if instant
global revocation is required.

---

## 5. Flow B — device enrollment (the daemon, no browser)

A root daemon shouldn't host a login form. Use the **OAuth 2.0 Device Authorization Grant**:

```
daemon ─► gateway POST /enroll/start ──► returns {user_code, verification_uri}
        │  (daemon opens the system browser to verification_uri, shows user_code)
        ▼
user authenticates at WorkOS (email / Okta) in their browser
        ▼
gateway: clave_identity::authorize_enrollment(&workspace, membership)
        │   Deny → enrollment refused
        ▼ Allow{workspace, role}
daemon polls /enroll/poll ─► on approval the gateway records the device (pubkey↔user↔workspace)
        and returns the doc 00 §5.1 step-3 artifacts:
          • signed PolicyBundle (clave-proto, pinned-key verifiable)
          • wrapped volume key (to the device's TPM/Secure Enclave root)
          • WireGuard config
        ▼
from here the device runs on its hardware-rooted key + pinned tenant key. Identity was the gate.
```

---

## 6. The `IdentityProvider` seam

Mirrors `GatewayLink`/`LoopbackLink` and `KeyStore`/`MemKeyStore`: a trait the gateway depends
on, a mock for tests, a WorkOS impl behind a feature.

```rust
pub trait IdentityProvider: Send + Sync {
    fn begin_device_auth(&self, ws: WorkspaceId) -> Result<DeviceAuth, IdpError>;
    fn poll_device_auth(&self, code: &DeviceCode) -> Result<Option<VerifiedUser>, IdpError>;
    fn exchange_console_code(&self, code: &str) -> Result<VerifiedUser, IdpError>;
    fn on_directory_event(&self, ev: ScimEvent) -> Result<MembershipDelta, IdpError>; // SCIM
}
// VerifiedUser { email, workos_user_id, workspace_hint } — already proven by the IdP.
// clave-identity then decides whether that verified human is allowed in.
```

---

## 7. Authorization model (roles)

Roles are ordered `Member < Admin < Owner`; `can(role, action)` is **monotonic** (a higher role
can do anything a lower one can). Pinned by proptest.

| Action | Min role |
|--------|----------|
| Enroll one's own device | Member |
| Manage members / invites, change roles, edit policy, manage SSO, lock/wipe a device, view audit | Admin |
| Delete workspace / transfer ownership | Owner |

(Ownership transfer's finer nuance — only an Owner may mint another Owner — lives in the service
layer; the pure `can()` is the coarse gate.)

---

## 8. Security invariants (proptest, `clave-identity`)

Pinned for all inputs, the way [doc 11 §6](11-rust-workspace-layout.md) pins `decide`:

- A **non-member never** logs in or enrolls — for any email/method/workspace.
- A **suspended** member is never authorized (login or enrollment).
- An **expired** invitation never accepts (fail-closed), regardless of other fields.
- Email/domain matching is **case- and whitespace-insensitive** (normalization).
- An **SSO-required** workspace denies every non-verified-SSO sign-in.
- `can()` is **monotonic** in role.
- Accepting an invitation yields an `active` membership with the invitation's role, and only when
  the email matches, it is unexpired, and it is unaccepted.

---

## 9. Build roadmap

1. ✅ **`clave-identity` portable core** — types + fail-closed authz + proptests.
2. ✅ **`clave-gateway` control-plane core** — `IdentityProvider` + `Store` seams with mock/in-memory
   doubles; the `Gateway` orchestration (console login, invitation acceptance, per-request
   authorization, device enrollment) over `clave-identity`.
2b. ✅ **Gateway HTTP + real adapters** — Axum router + sealed-cookie sessions (`http` module);
   `PgStore` (sqlx, `postgres` feature) + migration; `WorkosProvider` (reqwest + JWKS, `workos`
   feature); the `clave-gateway` server binary (`server` feature). HTTP handlers tested over the
   mock seams; the adapters are compile-verified (they need a live Postgres / WorkOS to run).
3. **WorkOS integration, live** — run against a real WorkOS env: confirm endpoint shapes, the
   org→workspace lookup backed by `workspace.workos_org_id`, and the **SCIM webhook → membership**
   suspend/restore path.
4. **`apps/clave-console`** — Vite/Shadcn/Tailwind: login, members (invite/role/suspend),
   devices (list/lock/wipe), audit.
5. **Daemon enrollment** — wire `clave-daemon` to the device-code flow over the existing
   `clave-proto` transport; issue policy + wrapped key + WireGuard config on Allow.
