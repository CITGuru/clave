# 19 — AI Gateway

The work zone's contained agents — Claude Code, Cursor, Copilot, an MCP host — reach model providers
through **Clave's gateway**. Two things happen there, and this document covers both:

- **The data path** ([§3](#3-the-data-path-inspect-the-request-observe-the-response)) — the agent's
  outbound prompt is inspected (DLP: block a secret before it leaves the device), and its response is
  observed (usage + traces, never blocked).
- **The control plane** ([§4](#4-the-control-plane-managed-authentication)–[§5](#5-governance-model-access-budgets-attribution))
  — the agent is authenticated by the gateway **brokering the company's real provider credential**, so
  the user never holds a model key; and the same broker governs which models a role may run and how
  much it may spend.

The one-sentence version: **the work agent's model endpoint is Clave's.** A passthrough proxy scans the
outbound prompt and blocks a secret before it reaches the model, the gateway attaches the company's
real key so the user never authenticates, and every call is metered, model-scoped, and recorded — with
the [split tunnel](08-network-split-tunnel.md) as the backstop for anything that tries to go around it.

---

## 1. Two problems, one chokepoint

A contained AI agent creates two problems at once, and both are solved at the same place — the endpoint
the agent is pointed at.

**Problem one: an agent is a process with initiative.** The enclave was built to govern how a **human**
moves work data across the boundary ([doc 05](05-clipboard-dlp.md)–[07](07-screen-capture-protection.md)).
An agent is the same problem with more autonomy: it reads the work tree and *decides on its own* to put
a file in a prompt and send it to a model. Every channel it uses already maps onto a primitive Clave has:

| What the agent does | Primitive that already governs it |
|---|---|
| Reads work source → streams it to `api.anthropic.com` / `api.openai.com` | `classify_flow` + [split tunnel](08-network-split-tunnel.md): a work-zone process making an egress flow |
| Pastes a secret into a chat prompt | This document — request inspection on the model egress (§3) |
| Slurps `.env` / a key file into context | This document — the highest-frequency real leak, and the one regex catches best (§3.3) |
| Is spawned by a work app, inheriting Clave-Disk reach | `classify_exec` on children + `LaunchProfile` contained HOME ([doc 17 §4.1](17-web-app-auth-and-browser-containment.md)) |

**Problem two: API keys on BYOD are a custody disaster.** The status-quo way an employee uses an agent
is `export ANTHROPIC_API_KEY=sk-…` in a dotfile on their **personal, unmanaged** machine. Every property
a company wants is now broken:

| Want | Broken by a key in a dotfile |
|---|---|
| **Custody** | A long-lived company secret sits in plaintext on a device IT does not own |
| **Rotation** | Rotating means chasing every employee's dotfile |
| **Attribution** | The provider bill is one key; you cannot tell who spent it |
| **Revocation** | Off-boarding leaves the key on a laptop that walked out the door |

Both reduce to a single control point: the model endpoint the contained agent talks to. Own that
endpoint and you can inspect what leaves, authenticate without handing over a key, and meter every call.

---

## 2. The position: the agent's endpoint is ours

The mechanism that makes this enforceable on an **unmanaged** machine — where we cannot install a
corporate root CA and MITM TLS — is that Clave already owns the contained agent's **launch environment**.
`LaunchProfile` ([doc 17 §4.1](17-web-app-auth-and-browser-containment.md)) resolves a supervised app's
HOME/temp/env inside the work zone; it also injects the model base URL **and** a device token:

```
ANTHROPIC_BASE_URL = http://127.0.0.1:<port>/anthropic
ANTHROPIC_API_KEY  = clave-dev-<short-lived device token>      # not a provider key (§4.2)
```

…pointing the **work-zone** agent at a loopback proxy the daemon hosts, and "authenticating" it without
the user doing anything — while the employee's **personal** Claude Code on the same machine is untouched.
No MITM: the agent opts in by configuration, and we own the configuration.

```
  contained work agent          daemon loopback (§3)          company gateway (§4–5)         model
  env-injected by LaunchProfile:  inspect request (DLP)        verify device · attach the
    ANTHROPIC_BASE_URL=…            observe response (usage)    company's real provider key
    ANTHROPIC_API_KEY=<device tok>  │                          meter tokens · attribute
        │  request + device token ──►  block│redact│alert ─pass─►  (mTLS tunnel) ─► attach key ─►  api.*
        │  ◄──── 4xx + reason (blocked) ─────┘
        │  ◄─────────── response streams back — observed (usage + traces), never gated ─────────────
```

What each hop holds and sees:

- **The device** holds a short-lived token, useless off-device and expiring — never a provider key (§4.2).
- **The daemon** inspects the request (block/redact/alert, §3) and observes the response (usage + traces,
  §3.2), then forwards over the existing **mTLS** link ([doc 10 §2](10-policy-engine-and-ipc.md),
  `clave-proto`'s `mtls`/`transport`).
- **The gateway** holds the real credential, verifies the device, attaches the key, meters usage, and
  attributes the call to a specific user + device (§4–5).

**The env injection is the enforcement; the split tunnel is the backstop.** An agent that ignores the
injected base URL and dials `api.anthropic.com` directly is a work-zone process egressing to a model
endpoint that **isn't** the sanctioned loopback — `classify_flow` sees exactly that and denies or flags
it (§6). Personal AI use is **not** in this picture: only the contained work agent's traffic is injected
and routed here; personal flows stay `Direct` and unseen ([doc 01 §9](01-threat-model.md)).

---

## 3. The data path: inspect the request, observe the response

### 3.1 Enforce on the request, observe the response

The proxy is **asymmetric on purpose**, and the asymmetry is between *enforcement* and *observation* —
not between looking and not looking:

- **The request is the enforcement point.** The thing a company prevents is *work data reaching the
  model* — a key, a customer record, a secrets file in the prompt. That lives entirely in the
  **request**, which is a single POST we hold in full before it egresses, so we can scan it and
  **block / redact / alert before anything leaves the device** (§3.4). Prevention happens here, and only
  here.
- **The response is observed, never gated.** We **monitor** the response as it streams — for
  **token-usage accounting** (how much a user is spending, §3.2) and for **traces** (the request →
  response record used for analysis and debugging). We do **not** block, buffer-and-hold, or redact it:
  the bytes stream straight back to the agent untouched, so the streaming UX that is the point of
  Claude Code / Cursor is never degraded.

So: **the request can be stopped; the response can only be recorded.** Enforcement is one-directional
(outbound); observation is bidirectional.

### 3.2 What the response monitor captures

Two things, at a policy-chosen fidelity:

| Signal | What it is | Consumer |
|---|---|---|
| **Usage** | The provider's `usage` counters (input + output tokens), model, latency | Spend accounting → token budgets (§5.2) |
| **Trace** | The request → response record for a call — for analysis, debugging, *"why did the agent do that"* | The console's analysis / trace view |

**Usage is always captured** — it is a small metadata field, and it is how a company knows what a user is
spending. **Trace fidelity is a policy tier**, exactly like [doc 18 §8](18-activity-tracking-and-monitoring.md)'s
activity-tracking fidelity: the default records **metadata only** (model, tokens, latency, timestamps), and
capturing **full request/response content** is a deliberate, audited escalation — a work agent's responses
are work data, and recording them is a posture change, not a default. Personal use never routes through the
proxy at all (§2), so nothing here observes it.

### 3.3 What it catches — and what it doesn't

Regex/heuristic detection is **excellent** at *structured* secrets and *formatted* PII, and **weak** at
unstructured sensitive prose. State both plainly.

| Class | Examples | Verdict |
|---|---|---|
| Provider keys / tokens | `sk-…`, `AKIA…`, `ghp_…`, `xox[baprs]-…`, JWTs, PEM `-----BEGIN … PRIVATE KEY-----` | **✓ strong** — fixed prefixes / shapes |
| High-entropy blobs | base64/hex secrets over an entropy threshold | **✓ good** — heuristic, tune false-positives |
| Formatted PII | SSN, credit card (+ Luhn), IBAN, email | **✓ good** — anchored patterns |
| Unstructured IP | "our Q3 revenue was…", an unreleased product described in prose | **✗ regex cannot** — do not claim it |

The honest headline: **this is a credentials + formatted-PII egress filter, not general IP-DLP.** Sell "we
stop keys, tokens, and formatted PII from reaching the model," never "we stop IP leakage." The saving grace
is frequency: the single most common real-world agent leak — **an agent reading a `.env` / credentials file
into context** — is precisely the structured case the regex nails.

### 3.4 The decision model

The *decision* is portable, pure Rust in `clave-core` — proptestable, deterministic, no I/O — exactly like
`classify_flow` and `decide()`. The daemon's loopback proxy is the only thing that touches a socket.

```rust
// SKETCH — crates/clave-core/src/aidlp.rs

pub struct SecretPattern {
    pub id: String,               // "aws-access-key", "pem-private-key" — label + audit tag
    pub regex: String,            // anchored; compiled once at policy load
    pub min_entropy: Option<f32>, // optional gate to cut false-positives on high-entropy classes
}

/// What to do when a rule matches. Per-rule, so each detector class is tuned independently.
pub enum Disposition {
    /// Refuse the request; return a 4xx to the agent with a reason. Nothing leaves.
    Reject,
    /// Rewrite the match out of the body, forward the remainder (§3.6).
    Redact { mode: RedactMode },
    /// Forward unchanged, raise a console alert and audit the hit.
    Alert,
    /// Forward unchanged, record nothing — the rule is present but dormant. An off switch
    /// that keeps the pattern (and its history) rather than deleting it.
    Ignore,
}

pub enum RedactMode {
    /// Replace the span with a labelled placeholder, e.g. `[redacted:aws-access-key]`.
    Mask,
    /// Delete the span outright.
    Remove,
}

pub struct PromptRule {
    pub pattern: SecretPattern,
    /// Omit to inherit the policy `default_disposition` (§3.5).
    pub disposition: Option<Disposition>,
}

pub enum EnforcementMode {
    /// Downgrade every `Reject` to `Alert` — watch the whole ruleset fire in production
    /// without blocking anyone. The rollout posture.
    Monitor,
    /// Rules act as written.
    Enforce,
}

pub struct AiEgressPolicy {
    pub rules: Vec<PromptRule>,
    /// Global switch, flipped per tenant: `Monitor` for rollout, `Enforce` once tuned (§3.5).
    pub mode: EnforcementMode,
    /// Applied to any rule that leaves its `disposition` unset.
    pub default_disposition: Disposition,
    /// Providers whose base URL we inject and inspect; everything else is denied by the backstop (§6).
    pub sanctioned_providers: Vec<String>,
}

/// Pure. Resolves per-rule → default → monitor-mode downgrade and returns the effective action.
pub fn inspect_request(body: &[u8], policy: &AiEgressPolicy) -> InspectDecision { /* … */ }
```

`AiEgressPolicy` joins `PolicyBundle` (`crates/clave-core/src/policy.rs`) as a `#[serde(default)]` field,
so it rides the **existing tenant-signed distribution path** — the gateway's `PolicyIssuer` signs it, the
device's pinned-key `GatewayVerifier` accepts it ([doc 10 §2](10-policy-engine-and-ipc.md)). Turning on a
new detector for a role is a **policy edit**, not a new subsystem — the same property
[`WebPolicy`](17-web-app-auth-and-browser-containment.md#4-policy-schema) has.

### 3.5 Reject, alert, or nothing — and monitor mode

The disposition is the knob a security team actually turns, set per detector class:

| Disposition | Effect | Fits |
|---|---|---|
| `Reject` | Hard block; 4xx with a reason, nothing leaves | Keys, PEM private keys — high-confidence, high-severity |
| `Redact` | Strip the match, forward the rest (§3.6) | Formatted PII where partial context is still useful |
| `Alert` | Forward unchanged, raise a console alert + audit | Noisy classes worth watching, not blocking |
| `Ignore` | Forward unchanged, record nothing | A dormant rule — kept in the bundle, switched off |

A rule that omits its disposition inherits `default_disposition`, so a tenant sets one posture and
overrides only the exceptions.

The **global `mode`** sits above all of them. `Monitor` downgrades every `Reject` to `Alert`, so a tenant
turns the full ruleset on in production, watches what *would* have been blocked, tunes the false-positives,
and only then flips to `Enforce`. This is the honest-rollout posture the rest of the enclave already takes
([doc 14 §5.3](14-production-and-development-platform-requirements.md)) — and every flip is itself an
audited policy change. The alerts land on the suppression-aware surface the gateway already has
(`BACKLOG.md` NG-7).

### 3.6 Redact — mask vs. remove

`Redact` is the middle path: the request still goes, minus the secret.

- **`Mask`** replaces the span with a labelled placeholder (`[redacted:aws-access-key]`) — it keeps the
  body's shape and tells the model *a secret was here*, which a coding agent often needs to stay coherent.
- **`Remove`** deletes the span outright.

Redact is the one disposition that pays the structure tax from [§3.7](#37-scan-raw-bytes-parse-only-to-redact):
rewriting the body means locating the text span and editing it back to valid JSON. Prefer `Reject` for keys
(better refused than silently altered); reach for `Redact` on formatted PII.

### 3.7 Scan raw bytes; parse only to redact

Because the proxy is a **passthrough**, `Reject` needs only *detection* — and detection does not need to
understand the provider's JSON. Scanning the **raw request body bytes** for patterns removes all coupling to
the Anthropic Messages / OpenAI Chat / tool-call formats (the real maintenance tax), costing only a little
precision (a match inside a field name). A new provider adds a base-URL route, not a body parser.

`Redact`, on the other hand, must rewrite the body and hand back something still valid — so it needs enough
structure to replace the matched span in place without corrupting the JSON. The design keeps that path
minimal and provider-light: locate the text spans (message `content`), redact within them.

> ⚠ Prefer `Reject` and `Alert` for the portable slice; treat `Redact` as the path that pays the structure
> tax. Most classes worth stopping (keys, PEM blocks) are better refused than silently altered anyway.

---

## 4. The control plane: managed authentication

### 4.1 Broker the key, don't ship it

The same move [doc 17 §1.1](17-web-app-auth-and-browser-containment.md) makes for web sessions ("don't move
the secret to the device — mint the session *on* the device") applies to model credentials:

> **Do not put the provider key on the device. Put a short-lived, device-scoped token on the device, and
> broker the real key at the gateway.**

The agent authenticates to **Clave**, not to Anthropic. The gateway — which the agent's traffic already
traverses (§2, same trust position as the static-IP egress in [doc 08 §4.2](08-network-split-tunnel.md)) —
swaps the device token for the company's real provider credential and forwards upstream. The device never
holds anything that outlives its enrollment. The gateway sees the plaintext request (it must, to inspect it,
§3) and forwards over the existing mTLS link.

### 4.2 The device token

The token the agent carries is minted from the device's **enrollment identity**
([doc 15](15-identity-and-enrollment-auth.md)) — the same identity behind the pinned tenant key and the mTLS
client certificate:

- **Short-lived and per-device.** Rotated by the daemon; a leaked token is inert once it expires and useless
  on another device (it is bound to the mTLS client identity the gateway verifies).
- **No standing secret on disk.** The device authenticates with its enrolled client cert / hardware key; the
  bearer token is a working credential, not a durable one.
- **Revoked by device lifecycle.** Suspending or wiping the device ([doc 04 §6](04-encrypted-volume.md),
  Ed25519 `SignedCommand`) invalidates its access to the broker at the next call — off-boarding is one
  action, and it reaches the model credential too.

### 4.3 Custody, rotation, revocation

The whole reason to broker: these move from the endpoint to the company.

| Property | Where it lives now |
|---|---|
| **Custody** | The provider key is at the gateway / cloud tenant / HSM — never plaintext on the personal machine |
| **Rotation** | Rotate the `credential_ref` once at the gateway; every device picks it up with no endpoint change |
| **Revocation** | Revoke the **device**, and its model access dies with it — the same `SignedCommand` path as lock/wipe |
| **Impersonation** | The gateway can grant and revoke access, but the device token cannot mint new company secrets — the key never leaves the gateway |

### 4.4 Providers are data, mechanisms are code

Exactly as [doc 16 §2](16-third-party-network-providers.md) does for network egress: there is **no
`Anthropic` or `OpenAI` type** in the broker. Model vendors churn; the thing that varies is a base URL, a
credential handle, and an auth header shape — a small, closed set. So a provider is a vendor-neutral **config
row**:

```rust
// SKETCH — crates/clave-gateway/src/model_provider.rs

pub struct ModelProvider {
    pub id: String,                 // "anthropic-prod", "acme-bedrock" — label + key-store lookup
    pub display_name: String,
    pub upstream_base: String,      // https://api.anthropic.com, a Bedrock/Azure endpoint, …
    pub credential_ref: String,     // key-store handle; the real key is resolved from the hardware root
    pub auth: AuthShape,            // how the credential is presented upstream (header/bearer/SigV4)
    pub models: Vec<String>,        // models this provider *can* serve; a role's permitted subset is `ModelAccess` (§5.1)
}

pub enum AuthShape {
    Header { name: String },        // x-api-key: <key>
    Bearer,                         // Authorization: Bearer <key>
    AwsSigV4 { region: String },    // Bedrock
}
```

- **`credential_ref`, never an inline key.** The real secret is referenced by a key-store handle and released
  from the hardware root at use ([doc 04 §2](04-encrypted-volume.md)) — same discipline as the WireGuard
  private key and the IPsec PSK ([doc 16 §4](16-third-party-network-providers.md)).
- **Enterprise tenancies are just providers.** "Anthropic via the company's own tenant", **Amazon Bedrock**,
  **Azure OpenAI** are the strongest custody story — the key belongs to the company's cloud account — and they
  are `ModelProvider` rows like any other. Prefer them.
- Which providers/models a **role** may use is carried in the signed policy bundle, so enabling a model for a
  team is a policy edit, not a code change.

---

## 5. Governance: model access, budgets, attribution

Because every call is authenticated per device and forwarded by the gateway, the broker is the control point
security and finance actually ask for. Two policy objects ride the signed bundle, scoped per **role** — so a
contractor and an engineer differ without touching code.

### 5.1 Model-access policy — what you're allowed to run

An allow-list of provider+model pairs, a **default model**, and what happens when an agent asks for something
off-list:

```rust
// SKETCH — crates/clave-gateway/src/model_policy.rs

pub struct ModelRef { pub provider: String, pub model: String }  // ("acme-bedrock", "claude-opus-4-8")

pub struct ModelAccess {
    /// Provider+model pairs this role may reach. Empty = no model access (fail-closed).
    pub allowed: Vec<ModelRef>,
    /// What an agent gets when it names no model — the "default model" the user sees.
    pub default_model: ModelRef,
    /// What to do when an agent requests a model outside `allowed`.
    pub on_disallowed: DisallowedModel,
}

pub enum DisallowedModel {
    /// Refuse with a 4xx naming the allowed set.
    Reject,
    /// Rewrite the request to `default_model` — the agent keeps working on a sanctioned model.
    RemapToDefault,
}
```

`RemapToDefault` is the quietly powerful option: a team standardises every contained agent onto the company's
enterprise-tenant model without reconfiguring each tool. The allow-list is the same set §6's network backstop
enforces structurally, so "consumer endpoints are off-limits" holds even if an agent hard-codes a model.

### 5.2 Token budgets — what you're allowed to spend

A cap over a rolling window, scoped to a user, role, or tenant, with an explicit over-budget action:

```rust
pub struct TokenBudget {
    pub scope: BudgetScope,     // User | Role | Tenant
    pub window: BudgetWindow,   // Daily | Weekly | Monthly
    pub limit_tokens: u64,      // the cap for the window
    pub on_exhausted: OverBudget,
}

pub enum BudgetScope  { User, Role, Tenant }
pub enum BudgetWindow { Daily, Weekly, Monthly }

pub enum OverBudget {
    /// Refuse further calls until the window resets — a hard cap.
    Reject,
    /// Keep serving, but alert — a soft cap that warns without blocking work.
    Alert,
    /// Serve the rest of the window on a cheaper model.
    Downgrade { to: ModelRef },
}
```

**Metering rides the response monitor.** The usage counters come from §3.2's response observation — the
provider's `usage` (input + output tokens), captured as the response streams back and decremented against the
window's running total in Postgres. It is **accounting, not a gate**: the response is never blocked (§3.1),
only counted. A monthly budget is the common shape; `Downgrade` (Opus → Haiku for the tail of the month) keeps
people working past the cap instead of dead-stopping them.

### 5.3 The readout — "what do I have, and how much is left?"

Because access and budget live at the broker, the device can ask for its own picture: **which models this role
may run, the default, and tokens remaining in the window.** Surfaced through the launcher's `Status` request
(`BACKLOG.md` NG-11) or a broker introspection call, it answers *"what models do I have access to, what's my
monthly budget, what's my default model"* without the user reading policy.

---

## 6. The backstop: `classify_flow`

The env swap only governs an agent that **honors** the base URL. The network layer catches the rest.
`classify_flow` ([doc 08 §5](08-network-split-tunnel.md)) already decides `Tunnel | Direct | Block` per flow
for a work-zone process. Extend its work-egress rules so that:

- a **work-zone** process connecting to a **known model endpoint** that is **not** the sanctioned
  loopback/gateway is `Block` (or `Tunnel`-and-flag) — the agent cannot route around the inspector, and the
  §5.1 model allow-list is enforced structurally, not just advisory;
- **personal** flows stay `Direct` and unseen, unchanged ([doc 01 §9](01-threat-model.md)).

Belt and suspenders: inspection at the loopback, and a network-layer denial for anything that tries to skip it.

---

## 7. Honest limits

State these rather than paper over them:

- **✗ Only agents that honor the base URL** are inspected at the proxy; §6 is what covers the rest, and §6 is
  only as strong as `classify_flow`'s endpoint list.
- **✗ Regex is not semantic DLP.** Unstructured IP walks through (§3.3). An agent that base64s or compresses
  its context before sending defeats byte-level patterns — heuristics help, but do not claim completeness.
- **The real prevention is containment, not the tripwire.** Scoping the agent's *reachable* files to the
  Clave-Disk work view ([doc 17 §4.1](17-web-app-auth-and-browser-containment.md)) is what keeps a secret out
  of reach in the first place; this proxy is the egress tripwire behind it. Ship both.
- **The response is observed, not gated** (§3.1): usage and traces are recorded, but the model's output is
  never blocked — a secret that appears *in the response* is logged, not prevented.
- **◐ The gateway is a chokepoint.** If it is unreachable the contained agent cannot reach the model —
  **fail-closed**, which is correct for work data but a real UX consideration, and the same availability posture
  as static-IP egress ([doc 08](08-network-split-tunnel.md)). Offline means no work-agent inference.
- **The gateway sees work prompts.** Brokering means the gateway forwards the request, so it necessarily sees
  the content it forwards — the same trust the company already places in its egress path. Personal use never
  routes here (§2).
- **The token is only as good as the enrollment.** Its security rests on [doc 15](15-identity-and-enrollment-auth.md)
  and the hardware-rooted device identity; on the unsigned `Dev` profile the custody is the plain fallback, and
  it must report `EnforcementStatus` honestly ([doc 14 §5.3](14-production-and-development-platform-requirements.md))
  — never a silent downgrade.

---

## 8. Everything is a record

A `Reject` / `Redact` / `Alert` hit is an `AuditEvent` carrying the **`app_id`** of the agent that triggered it
(the field added in the audit schema — see `BACKLOG.md` NG-14), written to the device's **hash-chained,
tamper-evident spool** and drained to the gateway ([doc 10 §6](10-policy-engine-and-ipc.md)). A denied-in-a-loop
agent must **coalesce** rather than flood the chain — the same rate-limit the clipboard denial path uses.

The response monitor's **usage and traces** (§3.2), and per-user **model access + budget consumption** (§5),
ride the same tamper-evident stream — next to [doc 18](18-activity-tracking-and-monitoring.md)'s usage stream —
so "who sent what to which model, and how much of the budget it burned" is a record, not a guess.

---

## 9. Build order

Portable — **not** OS-gated. It rides the gateway, the classifier, the enrollment identity, the mTLS
`GatewayLink`, and the launcher env-injection that already exist.

| Phase | Work | Delivers | Blocked on |
|---|---|---|---|
| **A** | `AiEgressPolicy` / `inspect_request()` in `clave-core`; the daemon's loopback proxy; base-URL **+ device-token** injection in `LaunchProfile`; the gateway broker route (`ModelProvider`, attach `credential_ref`, forward over mTLS) | An agent works through the gateway **zero-key**, with per-rule **`Reject`/`Alert`/`Ignore`** + monitor mode on structured secrets | — |
| **B** | `classify_flow` model-endpoint backstop (§6) | The agent can't route around the inspector or the model allow-list | — |
| **C** | Response monitor: usage counters + policy-tiered traces (§3.2) | Spend accounting + analysis traces | — |
| **D** | Model-access policy + token budgets + per-user attribution + the `Status` readout (§5) | The governance surface for the console | Gateway admin API (NG-4) |
| **E** | Audit `app_id` + coalescing (§8) | Tamper-evident record of every decision + trace | NG-14 (done) |
| **F** | `Redact` path (§3.6); entropy-tuned heuristics; enterprise-tenant providers (Bedrock SigV4, Azure OpenAI) | Partial-context stripping; the strongest custody posture | Phase A |

Phases A–C are a thin extension of existing machinery: `LaunchProfile` already injects contained env,
`PolicyBundle` already syncs tenant-signed, the broker is a signed-and-forwarded route on the mTLS link, and
the decision is one more pure classifier next to `classify_flow`. Together the work agent is **inspected,
authenticated, metered, and recorded** — without the user ever handling a key.
