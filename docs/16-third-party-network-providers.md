# 16 — Third-Party Network Providers (Zscaler, Cisco, …)

Goal: let a tenant point **work-zone egress** at the security stack they **already run** —
Zscaler, Cisco, Netskope, Palo Alto Prisma — instead of (or alongside) Clave's own WireGuard
gateway, **without** changing the split-tunnel decision and **without** hard-coding any vendor
into the codebase.

This extends [08 — Network Split-Tunnel](08-network-split-tunnel.md). Doc 08 answers *which flows
egress through the corporate path* (`Tunnel | Direct | Block`); this doc answers *what the corporate
path is* when the company owns an SSE/SASE stack of their own. The classifier
([`classify_flow`](08-network-split-tunnel.md#5-shared-core-the-classifier-and-data-plane-live-here))
and the privacy guarantee (personal traffic stays `Direct` and unseen — [doc 01 §9](01-threat-model.md))
are untouched.

> **Status:** design. The portable scaffold (provider model + mechanism dispatch) and the DNS-layer
> integration are the first increment (§9); the live IPsec / explicit-proxy data planes need the OS
> adapters and a real tenant — same Phase-2 wall as the WireGuard data plane (`DevelopmentOnly` until
> entitled, [doc 14 §5.3](14-production-and-development-platform-requirements.md)).

---

## 1. Why this exists

Most enterprises that would buy an unmanaged-BYO-PC enclave **already have** an SSE/SASE
subscription, and security/compliance teams want all egress to traverse *their* inspection stack
(logging, CASB, DLP, threat prevention) and present *their* known source IP. Two consequences:

- **Reuse, not replace.** The corporate path must be able to terminate in Zscaler ZIA / Cisco
  Umbrella / Secure Access, not only Clave's gateway. Clave still classifies and steers; the
  inspection + egress is delegated.
- **The static-IP selling point still has to hold.** Doc 08 §4.2 sells conditional access via a
  static egress IP. Each vendor has its own equivalent — Zscaler **Dedicated Source IP**, a Cisco
  SIG tunnel's egress IP — so the value survives the swap; the design must carry that through.

The split-tunnel privacy guarantee is *more* important here, not less: personal traffic must **never**
reach the company's SSE stack. The classifier already enforces this structurally — personal flows are
`Direct` and are never handed to any provider — and that property must not regress.

---

## 2. Design principle: vendors are data, mechanisms are code

There is deliberately **no `Zscaler` or `Cisco` type** anywhere in the data plane. Vendors are
unbounded and their product lines churn; the transport *mechanisms* they expose are a small, stable,
closed set. So:

- The data plane switches **only** on a `ForwardMode` (the mechanism). Onboarding a vendor is a
  **config row**, not a code path.
- A "provider" is a vendor-neutral `NetworkProvider` record — an id, a mode, endpoints, an optional
  static egress IP, optional DNS steering, and a free-form `params` bag — provisioned at enrollment
  over the policy bundle ([doc 10](10-policy-engine-and-ipc.md)).
- "Zscaler ZIA", "Cisco Umbrella", "Acme-internal-gw" are **fixtures / config**, never enum variants.

This is the same shape the rest of the system already uses: the *decision* is portable Rust over a
small closed vocabulary; the *vendor-specific glue* is data + a thin adapter.

---

## 3. The mechanism taxonomy (`ForwardMode`)

The closed set the data plane dispatches on. A vendor's product maps to exactly one:

| `ForwardMode` | Wire mechanism | Seam it needs | Example products |
|---|---|---|---|
| `Wireguard` | boringtun Noise → Clave gateway | packet pump (`Tunnel`) | Clave's own gateway (doc 08) |
| `Ipsec` | IKEv2 / ESP → third-party headend | packet pump (`Tunnel`) | Zscaler ZIA (IPsec/GRE), Cisco SIG / Secure Access, AnyConnect-IKEv2 |
| `ExplicitProxy` | HTTP `CONNECT` / PAC → upstream proxy | per-flow forwarder | Zscaler ZIA explicit proxy, Umbrella SWG |
| `Dns` | resolver steering (no egress tunnel) | DNS steerer | Cisco Umbrella DNS-layer |

Each mode collapses to one of three things the OS data plane must drive — `Forwarding`:

- **`PacketTunnel`** — an L3 packet pump. This is the existing [`Tunnel`](08-network-split-tunnel.md)
  seam (`encapsulate` / `decapsulate`); `Wireguard` and `Ipsec` both use it unchanged. ESP vs Noise
  differ only inside the box.
- **`FlowProxy`** — an L7, per-TCP-connection forward: open upstream TLS to the proxy, issue
  `CONNECT host:port`, splice. **Does not fit** the packet pump; it needs a *separate* seam (§6.2).
  It fits the OS flow layer naturally — macOS `NETransparentProxyProvider` hands you *flows*, not
  packets (doc 08 §3); on Windows it runs as a local listener behind the WFP redirect.
- **`DnsOnly`** — no egress data plane; only work-name resolution is steered (§7).

> ⚠ The `Tunnel` trait today is **WireGuard-shaped** (one UDP peer, packet-in/encrypted-datagram-out).
> `Ipsec` reuses it as-is. `ExplicitProxy` cannot — see §6.2 for the second seam. This is the one place
> the existing abstraction does not stretch, and the design names it rather than forcing it.

---

## 4. The provider model

A vendor-neutral, serde-deserialisable record carried in the policy bundle. SKETCH:

```rust
// clave-net/src/provider.rs  (SKETCH)
pub enum ForwardMode { Wireguard, Ipsec, ExplicitProxy, Dns }      // the only dispatch axis
pub enum Forwarding  { PacketTunnel, FlowProxy, DnsOnly }          // what the OS adapter drives

pub struct NetworkProvider {
    pub id: String,                       // "zscaler-zia" — label + key-store lookup, never matched on
    pub display_name: String,
    pub mode: ForwardMode,
    pub endpoints: Vec<String>,           // headend / proxy host:port, PAC URL; empty for Dns
    pub static_egress_ip: Option<String>, // Zscaler Dedicated Source IP / Cisco egress — doc 08 §4.2
    pub dns: Option<DnsSteering>,         // §7; present on Dns providers, optional alongside a tunnel
    pub params: BTreeMap<String, String>, // PSK key-store handle, IKE id, proxy realm, cloud name…
}

impl NetworkProvider {
    /// Validate config *for the mode* and return the seam to drive. Fail-closed: a provider missing
    /// the fields its mode requires is rejected, never silently downgraded (doc 14 §5.3).
    pub fn forwarding(&self) -> Result<Forwarding, ProviderError> { /* … */ }
}
```

Notes:

- **`params` keeps onboarding data-only.** Anything that doesn't yet deserve a typed field (Zscaler
  cloud name, IKE identity, proxy auth realm, PAC refresh) lives here. A new vendor never adds a field.
- **No secrets inline.** Key material (IPsec PSK, client certs) is referenced by a **key-store handle**
  in `params`, resolved from the hardware root at use ([doc 04 §2](04-encrypted-volume.md)) — same
  discipline as the WireGuard private key (released from TPM / Secure Enclave, never persisted).
- **Where it lives.** The record lives in `clave-net` next to the existing `GatewayConfig`; it is
  carried to the device inside the signed policy bundle (`clave-core` / `clave-proto`). The daemon
  reads it at provisioning and builds the seam.

### 4.1 Vendor profiles are fixtures

The same two providers, as **data** (this is the whole point — no Zscaler/Cisco code):

```jsonc
// Zscaler Internet Access — L3 IPsec, with a Dedicated Source IP for conditional access
{ "id": "zscaler-zia", "display_name": "Zscaler Internet Access", "mode": "ipsec",
  "endpoints": ["gre1.zscaler.net:4500"], "static_egress_ip": "203.0.113.10",
  "params": { "cloud": "zscalerthree.net", "psk_ref": "ks://ipsec/zscaler" } }

// Cisco Umbrella — DNS-layer only, steer every work query to the Umbrella anycast resolvers
{ "id": "cisco-umbrella", "display_name": "Cisco Umbrella (DNS)", "mode": "dns",
  "dns": { "resolvers": ["208.67.222.222", "208.67.220.220"], "steer_all": true } }
```

---

## 5. Mapping the two named vendors

### 5.1 Zscaler

| Product | What it is | `ForwardMode` | Static IP for conditional access |
|---|---|---|---|
| ZIA (internet / SWG) | inspect + egress to internet | `Ipsec` (IPsec/GRE to ZEN) or `ExplicitProxy` (explicit proxy / PAC) | ✅ **Dedicated Source IP** |
| ZPA (private apps / ZTNA) | broker to internal apps | — (not an egress tunnel; ZTNA App Connectors) | n/a — see §8 |

ZIA is the primary fit. **ZPA is explicitly out of scope of the egress data plane** — it is a ZTNA
broker, not a packet/flow tunnel to inspect-then-egress; integrating it is a separate effort (the
client steers named internal apps to ZPA, the rest follows the normal split-tunnel). Noted in §8.

### 5.2 Cisco

| Product | What it is | `ForwardMode` |
|---|---|---|
| Umbrella (DNS-layer) | resolver-based security | `Dns` |
| Umbrella SIG / Secure Access | full SSE: inspect + egress | `Ipsec` (IPsec/GRE to headend) |
| Umbrella SWG | secure web gateway proxy | `ExplicitProxy` |
| AnyConnect / Secure Client | SSL-VPN (DTLS/TLS) or IKEv2 | `Ipsec` (IKEv2 path); the proprietary DTLS path is out of scope (§8) |

Umbrella **DNS-layer** is the cheapest, most demoable first win (§9) — no data plane, just resolver
steering.

---

## 6. Data-plane seams

### 6.1 `PacketTunnel` — reuse the `Tunnel` seam (`Wireguard`, `Ipsec`)

`Ipsec` implements the existing trait with no router-side change:

```rust
// clave-net — an IPsec backend behind a feature flag, mirroring the wireguard one  (SKETCH)
#[cfg(feature = "ipsec")]
pub struct IpsecTunnel { /* IKEv2 SA + ESP state (strongswan/libreswan-backed or a Rust IKE crate) */ }
#[cfg(feature = "ipsec")]
impl Tunnel for IpsecTunnel {
    fn encapsulate(&mut self, ip: &[u8]) -> TunnelOut { /* ESP-encrypt to the headend */ }
    fn decapsulate(&mut self, dgram: &[u8]) -> Option<Vec<u8>> { /* ESP-decrypt */ }
}
```

⚠ **Cost.** There is no `boringtun`-clean pure-Rust IKEv2/ESP stack; this backend wraps a native IKE
implementation or a less-mature Rust crate. It is the **heaviest** of the three but the **widest**:
one backend covers Zscaler ZIA, Cisco SIG/Secure Access, and AnyConnect-IKEv2.

### 6.2 `FlowProxy` — a second seam (`ExplicitProxy`)

The packet pump does not model per-connection `CONNECT`. Add a sibling seam:

```rust
// clave-net  (SKETCH) — per-flow, not per-packet
pub trait FlowForwarder: Send {
    /// Establish an upstream tunnel to the proxy for one work TCP flow (CONNECT host:port), then
    /// splice. Returns a duplex handle the OS flow layer pumps bytes through.
    fn forward(&mut self, dst: &str, upstream: &ProxyTarget) -> io::Result<FlowConduit>;
}
```

This is comparatively light (TLS + `CONNECT`, no L3 crypto) but covers **web traffic only** and is
most natural at the OS flow layer (macOS NE flows; a Windows local listener behind the WFP redirect).

### 6.3 The router stays agnostic

`SplitRouter` ([`router.rs`](../crates/clave-net/src/router.rs)) keeps owning **one** `Box<dyn Tunnel>`
for `PacketTunnel` providers — unchanged. `FlowProxy` providers are driven by the OS flow layer
through `FlowForwarder` instead. The *disposition table* (`Tunnel | Direct | Block`) is identical; only
the egress object behind a `Tunnel` disposition differs. The daemon picks the seam from
`provider.forwarding()` at provisioning and hands the right object in (`Daemon::new(.. tunnel ..)`,
[`lib.rs`](../crates/clave-daemon/src/lib.rs)).

---

## 7. DNS-layer steering (`Dns`)

Cisco Umbrella DNS (and split-horizon corporate DNS generally) is **not a tunnel** — it steers
work-name resolution to a specific resolver. This formalises doc 08 §4.1 into the provider model.

```rust
// clave-net/src/provider.rs  (SKETCH)
pub struct DnsSteering {
    pub resolvers: Vec<String>,      // corporate split-horizon resolver / Umbrella anycast
    pub match_domains: Vec<String>,  // work domains; empty + steer_all => steer everything
    pub steer_all: bool,             // Umbrella model: inspect ALL work queries (not just intranet)
}
pub enum DnsDecision { Steer, Personal }

/// Mirrors classify_flow: a personal process is NEVER touched; a work process steers when
/// steer_all is set or qname matches a work-domain suffix. (doc 08 §4.1, doc 01 §9)
pub fn decide_dns(proc: &ProcId, qname: &str, zones: &ZoneRegistry, s: &DnsSteering) -> DnsDecision;
```

Two modes, both expressible per provider:

- **`steer_all = true`** — the Umbrella model: every work-process query goes to the provider resolver
  (the resolver is the inspection point). Personal queries still never steer.
- **`steer_all = false` + `match_domains`** — split-horizon: only intranet names go to the corporate
  resolver; public names from work processes stay on the user's resolver.

Suffix matching respects the label boundary (`corp.example` matches `git.corp.example`, not
`notcorp.example`) and tolerates a trailing dot. **Personal-process DNS is never inspected or
logged** — the same structural guarantee as routing.

`Dns` steering is **orthogonal** to egress: a provider may be `mode: Dns` (DNS-only, egress untouched
or handled by a second provider) *or* carry `dns: Some(..)` alongside a `PacketTunnel`/`FlowProxy`
mode (Umbrella DNS + a separate egress tunnel).

---

## 8. Non-goals / out of scope

- **Zscaler ZPA / ZTNA brokering.** ZPA is an internal-app broker, not an inspect-then-egress tunnel.
  Out of scope here; a future "named internal apps → ZPA" steering effort is separate.
- **Proprietary client protocols.** Zscaler Z-Tunnel/Tunnel 2.0 and Cisco AnyConnect DTLS are
  proprietary; we integrate via the **standards-based** paths each vendor also exposes (IPsec/IKEv2,
  explicit proxy, DNS). We do not reimplement a vendor's client agent.
- **Replacing the classifier.** `classify_flow` and the personal-stays-`Direct` guarantee are fixed.
  A provider changes *egress*, never *who is in the work zone*.
- **Multiple simultaneous egress providers per flow.** v1 is one egress provider per tenant policy
  (a `Dns` provider may coexist with one egress provider). Per-destination provider selection is a
  later policy concern.

---

## 9. Build phasing

Consistent with the build roadmap ([doc 13](13-build-roadmap.md)) and the enforcement-honesty model
([doc 14 §5.3](14-production-and-development-platform-requirements.md)): build the portable half here,
gate the OS half behind the same Phase-2 wall as WireGuard.

**Increment 1 — portable scaffold + DNS-layer (build & test on any machine, no driver):**
- `ForwardMode`, `Forwarding`, `NetworkProvider`, `DnsSteering`, `DnsDecision`, `ProviderError` in
  `clave-net` (serde, carried in the policy bundle).
- `NetworkProvider::forwarding()` validation (fail-closed) and `decide_dns()` — fully working.
- A factory that maps a provider to a seam and **refuses** (typed error) any mode whose data plane is
  not yet built — no silent fallback (doc 14 §5.3).
- Property/unit tests: vendor profiles round-trip through JSON; mechanism dispatch is vendor-neutral;
  Umbrella steers all work DNS but never personal; split-horizon steers only work domains.

**Increment 2 — `Ipsec` packet backend** (needs a real tenant + the OS adapters): `IpsecTunnel`
behind an `ipsec` feature, wired through the existing `Tunnel` seam; Dedicated Source IP / SIG egress
asserted against conditional access.

**Increment 3 — `ExplicitProxy` / `FlowForwarder`** (needs the OS flow layer): the `CONNECT` forwarder,
most naturally on macOS NE flows first.

⚠ Increments 2–3 are `DevelopmentOnly` until entitled and need a live Zscaler/Cisco tenant — the same
"more than this Mac" wall as the WireGuard data plane (README → *What needs more than this Mac*).

---

## 10. Test plan

- **Vendor-neutrality:** two distinct vendor profiles (a ZIA `ipsec` row, an Umbrella `dns` row) drive
  the correct `Forwarding` purely from data, with zero vendor symbols in the data plane.
- **Fail-closed:** a provider missing its mode's required fields (no endpoint; `dns` with no resolver)
  is rejected before any flow rides it.
- **DNS privacy:** assert a personal-process query is `Personal` even under `steer_all`; assert a
  work-process public-name query is `Personal` under split-horizon; assert label-boundary suffix
  matching. Packet-capture the personal resolver path and assert no work query leaks to it (doc 08 §7).
- **Static IP (Increment 2):** work browser via the provider shows the **Dedicated Source IP / SIG
  egress**; configure SaaS conditional access to allow only that IP and assert work login succeeds via
  the provider and fails from a raw personal connection (doc 08 §4.2, §7).
- **Round-trip:** `PacketTunnel` providers exercise the same `SplitRouter` round-trip test the
  WireGuard/loopback path uses today, with the provider-selected tunnel boxed in.

---

## 11. Open decisions

1. **`Ipsec` backend choice** — wrap a native IKE stack (strongswan/libreswan) via FFI, or take a
   pure-Rust IKEv2 crate (less mature)? Trades `unsafe`/packaging against maturity. Affects doc 11/12.
2. **`FlowForwarder` placement** — a `clave-net` trait driven by both OS adapters, or NE-only first
   given how cleanly NE flows fit `CONNECT`? (Windows needs a local listener regardless.)
3. **Provider in the policy schema** — embed `NetworkProvider` directly in the policy bundle
   ([doc 10](10-policy-engine-and-ipc.md)), or keep it in a separate signed enrollment artifact next to
   the gateway keys? Leaning: policy bundle, since it changes with policy.

---

## 12. References

- [08 — Network Split-Tunnel](08-network-split-tunnel.md) — the classifier, the `Tunnel` seam, static
  egress IP, DNS-leak prevention this doc builds on.
- [01 — Threat Model §9](01-threat-model.md) — personal traffic is never seen; the invariant this
  design must not regress.
- [04 — Encrypted Volume §2](04-encrypted-volume.md) — hardware key root; where provider secrets resolve.
- [10 — Policy Engine & IPC](10-policy-engine-and-ipc.md) — how a provider profile reaches the device.
- [14 §5.3 — Enforcement status](14-production-and-development-platform-requirements.md) — why unbuilt
  modes fail closed instead of silently degrading.
- Vendor docs: Zscaler ZIA forwarding (IPsec/GRE, Dedicated Source IP, explicit proxy/PAC); Cisco
  Umbrella DNS-layer + SIG/Secure Access tunnels; Cisco Secure Client / AnyConnect IKEv2.
