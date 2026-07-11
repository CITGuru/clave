# 08 — Network Split-Tunnel

Goal: traffic from **work** processes egresses through the corporate **gateway** (giving a
**static, dedicated IP** for conditional access) over an encrypted tunnel, while **personal**
traffic goes **direct** to the user's ISP and is never seen by the company. Per-flow
classification keys on the same authoritative process identity as everything else.

Implements the `NetworkTunnel` trait from [00 §4](00-architecture-overview.md). This is one of
the **✅ enforceable on both OSes** subsystems and a high-value, lower-risk early deliverable.

---

## 1. Architecture

```
   work proc socket ─┐                         ┌─► corporate gateway (STATIC IP) ─► SaaS / intranet
                     │  classify by PID/token  │     conditional access: allowlists this IP
   personal socket ─┐│  ┌───────────────────┐  │
                    ││  │ split-tunnel       │  │
                    │└─►│ classifier + data  │──┘
                    │   │ plane (boringtun)  │
                    └──►│   direct path      │──► user's ISP (personal, unseen by company)
                        └───────────────────┘
```

- **Control plane:** classify each new flow → `Tunnel` or `Direct`.
- **Data plane:** a userspace **WireGuard** stack (`boringtun`, Cloudflare's Rust impl) to the
  gateway; a virtual NIC (`wintun` on Windows, `utun` on macOS) carries tunneled flows.
- **Static egress IP:** the gateway NATs all tunneled traffic to a per-tenant fixed IP, so
  SaaS apps can `allow source == that IP` (conditional access / IP allowlisting) — a major
  selling point and the network analog of "managed device."

---

## 2. Windows: WFP callout

The **Windows Filtering Platform** lets you classify and redirect connections by **process
ID** at the **ALE (Application Layer Enforcement)** layers, in kernel.

### 2.1 Layers and the redirect

- `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` — intercept `connect()` and **bind-redirect** the
  socket onto the tunnel interface for work flows.
- `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` — permit/block decisions.
- The callout reads the **PID** from the classify metadata, checks the supervised set (doc 02,
  shared with the kernel), and steers.

```c
// WFP callout classifyFn (C/WDK; windows-drivers-rs mirrors it) — SKETCH
void classify_connect_redirect(const FWPS_INCOMING_VALUES* in,
        const FWPS_INCOMING_METADATA_VALUES* meta, void* layerData,
        const void* ctx, const FWPS_FILTER* filter, UINT64 flowCtx,
        FWPS_CLASSIFY_OUT* out)
{
    UINT64 pid = meta->processId;                  // authoritative
    if (SetContains(g_supervised, pid)) {
        // rewrite the socket's outbound path onto the tunnel (wintun) local address
        FwpsAcquireWritableLayerDataPointer(...);
        redirect->localAddress  = g_tunnel_local_ip;
        redirect->remoteAddress = remote;          // gateway forwards
        FwpsApplyModifiedLayerData(...);
        out->actionType = FWP_ACTION_PERMIT;
    } else {
        out->actionType = FWP_ACTION_CONTINUE;      // personal → leave alone (direct)
    }
}
```

### 2.2 The fast prototype: WinDivert (user mode)

Before committing to a signed WFP callout driver, prototype the entire classifier in **user
mode** with **WinDivert** (`windivert` Rust crate): it hands you packets/flows with PID, you
decide, you reinject. Great for v1 and demos; move hot-path classification into a WFP callout
for production (WinDivert adds latency and is itself a driver you must ship/sign).

### 2.3 Data plane

```rust
// clave-net-win — wintun + boringtun  (SKETCH)
let adapter = wintun::Adapter::create(&wintun, "Clave", "Clave Work Tunnel", None)?;
let session = adapter.start_session(wintun::MAX_RING_CAPACITY)?;
let mut tun = boringtun::noise::Tunn::new(priv_key, gateway_pub, None, None, 0, None)?;

loop {
    let pkt = session.receive_blocking()?;          // outbound work packet from WFP redirect
    match tun.encapsulate(pkt.bytes(), &mut scratch) {
        TunnResult::WriteToNetwork(buf) => udp_to_gateway.send(buf)?,  // WireGuard to static-IP GW
        _ => {}
    }
}
// reverse path: UDP from gateway → tun.decapsulate → session.send (inbound to work proc)
```

---

## 3. macOS: Network Extension

macOS gives you a **supported, no-kernel** per-app routing mechanism: the **Network
Extension** framework, specifically a **`NETransparentProxyProvider`** (or `NEAppProxyProvider`
for a per-app VPN). The provider receives new flows tagged with the originating app's identity
and decides per flow.

### 3.1 The provider

```swift
// ClaveProxyProvider.swift  (NETransparentProxyProvider, System Extension)
override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
    let meta = flow.metaData
    let token = meta.sourceAppAuditToken            // authoritative identity
    let signingId = meta.sourceAppSigningIdentifier

    if clave_core_zone_contains(token_bytes(token)) {
        // hand the flow's data to the Rust core → boringtun → gateway
        clave_core_handle_work_flow(flow)            // we own read/write on this flow
        return true                                 // we handle it
    }
    return false                                    // personal flow → system handles it directly
}
```

- `NEAppProxyFlow` gives you `sourceAppAuditToken` and `sourceAppSigningIdentifier` — you
  classify by the **same audit token** the ES client tracks (doc 02). No injection, no kext.
- Returning `false` for personal flows means the OS routes them normally and **you never see
  them** — the privacy guarantee is structural.
- The provider config is installed via a `NETunnelProviderManager` / MDM profile; on
  unmanaged BYO-PC it requires a user-approved VPN/Network-Extension configuration (one-time
  consent).

### 3.2 Data plane

Same `boringtun` core as Windows, shared Rust. The Swift provider reads `NEAppProxyTCPFlow` /
`UDPFlow` bytes and passes them to the Rust staticlib, which encapsulates to WireGuard and
sends to the gateway over a `utun` or directly via the provider's `NWUDPSession`/sockets.

---

## 4. Cross-cutting: DNS, conditional access, captive portals

### 4.1 DNS-leak prevention (✅ both)

Work-name resolution must **not** go to the personal resolver (it would leak intranet names
and bypass split-horizon DNS).

- Route DNS queries from work processes **into the tunnel** to the corporate resolver.
- Windows: the WFP redirect catches UDP/TCP 53 from work PIDs like any other flow; additionally
  set the tunnel adapter's DNS and use **NRPT** (Name Resolution Policy Table) to send work
  domains to the corporate resolver.
- macOS: the NE provider handles work flows including 53; pair with a **DNS proxy / on-demand
  rules** in the NE config for work domains.
- **Personal DNS stays on the user's resolver** — never tunneled, never logged.

### 4.2 Static egress IP & conditional access (the selling point)

The gateway SNATs all tunneled traffic to a fixed per-tenant IP. SaaS admin consoles
(Okta/Entra/Google) then enforce *"corporate apps only reachable from this IP."* Result:
even though the device is unmanaged BYO-PC, work SaaS is locked to traffic that has passed
through the enclave's tunnel — the network analog of device trust.

### 4.3 Captive portals & offline

- A captive portal (hotel/airport) must be reachable to authenticate the underlay *before* the
  tunnel comes up — allow the personal path to reach the portal; the work tunnel establishes
  after. Detect portal via the OS's connectivity check and surface a prompt.
- Offline: work apps with no tunnel should **fail-closed** for network (no direct fallback for
  work flows — that would bypass conditional access), while personal stays online.

---

## 5. Shared core: the classifier and data plane live here

```rust
// clave-core/src/net.rs
pub enum Route { Tunnel, Direct, Block }

pub fn classify_flow(proc: &ProcId, dst: &SocketAddr, zone: &ZoneRegistry, pol: &Policy) -> Route {
    if !zone.is_supervised(proc) { return Route::Direct; }       // personal → never tunneled
    if pol.is_blocked(dst)       { return Route::Block;  }       // work egress allowlist
    Route::Tunnel                                                 // work → corporate static IP
}

// boringtun wrapper shared by both OS data planes
pub struct WgTunnel { tun: boringtun::noise::Tunn, gateway: SocketAddr, /* … */ }
impl WgTunnel {
    pub fn out(&mut self, ip_pkt: &[u8]) -> Option<Vec<u8>> { /* encapsulate */ }
    pub fn inn(&mut self, wg_pkt: &[u8]) -> Option<Vec<u8>> { /* decapsulate */ }
}
```

The OS layers (WFP / NE) are thin: they capture flows and supply the authoritative identity;
the *decision* and the *crypto* are portable Rust.

---

## 6. Why this subsystem is the recommended first vertical slice

- **✅ enforceable on both OSes** with **supported** APIs (WFP, NetworkExtension) — no fragile
  injection, no compositor tricks.
- Mostly **shared Rust** (classifier + boringtun); the OS-specific glue is comparatively small.
- Delivers the **most visible enterprise value** early: conditional-access via static IP is a
  concrete, demoable win that doesn't depend on the harder DLP subsystems.
- Forces you through the **signing/entitlement pipeline** (WFP driver signing; Network
  Extension entitlement + approval) on a self-contained feature — de-risking doc 12's walls
  before they block the whole product.

See [13 — Build Roadmap](13-build-roadmap.md) for sequencing.

---

## 7. Test plan

- Work browser → `ifconfig.me` shows the **gateway static IP**; personal browser shows the
  **ISP IP**. Flip an app between zones and re-check.
- Work intranet DNS resolves via corporate resolver; personal DNS unaffected; assert no work
  query hits the personal resolver (packet-capture the personal path).
- Kill daemon/provider ⇒ work flows **fail-closed** (no direct fallback); personal stays up.
- SaaS conditional-access: configure Okta to allow only the static IP; assert work login
  succeeds via tunnel and fails from a raw personal connection.
- Captive portal: simulate; assert portal auth works and tunnel establishes after.

Proceed to [09 — Visual Border Overlay](09-visual-border-overlay.md).
