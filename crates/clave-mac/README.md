# clave-mac

macOS platform adapter. **Phase 2 scaffold.** See [`../../docs/08-network-split-tunnel.md`](../../docs/08-network-split-tunnel.md)
and [`../../docs/02-process-supervision.md`](../../docs/02-process-supervision.md).

## What builds here (CI on any Mac)

- `src/lib.rs` — the Rust core: audit-token → zone classification + the **C ABI** the Swift
  extensions call (`clave_mac_route_flow`, `clave_mac_zone_join`, `clave_mac_zone_leave`).
  Built as both `lib` (workspace) and `staticlib` (`libclave_mac.a`, for Swift to link).
- Unit tests for the classification + ABI codes.

```sh
cargo test -p clave-mac
cargo build -p clave-mac --release   # produces target/release/libclave_mac.a
```

## What does NOT build here (needs Xcode + entitlements + a Mac)

- `swift/ClaveProxyProvider.swift` — the `NETransparentProxyProvider` System Extension.
- The Endpoint Security client host (exec/file authorization).

These are Xcode System Extension targets, **not** part of the cargo build. They require:

| Requirement | Why |
|-------------|-----|
| `com.apple.developer.endpoint-security.client` | ES exec/file authorization (**Apple approval — weeks**, doc 12 §2.2) |
| `com.apple.developer.networking.networkextension` (`app-proxy-provider`) | the transparent proxy |
| Developer ID + Hardened Runtime + notarization | Gatekeeper |
| TCC: Full Disk Access, (Screen Recording / Accessibility for other subsystems) | doc 12 §2.3 |

## Linking

The Xcode targets link `libclave_mac.a` and call the `extern "C"` symbols. A bridging header
declares them, or use `@_silgen_name` as shown in the Swift scaffold. Pass the macOS
`audit_token_t` (8 × `u32`) straight through as an `UnsafePointer<UInt32>`.
