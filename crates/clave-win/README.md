# clave-win

Windows platform adapter. **Phase 2 scaffold.** See [`../../docs/08-network-split-tunnel.md`](../../docs/08-network-split-tunnel.md)
and [Appendix A](../../docs/appendix-a-windows-primitives.md).

## What builds here

On a non-Windows host this crate compiles to a near-empty lib: the `cfg(windows)` enforcement
module is excluded, and the portable `route()` (the WFP callout's decision) + its test build
everywhere.

```sh
cargo test -p clave-win        # the portable route() test runs on any OS
```

## What needs a Windows checkout (+ signing)

| Component | Primitive | Notes |
|-----------|-----------|-------|
| Split-tunnel | **WFP callout** at `ALE_CONNECT_REDIRECT_V4/V6` | classify by PID → `route()` → bind-redirect to `wintun` |
| Prototype | **WinDivert** (user mode) | iterate the classifier before a signed callout driver |
| Data plane | `wintun` + boringtun | WireGuard to the gateway static IP |
| Disk gating | **minifilter** | separate WDK / `windows-drivers-rs` project (`native/win-driver`) |
| Process supervision | `PsSetCreateProcessNotifyRoutineEx2` + Job Objects | doc 02 |

Real deps go under `[target.'cfg(windows)'.dependencies]` in `Cargo.toml` (commented) so
non-Windows CI never fetches them. Kernel components require EV-cert + Hardware-Dashboard
signing (doc 12 §1.2).
