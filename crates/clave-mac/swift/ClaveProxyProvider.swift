// ClaveProxyProvider.swift — macOS Network Extension host (SCAFFOLD, not built by cargo).
//
// A NETransparentProxyProvider that classifies each new flow by the originating app's audit
// token and hands work flows to the Rust core (linked staticlib `libclave_mac.a`). Personal
// flows are returned to the system untouched (returning false), so the company never sees
// personal traffic (doc 01 §9, doc 08 §3).
//
// Build: this is a System Extension target in an Xcode project, signed with Developer ID,
// the Network Extension entitlement, and notarized (doc 12 §2). It is NOT part of the cargo
// build; cargo produces the Rust staticlib this links against.

import NetworkExtension
import Foundation

// C ABI exported by clave-mac (see src/lib.rs).
@_silgen_name("clave_mac_route_flow")
func clave_mac_route_flow(_ token: UnsafePointer<UInt32>?, _ dstBlocked: Bool) -> UInt8

final class ClaveProxyProvider: NETransparentProxyProvider {

    override func startProxy(options: [String: Any]? = nil) async throws {
        // Install transparent-proxy network settings scoping which traffic we see, then signal
        // readiness. (Rules pushed via NETunnelProviderManager / MDM, doc 08 §3.1.)
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let token = flow.metaData.sourceAppAuditToken   // authoritative identity (doc 02)
        // TODO: compute dstBlocked from the remote endpoint against the work egress denylist.
        let route = token.withUnsafeBytes { raw -> UInt8 in
            let ptr = raw.bindMemory(to: UInt32.self).baseAddress
            return clave_mac_route_flow(ptr, /* dstBlocked: */ false)
        }

        switch route {
        case 1: // Tunnel: we own this flow → pump it through boringtun to the gateway.
            handleWorkFlow(flow)
            return true
        case 2: // Block: refuse (work egress denylist).
            flow.closeReadWithError(nil); flow.closeWriteWithError(nil)
            return true
        default: // 0 = Direct: personal flow → let the system route it; we never see it.
            return false
        }
    }

    private func handleWorkFlow(_ flow: NEAppProxyFlow) {
        // Open the flow and shuttle bytes between it and the Rust WireGuard data plane
        // (clave-net::wireguard once wired). See docs/08 §3.2.
    }
}
