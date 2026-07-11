// ClaveEndpointSecurityClient.swift — macOS Endpoint Security host (SCAFFOLD, not built by cargo).
//
// An ES client that (a) authorizes exec and seeds work-zone membership, (b) gates opens of the
// Clave Disk so only supervised processes can read it, and (c) tracks process exit. It links the
// Rust core (staticlib `libclave_mac.a`) and calls the C ABI in src/lib.rs. The *decisions* are
// the portable Rust core's; this host only subscribes to ES events and enforces the verdict
// (doc 02, doc 04 §4.2).
//
// Build: an Endpoint Security System Extension target, signed with the ES entitlement
// (com.apple.developer.endpoint-security.client) and notarized for production (doc 14 §1). For
// development it can run on a SIP-disabled lab Mac without the production entitlement
// (doc 14 §2.3) — that posture is reported as `DevelopmentOnly`, never `Enforced` (doc 14 §5.4).
// NOT part of the cargo build; cargo produces the Rust staticlib this links against.

import EndpointSecurity
import Foundation

// C ABI exported by clave-mac (see src/lib.rs).
@_silgen_name("clave_mac_zone_join")
func clave_mac_zone_join(_ token: UnsafePointer<UInt32>?)
@_silgen_name("clave_mac_zone_leave")
func clave_mac_zone_leave(_ token: UnsafePointer<UInt32>?)
@_silgen_name("clave_mac_can_access_volume")
func clave_mac_can_access_volume(_ token: UnsafePointer<UInt32>?) -> Bool

let claveDiskPrefix = "/Volumes/ClaveDisk"

func startClient() throws {
    var client: OpaquePointer?
    let result = es_new_client(&client) { client, msg in
        let token = msg.pointee.process.pointee.audit_token
        switch msg.pointee.event_type {

        case ES_EVENT_TYPE_AUTH_EXEC:
            // TODO: match the binary against the signed app allow-list (Team ID + signing id,
            // doc 10 §1) to decide allow + whether it joins the zone. Scaffold: seed membership.
            withTokenPointer(token) { clave_mac_zone_join($0) }
            es_respond_auth_result(client!, msg, ES_AUTH_RESULT_ALLOW, false)

        case ES_EVENT_TYPE_AUTH_OPEN:
            // Gate reads of the Clave Disk: only supervised callers, even while it is mounted.
            let path = String(cString: msg.pointee.event.open.file.pointee.path.data)
            if path.hasPrefix(claveDiskPrefix) {
                let allow = withTokenPointer(token) { clave_mac_can_access_volume($0) }
                es_respond_flags_result(client!, msg, allow ? UInt32.max : 0, false)
            } else {
                es_respond_flags_result(client!, msg, UInt32.max, false)
            }

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            withTokenPointer(token) { clave_mac_zone_leave($0) }

        default:
            break
        }
    }
    guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else { throw ClientError.create }

    // AUTH_OPEN is high-frequency: `es_mute_path` the volume for already-trusted supervised
    // processes so ES adjudicates only the boundary crossings, not every work-app read
    // (doc 04 §4.2). Re-evaluate mutes on policy change.
    var events = [ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_NOTIFY_EXIT]
    es_subscribe(client, &events, UInt32(events.count))
}

/// Pass a macOS `audit_token_t` (8 × `UInt32`) to the C ABI as a pointer.
func withTokenPointer<R>(_ token: audit_token_t, _ body: (UnsafePointer<UInt32>?) -> R) -> R {
    var t = token
    return withUnsafeBytes(of: &t) { raw in
        body(raw.bindMemory(to: UInt32.self).baseAddress)
    }
}

enum ClientError: Error { case create }
