import EndpointSecurity
import Foundation
import OSLog

@_silgen_name("clave_mac_load_policy_json")
func clave_mac_load_policy_json(_ ptr: UnsafePointer<UInt8>?, _ len: Int) -> Bool
@_silgen_name("clave_mac_authorize_exec")
func clave_mac_authorize_exec(
    _ parentToken: UnsafePointer<UInt32>?,
    _ targetToken: UnsafePointer<UInt32>?,
    _ teamId: UnsafePointer<CChar>?,
    _ signingId: UnsafePointer<CChar>?
) -> Bool
@_silgen_name("clave_mac_can_access_volume")
func clave_mac_can_access_volume(_ token: UnsafePointer<UInt32>?) -> Bool
@_silgen_name("clave_mac_zone_leave")
func clave_mac_zone_leave(_ token: UnsafePointer<UInt32>?)

let log = Logger(subsystem: "com.clave.ClaveES.ESClient", category: "es")
let claveDiskPrefix = "/Volumes/ClaveDisk"
let policyPath = ProcessInfo.processInfo.environment["CLAVE_POLICY_JSON"]
    ?? "/Library/Application Support/Clave/policy.json"

func withTokenPointer<R>(_ token: audit_token_t, _ body: (UnsafePointer<UInt32>?) -> R) -> R {
    var t = token
    return withUnsafeBytes(of: &t) { raw in
        body(raw.bindMemory(to: UInt32.self).baseAddress)
    }
}

func esString(_ token: es_string_token_t) -> String {
    guard token.length > 0, let data = token.data else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: data, count: token.length), as: UTF8.self)
}

func loadPolicy() {
    guard let bytes = FileManager.default.contents(atPath: policyPath) else {
        log.notice("No policy at \(policyPath, privacy: .public) — starting with an empty allow-list.")
        return
    }
    let ok = bytes.withUnsafeBytes { raw -> Bool in
        clave_mac_load_policy_json(raw.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    }
    log.notice("Loaded policy from \(policyPath, privacy: .public): \(ok ? "ok" : "parse failed")")
}

func handle(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>) {
    let m = msg.pointee
    switch m.event_type {

    case ES_EVENT_TYPE_AUTH_EXEC:
        let parent = m.process.pointee.audit_token
        let target = m.event.exec.target.pointee
        let team = esString(target.team_id)
        let signing = esString(target.signing_id)
        withTokenPointer(parent) { p in
            withTokenPointer(target.audit_token) { t in
                team.withCString { teamC in
                    signing.withCString { sigC in
                        _ = clave_mac_authorize_exec(p, t, teamC, sigC)
                    }
                }
            }
        }
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false)

    case ES_EVENT_TYPE_AUTH_OPEN:
        let token = m.process.pointee.audit_token
        let path = esString(m.event.open.file.pointee.path)
        if path.hasPrefix(claveDiskPrefix) {
            let allow = withTokenPointer(token) { clave_mac_can_access_volume($0) }
            es_respond_flags_result(client, msg, allow ? UInt32.max : 0, false)
        } else {
            es_respond_flags_result(client, msg, UInt32.max, false)
        }

    case ES_EVENT_TYPE_NOTIFY_EXIT:
        let token = m.process.pointee.audit_token
        withTokenPointer(token) { clave_mac_zone_leave($0) }

    default:
        break
    }
}

func startClient() {
    loadPolicy()

    var client: OpaquePointer?
    let result = es_new_client(&client) { client, msg in handle(client, msg) }
    guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
        log.fault("es_new_client failed: \(result.rawValue, privacy: .public) — is the ES entitlement present and SIP off?")
        exit(1)
    }

    var events: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    ]
    let sub = es_subscribe(client, &events, UInt32(events.count))
    guard sub == ES_RETURN_SUCCESS else {
        log.fault("es_subscribe failed")
        exit(1)
    }
    log.notice("Clave ES client subscribed (AUTH_EXEC, AUTH_OPEN, NOTIFY_EXIT).")
}

startClient()
dispatchMain()
