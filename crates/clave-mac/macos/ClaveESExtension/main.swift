import EndpointSecurity
import Foundation
import OSLog

@_silgen_name("clave_mac_load_policy_json")
func clave_mac_load_policy_json(_ ptr: UnsafePointer<UInt8>?, _ len: Int) -> Bool
@_silgen_name("clave_mac_set_mount_prefix")
func clave_mac_set_mount_prefix(_ ptr: UnsafePointer<CChar>?) -> Bool
@_silgen_name("clave_mac_authorize_exec")
func clave_mac_authorize_exec(
    _ parentToken: UnsafePointer<UInt32>?,
    _ targetToken: UnsafePointer<UInt32>?,
    _ teamId: UnsafePointer<CChar>?,
    _ signingId: UnsafePointer<CChar>?,
    _ isPlatformBinary: Bool
) -> Bool
@_silgen_name("clave_mac_authorize_open")
func clave_mac_authorize_open(
    _ token: UnsafePointer<UInt32>?,
    _ path: UnsafePointer<CChar>?,
    _ write: Bool
) -> Bool
@_silgen_name("clave_mac_authorize_clone")
func clave_mac_authorize_clone(
    _ token: UnsafePointer<UInt32>?,
    _ source: UnsafePointer<CChar>?,
    _ target: UnsafePointer<CChar>?
) -> Bool
@_silgen_name("clave_mac_authorize_rename")
func clave_mac_authorize_rename(
    _ token: UnsafePointer<UInt32>?,
    _ source: UnsafePointer<CChar>?,
    _ target: UnsafePointer<CChar>?
) -> Bool
@_silgen_name("clave_mac_authorize_link")
func clave_mac_authorize_link(
    _ token: UnsafePointer<UInt32>?,
    _ source: UnsafePointer<CChar>?,
    _ target: UnsafePointer<CChar>?
) -> Bool
@_silgen_name("clave_mac_zone_leave")
func clave_mac_zone_leave(_ token: UnsafePointer<UInt32>?)

let log = Logger(subsystem: "com.clave.ClaveES.ESClient", category: "es")
let policyPath = ProcessInfo.processInfo.environment["CLAVE_POLICY_JSON"]
    ?? "/Users/Shared/Clave/policy.json"

private let FWRITE: Int32 = 0x00000002

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

func configureMountPrefix() {
    let mount = ProcessInfo.processInfo.environment["CLAVE_DEV_MOUNT"]
        ?? ProcessInfo.processInfo.environment["CLAVE_MOUNT"]
        ?? "/Volumes/ClaveDisk"
    mount.withCString { ptr in
        if !clave_mac_set_mount_prefix(ptr) {
            log.error("failed to set Clave mount prefix")
        }
    }
    log.notice("Clave mount prefix: \(mount, privacy: .public)")
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
        let isPlatform = target.is_platform_binary
        withTokenPointer(parent) { p in
            withTokenPointer(target.audit_token) { t in
                team.withCString { teamC in
                    signing.withCString { sigC in
                        _ = clave_mac_authorize_exec(p, t, teamC, sigC, isPlatform)
                    }
                }
            }
        }
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false)

    case ES_EVENT_TYPE_AUTH_OPEN:
        let token = m.process.pointee.audit_token
        let path = esString(m.event.open.file.pointee.path)
        let write = (m.event.open.fflag & FWRITE) != 0
        let allow = withTokenPointer(token) { tok in
            path.withCString { pathC in
                clave_mac_authorize_open(tok, pathC, write)
            }
        }
        es_respond_flags_result(client, msg, allow ? UInt32.max : 0, false)

    case ES_EVENT_TYPE_AUTH_CLONE:
        let token = m.process.pointee.audit_token
        let source = esString(m.event.clone.source.pointee.path)
        let targetDir = esString(m.event.clone.target_dir.pointee.path)
        let targetName = esString(m.event.clone.target_name)
        let target = (targetDir as NSString).appendingPathComponent(targetName)
        let allow = withTokenPointer(token) { tok in
            source.withCString { srcC in
                target.withCString { dstC in
                    clave_mac_authorize_clone(tok, srcC, dstC)
                }
            }
        }
        es_respond_auth_result(client, msg, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)

    case ES_EVENT_TYPE_AUTH_RENAME:
        let token = m.process.pointee.audit_token
        let source = esString(m.event.rename.source.pointee.path)
        let target: String
        if m.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            target = esString(m.event.rename.destination.existing_file.pointee.path)
        } else {
            let dir = esString(m.event.rename.destination.new_path.dir.pointee.path)
            let name = esString(m.event.rename.destination.new_path.filename)
            target = (dir as NSString).appendingPathComponent(name)
        }
        let allow = withTokenPointer(token) { tok in
            source.withCString { srcC in
                target.withCString { dstC in
                    clave_mac_authorize_rename(tok, srcC, dstC)
                }
            }
        }
        es_respond_auth_result(client, msg, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)

    case ES_EVENT_TYPE_AUTH_LINK:
        let token = m.process.pointee.audit_token
        let source = esString(m.event.link.source.pointee.path)
        let dir = esString(m.event.link.target_dir.pointee.path)
        let name = esString(m.event.link.target_filename)
        let target = (dir as NSString).appendingPathComponent(name)
        let allow = withTokenPointer(token) { tok in
            source.withCString { srcC in
                target.withCString { dstC in
                    clave_mac_authorize_link(tok, srcC, dstC)
                }
            }
        }
        es_respond_auth_result(client, msg, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)

    case ES_EVENT_TYPE_NOTIFY_EXIT:
        let token = m.process.pointee.audit_token
        withTokenPointer(token) { clave_mac_zone_leave($0) }

    default:
        break
    }
}

let policyMachServiceName = "com.clave.ClaveES.ESClient.policy"
let daemonCodeRequirement =
    "identifier \"com.clave.daemon\" and anchor apple generic and certificate leaf[subject.OU] = \"B6MKLUGY37\""

@objc protocol ClavePolicyControl {
    func loadPolicy(_ data: Data, withReply reply: @escaping (Bool) -> Void)
}

final class ClavePolicyService: NSObject, ClavePolicyControl {
    func loadPolicy(_ data: Data, withReply reply: @escaping (Bool) -> Void) {
        let ok = data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return false }
            return clave_mac_load_policy_json(base, data.count)
        }
        log.notice("policy over XPC: \(ok ? "loaded" : "rejected") (\(data.count, privacy: .public) bytes)")
        reply(ok)
    }
}

final class ClavePolicyListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        newConnection.setCodeSigningRequirement(daemonCodeRequirement)
        newConnection.exportedInterface = NSXPCInterface(with: ClavePolicyControl.self)
        newConnection.exportedObject = ClavePolicyService()
        newConnection.resume()
        return true
    }
}

let policyListenerDelegate = ClavePolicyListenerDelegate()
var policyListener: NSXPCListener?

func startPolicyListener() {
    let listener = NSXPCListener(machServiceName: policyMachServiceName)
    listener.delegate = policyListenerDelegate
    listener.resume()
    policyListener = listener
    log.notice("Clave policy XPC listener on \(policyMachServiceName, privacy: .public)")
}

func startClient() {
    configureMountPrefix()
    loadPolicy()
    startPolicyListener()

    var client: OpaquePointer?
    let result = es_new_client(&client) { client, msg in handle(client, msg) }
    guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
        log.fault("es_new_client failed: \(result.rawValue, privacy: .public) — is the ES entitlement present and SIP off?")
        exit(1)
    }

    var events: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_CLONE,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_LINK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    ]
    let sub = es_subscribe(client, &events, UInt32(events.count))
    guard sub == ES_RETURN_SUCCESS else {
        log.fault("es_subscribe failed")
        exit(1)
    }
    log.notice("Clave ES client subscribed (AUTH_EXEC, AUTH_OPEN, AUTH_CLONE, AUTH_RENAME, AUTH_LINK, NOTIFY_EXIT).")
}

startClient()
dispatchMain()
