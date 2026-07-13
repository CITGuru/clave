import Foundation
import OSLog

@_silgen_name("clave_daemon_run")
func clave_daemon_run()

@_silgen_name("clave_daemon_set_policy_pusher")
func clave_daemon_set_policy_pusher(
    _ pusher: (@convention(c) (UnsafePointer<UInt8>?, Int) -> Bool)?
)

let log = Logger(subsystem: "com.clave.daemon", category: "policy")
let policyMachServiceName = "com.clave.ClaveES.ESClient.policy"

@objc protocol ClavePolicyControl {
    func loadPolicy(_ data: Data, withReply reply: @escaping (Bool) -> Void)
}

func pushPolicyOnce(_ data: Data) -> Bool {
    let conn = NSXPCConnection(machServiceName: policyMachServiceName, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: ClavePolicyControl.self)
    conn.resume()
    defer { conn.invalidate() }

    let sem = DispatchSemaphore(value: 0)
    var result = false
    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        log.error("policy push error: \(err.localizedDescription, privacy: .public)")
        sem.signal()
    } as? ClavePolicyControl
    guard let proxy = proxy else { return false }
    proxy.loadPolicy(data) { ok in
        result = ok
        sem.signal()
    }
    _ = sem.wait(timeout: .now() + 5)
    return result
}

func pushPolicyWithRetry(_ data: Data) -> Bool {
    let deadline = Date().addingTimeInterval(15)
    while Date() < deadline {
        if pushPolicyOnce(data) {
            log.notice("policy pushed to ES client (\(data.count, privacy: .public) bytes)")
            return true
        }
        Thread.sleep(forTimeInterval: 1.0)
    }
    log.error("policy push to ES client timed out")
    return false
}

let policyPusher: @convention(c) (UnsafePointer<UInt8>?, Int) -> Bool = { ptr, len in
    guard let ptr = ptr, len > 0 else { return false }
    let data = Data(bytes: ptr, count: len)
    return pushPolicyWithRetry(data)
}

clave_daemon_set_policy_pusher(policyPusher)
clave_daemon_run()
