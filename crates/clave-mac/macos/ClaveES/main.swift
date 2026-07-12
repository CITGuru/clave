// ClaveES — containing app for the Endpoint Security System Extension.
//
// Its only job in this dev scaffold is lifecycle: request activation of the ES extension
// (OSSystemExtensionRequest) and surface the result. In production this role is filled by the
// privileged launchd daemon / menu-bar controller (doc 14 §1.1); here it is a minimal AppKit app
// so the extension can be loaded and iterated on a SIP-disabled dev Mac.

import AppKit
import OSLog
import SystemExtensions

let extensionIdentifier = "com.clave.ClaveES.ESClient"
let log = Logger(subsystem: "com.clave.ClaveES", category: "activation")

final class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    static let shared = ExtensionManager()

    @objc func activate() {
        log.info("Requesting activation of \(extensionIdentifier, privacy: .public)")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    @objc func deactivate() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // Replacing an already-installed build: always take the new one during development.
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        log.info("Replacing \(existing.bundleVersion, privacy: .public) with \(ext.bundleVersion, privacy: .public)")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log.notice("Extension needs user approval — approve it in System Settings ▸ General ▸ Login Items & Extensions.")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        log.notice("Activation finished: \(result.rawValue, privacy: .public)")
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        log.error("Activation failed: \(error.localizedDescription, privacy: .public)")
    }
}

// A trivial AppKit shell: one window with Activate / Deactivate buttons.
final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!

    func applicationDidFinishLaunching(_ notification: Notification) {
        let frame = NSRect(x: 0, y: 0, width: 420, height: 160)
        window = NSWindow(
            contentRect: frame,
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Clave Endpoint Security"
        window.center()

        let activate = NSButton(title: "Activate Extension", target: ExtensionManager.shared, action: #selector(ExtensionManager.activate))
        let deactivate = NSButton(title: "Deactivate", target: ExtensionManager.shared, action: #selector(ExtensionManager.deactivate))
        let stack = NSStackView(views: [activate, deactivate])
        stack.orientation = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView(frame: frame)
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: content.centerYAnchor),
        ])
        window.contentView = content
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
