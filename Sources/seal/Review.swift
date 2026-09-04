import AppKit
import LocalAuthentication
import SealCore

/// The window Seal shows for a Signing request: a flat list (today only Message) with Deny and
/// Authorize with Touch ID. Raised by this process, floating and activated, gone when the process exits.
/// Approval is a successful LocalAuthentication evaluation with the device-owner policy; anything else is denial.
final class Review: NSObject, NSWindowDelegate {
    private let request: SigningRequest
    private var decision: Decision?
    private var window: NSWindow!

    init(_ request: SigningRequest) {
        self.request = request
    }

    /// Shows the window and blocks until the author decides or the window closes.
    func awaitDecision() -> Decision {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        window = makeWindow()
        window.delegate = self
        window.center()
        app.activate(ignoringOtherApps: true)
        app.runModal(for: window)
        return decision ?? .denial
    }

    private func makeWindow() -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 360),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Seal: sign commit"
        window.level = .floating
        window.isReleasedWhenClosed = false

        let label = NSTextField(labelWithString: "Message")
        label.font = .boldSystemFont(ofSize: NSFont.systemFontSize)

        let message = NSTextView()
        message.isEditable = false
        message.isSelectable = true
        message.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        message.string = request.message
        message.textContainerInset = NSSize(width: 4, height: 4)
        message.autoresizingMask = [.width]
        message.isVerticallyResizable = true
        message.textContainer?.widthTracksTextView = true
        let scroll = NSScrollView()
        scroll.documentView = message
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.setContentHuggingPriority(.defaultLow, for: .vertical)

        let deny = NSButton(title: "Deny", target: self, action: #selector(deny(_:)))
        deny.keyEquivalent = "\u{1b}"
        let authorize = NSButton(title: "Authorize with Touch ID", target: self, action: #selector(approve(_:)))
        authorize.keyEquivalent = "\r"
        let buttons = NSStackView(views: [deny, authorize])
        buttons.orientation = .horizontal
        buttons.alignment = .centerY

        let column = NSStackView(views: [label, scroll, buttons])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        column.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        column.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            scroll.widthAnchor.constraint(equalTo: column.widthAnchor, constant: -32),
            buttons.trailingAnchor.constraint(equalTo: column.trailingAnchor, constant: -16),
        ])
        window.contentView = column
        return window
    }

    @objc private func deny(_ sender: Any?) {
        finish(with: .denial)
    }

    @objc private func approve(_ sender: Any?) {
        let context = LAContext()
        context.localizedReason = "sign the commit shown in the Review"
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: context.localizedReason) { success, _ in
            DispatchQueue.main.async { self.finish(with: success ? .approval : .denial) }
        }
    }

    func windowWillClose(_ notification: Notification) {
        finish(with: .denial)
    }

    /// The first decision wins: a Touch ID result arriving after Deny or after the window closed is ignored.
    private func finish(with decision: Decision) {
        guard self.decision == nil else { return }
        self.decision = decision
        window.delegate = nil
        window.close()
        NSApplication.shared.stopModal()
    }
}
