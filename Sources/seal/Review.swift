import AppKit
import LocalAuthentication
import SealCore

/// The window Seal shows for a Signing request: a flat list (for a commit: Branch, Author, Committer when it
/// differs, Message, one Changes block per parent; for a tag: Tag, Tagged, Tagger, Message, Changes) with Deny and
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
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 560),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Seal: sign \(objectNoun)"
        window.level = .floating
        window.isReleasedWhenClosed = false

        var rows: [NSView] = []
        switch request.object {
        case .commit(let commit):
            rows += labelled("Branch", request.branch)
            rows += labelled("Author", commit.author)
            if commit.committer != commit.author {
                rows += labelled("Committer", commit.committer)
            }
        case .tag(let tag):
            rows += labelled("Tag", tag.name)
            rows += labelled("Tagged", "\(tag.object.prefix(7)) (\(tag.type))")
            rows += labelled("Tagger", tag.tagger)
        }
        rows += labelled("Message", request.message, expanding: true)
        for changes in request.changes {
            rows += labelled(changesTitle(for: changes), changes.stat.isEmpty ? "(no changes)" : changes.stat)
        }

        let deny = NSButton(title: "Deny", target: self, action: #selector(deny(_:)))
        deny.keyEquivalent = "\u{1b}"
        let authorize = NSButton(title: "Authorize with Touch ID", target: self, action: #selector(approve(_:)))
        authorize.keyEquivalent = "\r"
        let buttons = NSStackView(views: [deny, authorize])
        buttons.orientation = .horizontal
        buttons.alignment = .centerY

        let column = NSStackView(views: rows + [buttons])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        column.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        column.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate(
            rows.compactMap { $0 as? NSScrollView }.map { $0.widthAnchor.constraint(equalTo: column.widthAnchor, constant: -32) }
                + [buttons.trailingAnchor.constraint(equalTo: column.trailingAnchor, constant: -16)]
        )
        window.contentView = column
        return window
    }

    /// A bold title and a read-only monospaced text below it. Expanding rows take the spare height.
    private func labelled(_ title: String, _ text: String, expanding: Bool = false) -> [NSView] {
        let label = NSTextField(labelWithString: title)
        label.font = .boldSystemFont(ofSize: NSFont.systemFontSize)

        let view = NSTextView()
        view.isEditable = false
        view.isSelectable = true
        view.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        view.string = text
        view.textContainerInset = NSSize(width: 4, height: 4)
        view.autoresizingMask = [.width]
        view.isVerticallyResizable = true
        view.textContainer?.widthTracksTextView = true
        let scroll = NSScrollView()
        scroll.documentView = view
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        if expanding {
            scroll.setContentHuggingPriority(.defaultLow, for: .vertical)
        } else {
            let lines = max(1, min(text.split(separator: "\n", omittingEmptySubsequences: false).count, 12))
            let lineHeight = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular).boundingRectForFont.height
            scroll.heightAnchor.constraint(equalToConstant: CGFloat(lines) * lineHeight + 12).isActive = true
        }
        return [label, scroll]
    }

    private var objectNoun: String {
        switch request.object {
        case .commit: return "commit"
        case .tag: return "tag"
        }
    }

    /// "Changes" for a single parent, "Changes vs <short hash>" for each parent of a merge,
    /// "Changes (root commit)" against the empty tree, and plain "Changes" for a tag on a non-commit.
    private func changesTitle(for changes: ChangeSummary) -> String {
        guard let parent = changes.parent else {
            if case .tag(let tag) = request.object, tag.type != "commit" { return "Changes" }
            return "Changes (root commit)"
        }
        guard request.changes.count > 1 else { return "Changes" }
        return "Changes vs \(parent.prefix(7))"
    }

    @objc private func deny(_ sender: Any?) {
        finish(with: .denial)
    }

    @objc private func approve(_ sender: Any?) {
        let context = LAContext()
        context.localizedReason = "sign the \(objectNoun) shown in the Review"
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
