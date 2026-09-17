import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SealCore

/// The window Seal shows for a Signing request: the approval card (ADR 0002, point 5), laid out like
/// terminal output:
///
///     🔏 Sign?  fluent-connect-service · feat/widget
///     ~/dev/ws/fluent-connect-service  │  design: Seal signs with FROST
///     Author:    d1r1 <me@d1r1.me>
///     ────────────────────────────────────────
///     🤖 implementer  ✅ stub: not checked
///     🔍 reviewer     ✅ stub: not checked
///     🧑 you          ⏳ Touch ID
///     ────────────────────────────────────────
///     📝 feat(widget): read Privy id from session        ▸ expand
///     🐛 Problem  widget asked Privy twice
///     💡 Why      one source (session)
///     ⚠️ Risks    —
///     📊 4 files · +70 −50 · parent a1b2c3d → tree e4f5a6b
///     <diff --stat as git prints it>
///
///     [Touch ID glyph]  Touch ID to sign · Esc to deny
///
/// Touch ID is the only action. For the group key it is the Secure Enclave unwrapping the user's share
/// through the window's own `LAContext`: success is the Approval and carries the share; a cancelled prompt is
/// Denial; any other unwrap error is reported as a Key holder failure. For the personal key it is a
/// LocalAuthentication evaluation with the device-owner policy, as before. The prompt is raised as soon as
/// the window becomes key; Escape, cancelling, or closing the window is Denial. Return asks again.
/// Only the key window prompts, so overlapping cards ask one at a time.
final class CardWindow: NSObject, NSWindowDelegate {
    private let request: SigningRequest
    private let card: Card
    private let group: GroupKey
    private var decision: Decision?
    private var window: NSWindow!
    /// One context for the life of the window; the embedded glyph and the enclave key are bound to it.
    private let prompt = LAContext()
    private var prompting = false
    private var bodyView: NSView?
    private var expander: NSButton?

    init(_ request: SigningRequest, group: GroupKey) {
        self.request = request
        self.card = Card(request)
        self.group = group
    }

    /// Shows the window and blocks until the author decides or the window closes.
    func awaitDecision() -> Decision {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        window = makeWindow()
        let keys = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [unowned self] in handle($0) }
        defer { if let keys { NSEvent.removeMonitor(keys) } }
        window.delegate = self
        window.center()
        app.activate(ignoringOtherApps: true)
        app.runModal(for: window)
        return decision ?? .denial
    }

    func windowDidBecomeKey(_ notification: Notification) {
        askForTouchID()
    }

    private func handle(_ event: NSEvent) -> NSEvent? {
        guard event.window === window else { return event }
        switch event.keyCode {
        case 53: finish(with: .denial); return nil       // Escape
        case 36, 76: askForTouchID(); return nil         // Return, keypad Enter
        default: return event
        }
    }

    /// One prompt at a time per window: a second call while one is running does nothing.
    private func askForTouchID() {
        guard decision == nil, !prompting else { return }
        prompting = true
        prompt.localizedCancelTitle = "Deny"
        let reason = "sign the \(objectNoun) shown in the card"
        switch request.keyHolder {
        case .group:
            // The enclave raises the prompt itself during the key agreement; it blocks, so it runs off the main thread.
            prompt.localizedReason = reason
            DispatchQueue.global(qos: .userInitiated).async {
                let outcome: Decision
                do {
                    outcome = .approval(try UserShare.unwrap(self.group, context: self.prompt))
                } catch {
                    outcome = Self.isCancellation(error) ? .denial : .failure("cannot unwrap the user share: \(error)")
                }
                DispatchQueue.main.async {
                    self.prompting = false
                    self.finish(with: outcome)
                }
            }
        case .personal:
            prompt.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
                DispatchQueue.main.async {
                    self.prompting = false
                    self.finish(with: success ? .approval() : .denial)
                }
            }
        }
    }

    /// The user's cancel (Deny, Escape on the system prompt, or the context invalidated by Escape here) is
    /// Denial; everything else about the enclave or the file is a failure worth reporting.
    private static func isCancellation(_ error: Error) -> Bool {
        let nsError = error as NSError
        if nsError.domain == LAErrorDomain {
            return [LAError.userCancel, .appCancel, .systemCancel, .userFallback].map(\.rawValue).contains(nsError.code)
        }
        return "\(error)".lowercased().contains("cancel")
    }

    func windowWillClose(_ notification: Notification) {
        finish(with: .denial)
    }

    /// The first decision wins: a Touch ID result arriving after Escape or after the window closed is ignored,
    /// and a prompt still running is taken down.
    private func finish(with decision: Decision) {
        guard self.decision == nil else { return }
        self.decision = decision
        prompt.invalidate()
        window.delegate = nil
        window.close()
        NSApplication.shared.stopModal()
    }

    // MARK: Layout

    private static let width: CGFloat = 760
    private static let margin: CGFloat = 20
    private static let body = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    private static let small = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
    private static let statLimit = 12

    private func makeWindow() -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 300),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Seal"
        window.level = .floating
        window.isReleasedWhenClosed = false

        var sections: [NSView] = [
            text("🔏 Sign?  \(card.header)", font: Self.body),
            text(whereLine, font: Self.small, color: .secondaryLabelColor),
            text(whoLines, font: Self.body),
            rule(),
            text((card.attestations + ["🧑 you          ⏳ Touch ID"]).joined(separator: "\n"), font: Self.body),
            rule(),
            titleRow(),
        ]
        let body = text(card.body.map { $0.split(separator: "\n", omittingEmptySubsequences: false).map { "   \($0)" }.joined(separator: "\n") } ?? "",
                        font: Self.small, color: .secondaryLabelColor)
        body.isHidden = true
        bodyView = body
        sections.append(body)
        sections.append(text(["🐛 Problem  \(card.problem)", "💡 Why      \(card.why)", "⚠️ Risks    \(card.risks)"].joined(separator: "\n"),
                             font: Self.body))
        sections.append(text("📊 \(card.summary)", font: Self.body))
        for changes in request.changes {
            sections.append(statBlock(changes))
        }
        sections.append(footer())

        let column = NSStackView(views: sections)
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 12
        column.setCustomSpacing(2, after: sections[0])
        column.setCustomSpacing(2, after: sections[1])
        column.setCustomSpacing(4, after: sections[6])
        column.edgeInsets = NSEdgeInsets(top: Self.margin, left: Self.margin, bottom: Self.margin, right: Self.margin)
        column.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate(
            [column.widthAnchor.constraint(equalToConstant: Self.width)]
                + sections.map { $0.widthAnchor.constraint(equalTo: column.widthAnchor, constant: -2 * Self.margin) }
        )
        window.contentView = column
        fit(window, to: column)
        return window
    }

    private func fit(_ window: NSWindow, to column: NSStackView) {
        column.layoutSubtreeIfNeeded()
        let height = min(column.fittingSize.height, (NSScreen.main?.visibleFrame.height ?? 900) - 80)
        window.setContentSize(NSSize(width: Self.width, height: height))
    }

    /// `📝 <title>` with `▸ expand` when the message has a body.
    private func titleRow() -> NSView {
        let title = text("📝 \(card.title)", font: Self.body)
        guard card.body != nil else { return title }
        let button = NSButton(title: "▸ expand", target: self, action: #selector(toggleBody))
        button.bezelStyle = .inline
        button.font = Self.small
        button.setContentHuggingPriority(.required, for: .horizontal)
        expander = button
        let row = NSStackView(views: [title, button])
        row.orientation = .horizontal
        row.alignment = .firstBaseline
        row.spacing = 12
        return row
    }

    @objc private func toggleBody() {
        guard let bodyView, let expander else { return }
        bodyView.isHidden.toggle()
        expander.title = bodyView.isHidden ? "▸ expand" : "▾ collapse"
        if let column = window.contentView as? NSStackView { fit(window, to: column) }
    }

    /// `~/path │ session`: the Origin, for orientation.
    private var whereLine: String {
        [abbreviated(request.origin.directory), request.origin.session].joined(separator: "  \u{2502}  ")
    }

    private var whoLines: String {
        switch request.object {
        case .commit(let commit):
            var lines = ["Author:    \(identity(commit.author))"]
            if commit.committer != commit.author { lines.append("Committer: \(identity(commit.committer))") }
            return lines.joined(separator: "\n")
        case .tag(let tag):
            return "Tagger:    \(identity(tag.tagger))\nTagged:    \(tag.type) \(tag.object.prefix(7))"
        }
    }

    private func rule() -> NSView {
        let line = NSBox()
        line.boxType = .separator
        line.translatesAutoresizingMaskIntoConstraints = false
        return line
    }

    /// `diff --stat` as git prints it; scrolls past `statLimit` lines. Merges label each block by parent.
    private func statBlock(_ changes: ChangeSummary) -> NSView {
        var views: [NSView] = []
        if request.changes.count > 1, let parent = changes.parent {
            views.append(text("vs \(parent.prefix(7))", font: Self.small, color: .secondaryLabelColor))
        }
        let stat = changes.stat.isEmpty ? "no changes" : changes.stat
        let lines = stat.split(separator: "\n", omittingEmptySubsequences: false).count
        if lines > Self.statLimit {
            views.append(scrolling(stat, lines: Self.statLimit))
        } else {
            views.append(text(stat, font: Self.small))
        }
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        views.compactMap { $0 as? NSScrollView }.forEach { $0.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true }
        return stack
    }

    private func scrolling(_ string: String, lines: Int) -> NSScrollView {
        let view = NSTextView()
        view.isEditable = false
        view.isSelectable = true
        view.drawsBackground = false
        view.font = Self.small
        view.string = string
        view.textContainerInset = .zero
        view.autoresizingMask = [.width]
        view.isVerticallyResizable = true
        view.textContainer?.widthTracksTextView = true
        view.textContainer?.lineFragmentPadding = 0
        let scroll = NSScrollView()
        scroll.documentView = view
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(equalToConstant: CGFloat(lines) * Self.small.boundingRectForFont.height).isActive = true
        return scroll
    }

    private func footer() -> NSView {
        let hint = text("Touch ID to sign \u{00B7} Esc to deny", font: Self.small, color: .secondaryLabelColor)
        let glyph = LAAuthenticationView(context: prompt)
        glyph.translatesAutoresizingMaskIntoConstraints = false
        let stack = NSStackView(views: [glyph, hint])
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 12
        return stack
    }

    /// Selectable, non-wrapping monospaced text; long lines truncate in the middle with the full text as tooltip.
    private func text(_ string: String, font: NSFont, color: NSColor = .labelColor) -> NSTextField {
        let field = NSTextField(labelWithString: string)
        field.font = font
        field.textColor = color
        field.isSelectable = true
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byTruncatingMiddle
        field.cell?.wraps = false
        field.cell?.isScrollable = false
        field.toolTip = string.contains("\n") ? nil : string
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return field
    }

    /// "Name <email>" without git's timestamp and zone.
    private func identity(_ raw: String) -> String {
        guard let close = raw.range(of: ">", options: .backwards) else { return raw }
        return String(raw[...close.lowerBound])
    }

    private func abbreviated(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }

    private var objectNoun: String {
        switch request.object {
        case .commit: return "commit"
        case .tag: return "tag"
        }
    }
}
