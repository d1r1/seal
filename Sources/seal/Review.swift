import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SealCore

/// The window Seal shows for a Signing request, laid out like terminal output:
///
///     ~/dev/src/github.com/d1r1/seal │ main │ seal-touch-id
///     Author: d1r1 <me@d1r1.me>
///
///     git commit "subject
///
///         body"
///
///     <diff --stat as git prints it>
///
///     [Touch ID glyph]  Touch ID to sign · Esc to deny
///
/// Approval is a successful LocalAuthentication evaluation with the device-owner policy; anything else is denial.
/// The Touch ID prompt is raised as soon as the window becomes key, so the finger is the only gesture; Escape,
/// cancelling the prompt, or closing the window is Denial. Return asks again after an accidental dismissal.
/// Only the key window prompts, so overlapping Reviews ask one at a time.
final class Review: NSObject, NSWindowDelegate {
    private let request: SigningRequest
    private var decision: Decision?
    private var window: NSWindow!
    /// One context for the life of the window; the embedded glyph is bound to it.
    private let prompt = LAContext()
    private var prompting = false

    init(_ request: SigningRequest) {
        self.request = request
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

    /// One evaluation at a time per window: a second call while one is running does nothing.
    private func askForTouchID() {
        guard decision == nil, !prompting else { return }
        prompting = true
        prompt.localizedCancelTitle = "Deny"
        prompt.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "sign the \(objectNoun) shown in the Review") { success, _ in
            DispatchQueue.main.async {
                self.prompting = false
                self.finish(with: success ? .approval : .denial)
            }
        }
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
    private static let statLimit = 15

    private func makeWindow() -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 300),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Seal"
        window.level = .floating
        window.isReleasedWhenClosed = false

        var sections: [NSView] = [text(whereLine, font: Self.body, color: .secondaryLabelColor), text(whoLines, font: Self.body)]
        sections.append(text(commandLines, font: Self.body))
        for changes in request.changes {
            sections.append(statBlock(changes))
        }
        sections.append(footer())

        let column = NSStackView(views: sections)
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 14
        column.setCustomSpacing(2, after: sections[0])
        column.edgeInsets = NSEdgeInsets(top: Self.margin, left: Self.margin, bottom: Self.margin, right: Self.margin)
        column.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate(
            [column.widthAnchor.constraint(equalToConstant: Self.width)]
                + sections.map { $0.widthAnchor.constraint(equalTo: column.widthAnchor, constant: -2 * Self.margin) }
        )
        column.layoutSubtreeIfNeeded()
        let height = min(column.fittingSize.height, (NSScreen.main?.visibleFrame.height ?? 900) - 80)
        window.setContentSize(NSSize(width: Self.width, height: height))
        window.contentView = column
        return window
    }

    /// `~/path │ branch │ session`; a tag shows its name in place of the branch.
    private var whereLine: String {
        let place: String
        switch request.object {
        case .commit: place = request.branch
        case .tag(let tag): place = "tag \(tag.name)"
        }
        return [abbreviated(request.origin.directory), place, request.origin.session].joined(separator: "  \u{2502}  ")
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

    /// `git commit "subject` … `body"`: the signed message verbatim inside the quotes, body indented four spaces.
    private var commandLines: String {
        let verb: String
        switch request.object {
        case .commit: verb = "git commit"
        case .tag(let tag): verb = "git tag \(tag.name)"
        }
        let message = request.message.trimmingCharacters(in: .newlines)
        let lines = message.split(separator: "\n", omittingEmptySubsequences: false)
        guard let subject = lines.first else { return "\(verb) \"\"" }
        let rest = lines.dropFirst().map { $0.isEmpty ? "" : "    \($0)" }
        return "\(verb) \"" + ([String(subject)] + rest).joined(separator: "\n") + "\""
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
