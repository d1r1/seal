import Foundation

/// The fields of the approval card (ADR 0002, point 5), computed from a Signing request alone so that the
/// window only lays them out. Everything the signature covers comes from the object body; the attestation
/// lines are a stub in this step and say so.
public struct Card: Equatable {
    /// `<repository directory name> · <branch>`, or `· tag <name>` for a tag.
    public let header: String
    /// The two attestation lines, implementer then reviewer. Stub: always ✅, labelled "stub: not checked".
    public let attestations: [String]
    /// The message's first line.
    public let title: String
    /// The rest of the message, trailing newlines trimmed, or nil when the message is the title alone.
    public let body: String?
    /// The `Problem:`, `Why:` and `Risks:` trailers, or "—" when absent.
    public let problem: String
    public let why: String
    public let risks: String
    /// `<files> · +<insertions> −<deletions> · parent <short> → tree <short>`; a merge lists its parents instead
    /// of the counts; a tag shows `tag → <type> <short>`.
    public let summary: String

    public static let absent = "—"

    public init(_ request: SigningRequest) {
        let directory = URL(fileURLWithPath: request.origin.directory).lastPathComponent
        let place: String
        switch request.object {
        case .commit: place = request.branch
        case .tag(let tag): place = "tag \(tag.name)"
        }
        header = "\(directory) · \(place)"
        attestations = ["🤖 implementer  ✅ stub: not checked", "🔍 reviewer     ✅ stub: not checked"]

        let message = request.message.trimmingCharacters(in: .newlines)
        let lines = message.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        title = lines.first ?? ""
        let rest = lines.dropFirst().joined(separator: "\n").trimmingCharacters(in: .newlines)
        body = rest.isEmpty ? nil : rest

        let trailers = Self.trailers(of: message)
        problem = trailers["problem"] ?? Self.absent
        why = trailers["why"] ?? Self.absent
        risks = trailers["risks"] ?? Self.absent

        summary = Self.summary(of: request)
    }

    /// git's trailer block: the last paragraph, when every line in it is `Key: value` or an indented continuation.
    /// Values are joined with single spaces; keys are matched case-insensitively.
    static func trailers(of message: String) -> [String: String] {
        guard let paragraph = message.components(separatedBy: "\n\n").last else { return [:] }
        var found: [String: String] = [:]
        var current: String?
        for line in paragraph.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            if line.first?.isWhitespace == true, let key = current {
                found[key, default: ""] += " " + line.trimmingCharacters(in: .whitespaces)
            } else if let match = line.range(of: "^[A-Za-z][A-Za-z0-9-]*: ", options: .regularExpression) {
                let key = String(line[..<match.upperBound].dropLast(2)).lowercased()
                found[key] = String(line[match.upperBound...]).trimmingCharacters(in: .whitespaces)
                current = key
            } else {
                return [:]
            }
        }
        return found
    }

    private static func summary(of request: SigningRequest) -> String {
        switch request.object {
        case .commit(let commit):
            if commit.parents.count > 1 {
                return "parents \(commit.parents.map { $0.prefix(7) }.joined(separator: ", ")) → tree \(commit.tree.prefix(7))"
            }
            let from = commit.parents.first.map { "parent \($0.prefix(7))" } ?? "no parent"
            return "\(counts(of: request.changes.first)) · \(from) → tree \(commit.tree.prefix(7))"
        case .tag(let tag):
            return "\(counts(of: request.changes.first)) · tag → \(tag.type) \(tag.object.prefix(7))"
        }
    }

    /// `N files · +I −D` from the stat's summary line (`N file(s) changed, I insertion(s)(+), D deletion(s)(-)`).
    static func counts(of changes: ChangeSummary?) -> String {
        guard let last = changes?.stat.split(separator: "\n").last else { return "no changes" }
        func number(before word: String) -> Int {
            guard let range = last.range(of: "[0-9]+ \(word)", options: .regularExpression) else { return 0 }
            return Int(last[range].split(separator: " ")[0]) ?? 0
        }
        let files = number(before: "files?"), insertions = number(before: "insertions?"), deletions = number(before: "deletions?")
        guard files > 0 else { return "no changes" }
        return "\(files) \(files == 1 ? "file" : "files") · +\(insertions) −\(deletions)"
    }
}
