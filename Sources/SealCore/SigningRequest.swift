import Foundation

/// One invocation of Seal by git to sign a single object, derived from the object body git handed over.
/// Everything the Review shows comes from here.
public struct SigningRequest: Equatable {
    /// Where the request came from; shown first in the Review.
    public let origin: Origin
    /// The commit or tag being signed, with its headers as git wrote them.
    public let object: SignedObject
    /// The message exactly as it will land in history, trailing newline included.
    public let message: String
    /// The symbolic ref of `HEAD` in the working directory, or "detached". Shown for orientation; not part of the signed body.
    public let branch: String
    /// For a commit: one summary per parent (one against the empty tree for a root commit). For a tag: the tagged
    /// commit's own summaries, or a single line saying what the tag points at. Computed from the hashes in the
    /// signed body so it cannot differ from what is signed.
    public let changes: [ChangeSummary]
    /// The Key holder this request goes to: the group when `-f` names the group key, the personal key otherwise.
    public let keyHolder: KeyHolderKind
    /// The object body exactly as git wrote it to the buffer file; the notary receives it verbatim.
    let body: String
    /// The `-n` value git gave, `git` for commits and tags; the notary signs with it.
    let namespace: String
    /// The contents of the `-f` public key file, one line, trailing newline stripped; nil unless the file holds a
    /// single OpenSSH public key line. For the personal key `-f` may name a private key file, which only
    /// `ssh-keygen` reads; it must never reach the notary.
    let keyLine: String?

    /// The arguments git gave for `-Y sign`, handed to the Key holder unchanged (`-U` selects the agent).
    let arguments: [String]
    let bufferFile: URL

    struct Malformed: Error {
        let reason: String
    }

    /// Reads the arguments git passes for `-Y sign` and parses the object body in the buffer file.
    static func parse(arguments: [String], origin: Origin, in repository: Repository, group: GroupKey) throws -> SigningRequest {
        let scanned = SignArguments(arguments)
        if let option = scanned.danglingOption { throw Malformed(reason: "option \(option) has no value") }
        guard let publicKeyFile = scanned.options["-f"] else { throw Malformed(reason: "no -f key file given") }
        guard let namespace = scanned.options["-n"] else { throw Malformed(reason: "no -n namespace given") }
        guard scanned.positional.count == 1, let bufferPath = scanned.positional.first else {
            throw Malformed(reason: "expected exactly one buffer file, got \(scanned.positional.count)")
        }
        let bufferFile = URL(fileURLWithPath: bufferPath)
        guard let data = FileManager.default.contents(atPath: bufferPath) else {
            throw Malformed(reason: "cannot read buffer file \(bufferPath)")
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw Malformed(reason: "buffer file is not UTF-8")
        }
        let parsed = try ObjectBody.parse(body)
        let changes: [ChangeSummary]
        switch parsed.object {
        case .commit(let commit):
            changes = repository.changes(from: commit.parents, to: commit.tree)
        case .tag(let tag):
            changes = repository.changes(ofTagged: tag)
        }
        return SigningRequest(origin: origin, object: parsed.object, message: parsed.message, branch: repository.branch(),
                              changes: changes, keyHolder: group.isGroupKey(fileAt: publicKeyFile) ? .group : .personal,
                              body: body, namespace: namespace, keyLine: keyLine(fileAt: publicKeyFile),
                              arguments: arguments, bufferFile: bufferFile)
    }

    /// One OpenSSH public key line, as `ssh-keygen` reads it: a key type, the base64 blob, an optional comment,
    /// separated by spaces or tabs, where the blob starts with its own length-prefixed type. Only whitespace may
    /// follow on later lines. The line comes back with just its line end (`\n` or `\r\n`) removed. Anything
    /// else, a private key file included, reads as nil.
    private static func keyLine(fileAt path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path), let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        // Scalars, not Characters: `\r\n` is a single Character and would hide a line break.
        let lines = text.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: false).map { line -> String in
            let scalars = line.last == "\r" ? line.dropLast() : line
            return String(String.UnicodeScalarView(scalars))
        }
        guard let line = lines.first,
              lines.dropFirst().allSatisfy({ $0.unicodeScalars.allSatisfy(CharacterSet.whitespaces.contains) })
        else { return nil }
        let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard tokens.count >= 2, let blob = Data(base64Encoded: String(tokens[1])),
              blobHeader(blob) == Array(tokens[0].utf8) else { return nil }
        return line
    }

    /// The type string at the start of a key blob: a big-endian uint32 length, then that many bytes.
    private static func blobHeader(_ blob: Data) -> [UInt8]? {
        let bytes = Array(blob)
        guard bytes.count >= 4 else { return nil }
        let length = bytes[0..<4].reduce(0) { $0 << 8 | Int($1) }
        guard length > 0, bytes.count >= 4 + length else { return nil }
        return Array(bytes[4..<(4 + length)])
    }
}

/// The options and positional arguments of `-Y sign`, read without failing: every option but `-U` takes the
/// next argument as its value, and an option left without one is reported rather than thrown, so the buffer
/// file is known even when the request is malformed.
struct SignArguments {
    private(set) var options: [String: String] = [:]
    private(set) var positional: [String] = []
    private(set) var danglingOption: String?

    init(_ arguments: [String]) {
        var index = arguments.startIndex
        while index < arguments.endIndex {
            let argument = arguments[index]
            if argument == "-U" {
                // Bare flag: sign with the agent that holds the key named by `-f`.
            } else if argument.hasPrefix("-") {
                index += 1
                guard index < arguments.endIndex else { danglingOption = argument; return }
                options[argument] = arguments[index]
            } else {
                positional.append(argument)
            }
            index += 1
        }
    }
}

/// The object git is signing, told apart by its headers: a commit body starts with `tree`, a tag body with `object`.
public enum SignedObject: Equatable {
    case commit(Commit)
    case tag(Tag)

    public struct Commit: Equatable {
        public let tree: String
        public let parents: [String]
        public let author: String
        public let committer: String
    }

    public struct Tag: Equatable {
        /// The tag name from the `tag` header (the ref is `refs/tags/<name>`).
        public let name: String
        /// The hash of the tagged object and its type (`commit`, `tree`, `blob`, or `tag`).
        public let object: String
        public let type: String
        public let tagger: String
    }
}

/// The headers and message of an object body, exactly as git wrote them.
struct ObjectBody {
    let object: SignedObject
    let message: String

    /// An object body is a run of `key value` header lines, a blank line, and the message verbatim.
    static func parse(_ body: String) throws -> ObjectBody {
        guard let separator = body.range(of: "\n\n") else {
            throw SigningRequest.Malformed(reason: "object body has no message separator")
        }
        let headerLines = body[..<separator.lowerBound].split(separator: "\n", omittingEmptySubsequences: false)
        let message = String(body[separator.upperBound...])

        var headers: [(key: String, value: String)] = []
        for line in headerLines {
            if line.hasPrefix(" ") {
                // Continuation of a multi-line header (for example `gpgsig`); nothing here needs it.
                guard !headers.isEmpty else { throw SigningRequest.Malformed(reason: "object header starts with a continuation line") }
                continue
            }
            guard let space = line.firstIndex(of: " ") else {
                throw SigningRequest.Malformed(reason: "object header line without a value: \(line)")
            }
            headers.append((String(line[..<space]), String(line[line.index(after: space)...])))
        }
        func first(_ key: String) -> String? { headers.first { $0.key == key }?.value }
        func require(_ key: String, in kind: String) throws -> String {
            guard let value = first(key) else { throw SigningRequest.Malformed(reason: "\(kind) body has no \(key)") }
            return value
        }

        switch headers.first?.key {
        case "tree":
            let commit = SignedObject.Commit(tree: try require("tree", in: "commit"),
                                             parents: headers.filter { $0.key == "parent" }.map(\.value),
                                             author: try require("author", in: "commit"),
                                             committer: try require("committer", in: "commit"))
            return ObjectBody(object: .commit(commit), message: message)
        case "object":
            let tag = SignedObject.Tag(name: try require("tag", in: "tag"),
                                       object: try require("object", in: "tag"),
                                       type: try require("type", in: "tag"),
                                       tagger: try require("tagger", in: "tag"))
            return ObjectBody(object: .tag(tag), message: message)
        case let key?:
            throw SigningRequest.Malformed(reason: "object body starts with '\(key)', not 'tree' or 'object'")
        case nil:
            throw SigningRequest.Malformed(reason: "object body has no headers")
        }
    }
}

/// `diff --stat` between one parent's tree and the signed tree, as git prints it.
public struct ChangeSummary: Equatable {
    /// The parent hash of the summarised commit, or nil for a root commit (summary against the empty tree)
    /// and for a tag that does not point at a commit.
    public let parent: String?
    public let stat: String
}

/// The author's decision inside the card. Only Approval leads to a signature. For the group key the Approval
/// is the unwrap of the user's share and carries it (ADR 0002, point 4); for the personal key it carries nothing.
/// `failure` is the card reporting that it could not take the decision at all (the sealed share would not open
/// for a reason other than the user's cancel); it ends as a Key holder failure.
public enum Decision {
    case approval(SecretShare? = nil)
    case denial
    case failure(String)
}

/// Which Key holder a Signing request selects, by the key git named with `-f`.
public enum KeyHolderKind: Equatable {
    /// The FROST group: Seal's share plus the user's share, aggregated by the helper.
    case group
    /// The SSH agent behind `SSH_AUTH_SOCK` (or a key file), through `ssh-keygen -Y sign`, as in ADR 0001.
    case personal
}
