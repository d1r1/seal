import Foundation

/// One invocation of Seal by git to sign a single object, derived from the object body git handed over.
/// Everything the Review shows comes from here.
public struct SigningRequest: Equatable {
    public let tree: String
    public let parents: [String]
    public let author: String
    public let committer: String
    /// The commit message exactly as it will land in history, trailing newline included.
    public let message: String
    /// The symbolic ref of `HEAD` in the working directory, or "detached". Shown for orientation; not part of the signed body.
    public let branch: String
    /// One summary per parent (one against the empty tree for a root commit), computed from the hashes
    /// in the signed body so it cannot differ from what is signed.
    public let changes: [ChangeSummary]

    /// The arguments git gave for `-Y sign`, handed to the Key holder unchanged (`-U` selects the agent).
    let arguments: [String]
    let bufferFile: URL

    struct Malformed: Error {
        let reason: String
    }

    /// Reads the arguments git passes for `-Y sign` and parses the commit body in the buffer file.
    static func parse(arguments: [String], in repository: Repository) throws -> SigningRequest {
        var publicKeyFile: String?
        var positional: [String] = []
        var index = arguments.startIndex
        while index < arguments.endIndex {
            let argument = arguments[index]
            if argument == "-U" {
                // Bare flag: sign with the agent that holds the key named by `-f`.
            } else if argument.hasPrefix("-") {
                // Every other `ssh-keygen -Y sign` option takes a value.
                index += 1
                guard index < arguments.endIndex else { throw Malformed(reason: "option \(argument) has no value") }
                if argument == "-f" { publicKeyFile = arguments[index] }
            } else {
                positional.append(argument)
            }
            index += 1
        }
        guard publicKeyFile != nil else { throw Malformed(reason: "no -f key file given") }
        guard positional.count == 1, let bufferPath = positional.first else {
            throw Malformed(reason: "expected exactly one buffer file, got \(positional.count)")
        }
        let bufferFile = URL(fileURLWithPath: bufferPath)
        guard let data = FileManager.default.contents(atPath: bufferPath) else {
            throw Malformed(reason: "cannot read buffer file \(bufferPath)")
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw Malformed(reason: "buffer file is not UTF-8")
        }
        let commit = try CommitBody.parse(body)
        return SigningRequest(tree: commit.tree, parents: commit.parents, author: commit.author,
                              committer: commit.committer, message: commit.message,
                              branch: repository.branch(),
                              changes: repository.changes(from: commit.parents, to: commit.tree),
                              arguments: arguments, bufferFile: bufferFile)
    }
}

/// The headers and message of a commit body, exactly as git wrote them.
struct CommitBody {
    let tree: String
    let parents: [String]
    let author: String
    let committer: String
    let message: String

    /// A commit body is a run of `key value` header lines, a blank line, and the message verbatim.
    static func parse(_ body: String) throws -> CommitBody {
        guard let separator = body.range(of: "\n\n") else {
            throw SigningRequest.Malformed(reason: "commit body has no message separator")
        }
        let headerLines = body[..<separator.lowerBound].split(separator: "\n", omittingEmptySubsequences: false)
        let message = String(body[separator.upperBound...])

        var tree: String?, author: String?, committer: String?
        var parents: [String] = []
        var lastKey: String?
        for line in headerLines {
            if line.hasPrefix(" ") {
                // Continuation of a multi-line header (for example `gpgsig`); nothing here needs it.
                guard lastKey != nil else { throw SigningRequest.Malformed(reason: "commit header starts with a continuation line") }
                continue
            }
            guard let space = line.firstIndex(of: " ") else {
                throw SigningRequest.Malformed(reason: "commit header line without a value: \(line)")
            }
            let key = String(line[..<space])
            let value = String(line[line.index(after: space)...])
            lastKey = key
            switch key {
            case "tree": tree = value
            case "parent": parents.append(value)
            case "author": author = value
            case "committer": committer = value
            default: continue
            }
        }
        guard let tree else {
            if body.hasPrefix("object ") { throw SigningRequest.Malformed(reason: "tag signing is not supported yet") }
            throw SigningRequest.Malformed(reason: "commit body has no tree")
        }
        guard let author else { throw SigningRequest.Malformed(reason: "commit body has no author") }
        guard let committer else { throw SigningRequest.Malformed(reason: "commit body has no committer") }
        return CommitBody(tree: tree, parents: parents, author: author, committer: committer, message: message)
    }
}

/// `diff --stat` between one parent's tree and the signed tree, as git prints it.
public struct ChangeSummary: Equatable {
    /// The parent hash from the signed body, or nil for a root commit (summary against the empty tree).
    public let parent: String?
    public let stat: String
}

/// The author's decision inside the Review. Only Approval leads to a signature.
public enum Decision {
    case approval
    case denial
}
