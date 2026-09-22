import Foundation

/// What the `seal` executable does after handling one invocation from git.
public struct Exit: Equatable {
    public let status: Int32
    /// One line for stderr, or nil when nothing should be printed.
    public let message: String?

    public init(status: Int32, message: String? = nil) {
        self.status = status
        self.message = message
    }

    /// Exit statuses from the spec: 0 signed, 1 no Approval, 2 Key holder failure, 3 malformed request.
    static let signed = Exit(status: 0)
    static let denied = Exit(status: 1, message: "seal: signing denied")
    /// Git went away while the Review was open; nothing was signed.
    public static let abandoned = Exit(status: 1, message: "seal: git exited before a decision was made")

    static func keyHolderFailure(_ reason: String) -> Exit {
        Exit(status: 2, message: "seal: \(reason)")
    }

    static func malformedRequest(_ reason: String) -> Exit {
        Exit(status: 3, message: "seal: malformed request: \(reason)")
    }

    /// The notary's answer on the agent path; the statuses are the same as for the card.
    static func notaryRefusal(_ reason: String) -> Exit {
        Exit(status: 1, message: "seal: signing denied: \(reason)")
    }

    static func notaryFailure(_ reason: String) -> Exit {
        Exit(status: 2, message: "seal: notary: \(reason)")
    }

    static func notaryNotFound(at path: URL) -> Exit {
        Exit(status: 2, message: "seal: notary socket not found at \(path.path)")
    }
}

public enum Seal {
    public static let defaultSessionRecords = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".claude").appendingPathComponent("projects")

    /// Handles one invocation of `gpg.ssh.program` and says how the process should end.
    /// `review` shows the Signing request to the author and returns their Decision; the `seal` executable
    /// supplies the Review window and Touch ID, tests supply a closure. `workingDirectory` is where git ran Seal;
    /// the branch and change summary are read from the repository there. `processTable` and `sessionRecords`
    /// (Claude Code's transcripts, `~/.claude/projects` by default) feed the Origin; tests supply synthetic ones.
    /// `group` is where the group key and Seal's share live and `helper` is the `seal-frost` executable; tests
    /// supply a temporary directory and the crate's build. No environment variable selects either.
    /// A request from a Paseo agent (`PASEO_AGENT_ID` set) takes the agent path whatever key it names: it is
    /// forwarded to the notary on `notary` and `review` is not called (seal-frost ADR 0003, decision 1). Tests
    /// supply a temporary socket; the path never comes from the environment.
    public static func run(arguments: [String], environment: [String: String], workingDirectory: URL,
                           processTable: ProcessTable = .live, sessionRecords: URL = defaultSessionRecords,
                           group: GroupKey = GroupKey(), helper: FrostHelper = .nextTo(Bundle.main.executableURL ?? URL(fileURLWithPath: "/")),
                           notary: NotarySocket = NotarySocket(),
                           review: (SigningRequest) -> Decision) -> Exit {
        switch Mode.of(arguments) {
        case .signingRequest:
            let request: SigningRequest
            let origin = Origin.resolve(environment: environment, workingDirectory: workingDirectory,
                                        processTable: processTable, sessionRecords: sessionRecords)
            do {
                request = try SigningRequest.parse(arguments: arguments, origin: origin,
                                                   in: Repository(workingDirectory: workingDirectory, environment: environment),
                                                   group: group)
            } catch {
                if origin.paseoAgentId != nil {
                    // The agent path leaves no `.sig` behind on any non-zero exit, a stale one included; every
                    // argument that could be the buffer file counts.
                    for candidate in SignArguments(arguments).positional {
                        try? FileManager.default.removeItem(at: URL(fileURLWithPath: candidate).appendingPathExtension("sig"))
                    }
                }
                return .malformedRequest((error as? SigningRequest.Malformed)?.reason ?? error.localizedDescription)
            }
            if request.origin.paseoAgentId != nil {
                return Notary.sign(request, socket: notary)
            }
            switch (review(request), request.keyHolder) {
            case (.approval(nil), .personal):
                return KeyHolder.sign(request, environment: environment)
            case (.approval(let share?), .group):
                return GroupKeyHolder.sign(request, share: share, group: group, helper: helper)
            case (.approval(nil), .group):
                return .keyHolderFailure("the Approval carried no user share for the group key")
            case (.approval(_?), .personal):
                return .keyHolderFailure("the Approval carried a user share for the personal key")
            case (.denial, _):
                return .denied
            case (.failure(let reason), _):
                return .keyHolderFailure(reason)
            }
        case .passThrough:
            return PassThrough.run(arguments: arguments, environment: environment)
        case .missing:
            return .malformedRequest("no -Y mode given")
        case .unknown(let mode):
            return .malformedRequest("unknown -Y mode '\(mode)'")
        }
    }
}

/// The `-Y` mode git asked for, as `ssh-keygen` would read it.
enum Mode {
    case signingRequest
    case passThrough
    case missing
    case unknown(String)

    static let passThroughModes: Set<String> = ["verify", "find-principals", "check-novalidate", "match-principals"]

    static func of(_ arguments: [String]) -> Mode {
        guard let flag = arguments.firstIndex(of: "-Y"), arguments.indices.contains(flag + 1) else {
            return .missing
        }
        let mode = arguments[flag + 1]
        if mode == "sign" { return .signingRequest }
        if passThroughModes.contains(mode) { return .passThrough }
        return .unknown(mode)
    }
}

/// Hands a non-signing `-Y` mode to `ssh-keygen` with the arguments unchanged and stdio inherited,
/// so git talks to `ssh-keygen` as if Seal were not there.
enum PassThrough {
    static func run(arguments: [String], environment: [String: String]) -> Exit {
        do {
            return Exit(status: try SSHKeygen.run(arguments, environment: environment, capturingStderr: false).status)
        } catch let failure as SSHKeygen.CannotRun {
            return .keyHolderFailure(failure.reason)
        } catch {
            return .keyHolderFailure(error.localizedDescription)
        }
    }
}
