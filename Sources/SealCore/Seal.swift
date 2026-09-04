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

    static func keyHolderFailure(_ reason: String) -> Exit {
        Exit(status: 2, message: "seal: \(reason)")
    }

    static func malformedRequest(_ reason: String) -> Exit {
        Exit(status: 3, message: "seal: malformed request: \(reason)")
    }
}

public enum Seal {
    /// Handles one invocation of `gpg.ssh.program` and says how the process should end.
    public static func run(arguments: [String], environment: [String: String]) -> Exit {
        switch Mode.of(arguments) {
        case .signingRequest:
            return .malformedRequest("signing is not available yet; the Review is not built")
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

/// Hands a non-signing `-Y` mode to `ssh-keygen` with the arguments unchanged.
/// stdin, stdout, and stderr are inherited so git talks to `ssh-keygen` as if Seal were not there.
/// `ssh-keygen` runs as a child rather than replacing the process so that the library stays callable in tests.
enum PassThrough {
    static func run(arguments: [String], environment: [String: String]) -> Exit {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["ssh-keygen"] + arguments
        process.environment = environment
        do {
            try process.run()
        } catch {
            return .keyHolderFailure("cannot run ssh-keygen: \(error.localizedDescription)")
        }
        process.waitUntilExit()
        return Exit(status: process.terminationStatus)
    }
}
