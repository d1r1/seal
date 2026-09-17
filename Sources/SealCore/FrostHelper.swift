import Foundation

/// The `seal-frost` helper (ADR 0002, point 2): a child process that owns every FROST and SSHSIG operation.
/// Shares reach it through pipes only.
public struct FrostHelper {
    public let executable: URL

    public init(executable: URL) {
        self.executable = executable
    }

    /// The helper installed next to the `seal` executable.
    public static func nextTo(_ executable: URL) -> FrostHelper {
        FrostHelper(executable: executable.deletingLastPathComponent().appendingPathComponent("seal-frost"))
    }

    public struct Failed: Error, CustomStringConvertible {
        public let reason: String
        public var description: String { reason }
    }

    /// What the dealer produced: the group key line, the public key package (JSON) and three shares, in
    /// identifier order 1, 2, 3.
    struct Generated {
        let groupPublicKey: String
        let publicKeyPackage: Data
        let shares: [SecretShare]
    }

    func keygen() throws -> Generated {
        let result = try run(["keygen"], stdin: nil, environment: [:])
        guard result.status == 0 else { throw Failed(reason: "seal-frost keygen exited \(result.status): \(result.stderr)") }
        guard let object = try? JSONSerialization.jsonObject(with: result.stdout) as? [String: Any],
              let line = object["group_public_key"] as? String,
              let package = object["public_key_package"],
              let shares = object["shares"] as? [Any], shares.count == 3
        else { throw Failed(reason: "seal-frost keygen printed something other than the expected JSON") }
        return Generated(groupPublicKey: line,
                         publicKeyPackage: try JSONSerialization.data(withJSONObject: package, options: .sortedKeys),
                         shares: try shares.map { SecretShare(try JSONSerialization.data(withJSONObject: $0, options: .sortedKeys)) })
    }

    struct Result {
        let status: Int32
        let stdout: Data
        let stderr: String
    }

    func run(_ arguments: [String], stdin: Data?, environment: [String: String]) throws -> Result {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        var env = ProcessInfo.processInfo.environment
        environment.forEach { env[$0.key] = $0.value }
        process.environment = env
        let input = Pipe(), output = Pipe(), errors = Pipe()
        process.standardInput = stdin == nil ? FileHandle.nullDevice : input
        process.standardOutput = output
        process.standardError = errors
        do {
            try process.run()
        } catch {
            throw Failed(reason: "cannot run \(executable.path): \(error.localizedDescription)")
        }
        if let stdin {
            input.fileHandleForWriting.write(stdin)
            try input.fileHandleForWriting.close()
        }
        var err = Data()
        let drained = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            err = errors.fileHandleForReading.readDataToEndOfFile()
            drained.signal()
        }
        let out = output.fileHandleForReading.readDataToEndOfFile()
        drained.wait()
        process.waitUntilExit()
        return Result(status: process.terminationStatus, stdout: out,
                      stderr: String(decoding: err, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
