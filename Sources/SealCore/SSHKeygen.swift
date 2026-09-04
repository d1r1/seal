import Foundation

/// Runs `ssh-keygen` from `PATH` as a child process. A child rather than an exec keeps the library callable in tests.
enum SSHKeygen {
    struct Result {
        let status: Int32
        let stderr: String
    }

    struct CannotRun: Error {
        let reason: String
    }

    /// With `capturingStderr` false, stdin, stdout, and stderr are inherited so git talks to `ssh-keygen` directly.
    static func run(_ arguments: [String], environment: [String: String], capturingStderr: Bool) throws -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["ssh-keygen"] + arguments
        process.environment = environment
        let stderr = Pipe()
        if capturingStderr {
            process.standardOutput = FileHandle.nullDevice
            process.standardError = stderr
        }
        do {
            try process.run()
        } catch {
            throw CannotRun(reason: "cannot run ssh-keygen: \(error.localizedDescription)")
        }
        let output = capturingStderr
            ? String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            : ""
        process.waitUntilExit()
        return Result(status: process.terminationStatus, stderr: output.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
