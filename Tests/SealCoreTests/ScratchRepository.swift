import Foundation

/// A temporary git repository with a throwaway SSH key configured for signing.
struct ScratchRepository {
    let directory: URL
    var privateKey: URL { directory.appendingPathComponent("id_ed25519") }
    var allowedSigners: URL { directory.appendingPathComponent("allowed_signers") }

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("seal-repo-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        _ = try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "test@seal", "-f", privateKey.path])
        let publicKey = try String(contentsOf: privateKey.appendingPathExtension("pub"), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        try "test@seal \(publicKey)\n".write(to: allowedSigners, atomically: true, encoding: .utf8)

        try git("init", "-q")
        try git("config", "user.name", "Seal Test")
        try git("config", "user.email", "test@seal")
        try git("config", "gpg.format", "ssh")
        try git("config", "user.signingkey", privateKey.path)
        try git("config", "gpg.ssh.allowedSignersFile", allowedSigners.path)
        try git("config", "commit.gpgsign", "true")
    }

    func commitSignedWithSSHKeygen(message: String) throws {
        try git("-c", "gpg.ssh.program=ssh-keygen", "commit", "--allow-empty", "-m", message)
    }

    @discardableResult
    func git(_ arguments: String...) throws -> String {
        try run("/usr/bin/git", arguments)
    }

    func remove() throws {
        try FileManager.default.removeItem(at: directory)
    }

    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.currentDirectoryURL = directory
        var environment = ProcessInfo.processInfo.environment
        environment["SSH_AUTH_SOCK"] = nil
        environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        process.environment = environment
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let out = String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let err = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw CommandFailed(command: ([executable] + arguments).joined(separator: " "), status: process.terminationStatus, stderr: err)
        }
        return out
    }

    struct CommandFailed: Error, CustomStringConvertible {
        let command: String
        let status: Int32
        let stderr: String
        var description: String { "\(command) exited \(status): \(stderr)" }
    }
}

extension ScratchRepository {
    /// The arguments git passes to `gpg.ssh.program` for one object, with the buffer file holding the genuine body.
    struct CapturedSigningRequest {
        let arguments: [String]
        let bufferFile: URL
        var signatureFile: URL { bufferFile.appendingPathExtension("sig") }
    }

    /// Makes an unsigned commit and captures its body the way git hands it to the signing program.
    func signingRequest(forCommitWithMessage message: String) throws -> CapturedSigningRequest {
        try git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", message)
        let body = try git("cat-file", "commit", "HEAD")
        return try signingRequest(body: body)
    }

    func signingRequest(body: String) throws -> CapturedSigningRequest {
        let bufferFile = directory.appendingPathComponent(".git_signing_buffer_\(UUID().uuidString)")
        try Data(body.utf8).write(to: bufferFile)
        let arguments = ["-Y", "sign", "-n", "git", "-f", privateKey.path, bufferFile.path]
        return CapturedSigningRequest(arguments: arguments, bufferFile: bufferFile)
    }

    /// The environment git would give the signing program in this repository: no agent socket.
    var environment: [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["SSH_AUTH_SOCK"] = nil
        return environment
    }

    /// Checks the signature file with `ssh-keygen -Y verify` against the repository's allowed signers.
    func verify(_ request: CapturedSigningRequest) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-Y", "verify", "-n", "git", "-f", allowedSigners.path, "-I", "test@seal",
                             "-s", request.signatureFile.path]
        process.standardInput = try FileHandle(forReadingFrom: request.bufferFile)
        let stderr = Pipe()
        process.standardError = stderr
        process.standardOutput = Pipe()
        try process.run()
        let err = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw CommandFailed(command: "ssh-keygen -Y verify", status: process.terminationStatus, stderr: err)
        }
    }
}

extension ScratchRepository {
    /// Writes and stages the given files (the throwaway key lives in the same directory and stays untracked),
    /// then commits unsigned.
    func commit(message: String, files: [String: String] = [:]) throws {
        for (name, contents) in files {
            try contents.write(to: directory.appendingPathComponent(name), atomically: true, encoding: .utf8)
            try git("add", "--", name)
        }
        try git("-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", message)
    }

    /// Captures the body of `HEAD` the way git hands it to the signing program.
    func signingRequestForHead() throws -> CapturedSigningRequest {
        try signingRequest(body: try git("cat-file", "commit", "HEAD"))
    }
}

extension ScratchRepository {
    /// Makes an unsigned annotated tag on `target` and captures its body the way git hands it to the signing program.
    func signingRequest(forTag name: String, on target: String = "HEAD", message: String) throws -> CapturedSigningRequest {
        try git("-c", "tag.gpgsign=false", "tag", "-a", "-m", message, name, target)
        return try signingRequest(body: try git("cat-file", "tag", name))
    }
}
