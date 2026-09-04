import Foundation
import XCTest

/// Drives the built `seal` binary as git's `gpg.ssh.program` in a scratch repository.
final class GitIntegrationTests: XCTestCase {
    private var repo: ScratchRepository!

    override func setUpWithError() throws {
        repo = try ScratchRepository()
    }

    override func tearDownWithError() throws {
        try repo.remove()
    }

    func testShowSignatureReportsGoodSignatureOnExistingSignedCommit() throws {
        try repo.commitSignedWithSSHKeygen(message: "signed before seal")

        try repo.git("config", "gpg.ssh.program", sealBinary.path)
        let log = try repo.git("log", "--show-signature", "-1")

        XCTAssertTrue(log.contains("Good \"git\" signature"), log)
    }

    func testCommitThroughSealIsRefusedAndLeavesNoCommit() throws {
        try repo.commitSignedWithSSHKeygen(message: "first")
        try repo.git("config", "gpg.ssh.program", sealBinary.path)

        XCTAssertThrowsError(try repo.git("commit", "--allow-empty", "-m", "through seal")) { error in
            XCTAssertTrue("\(error)".contains("seal: "), "\(error)")
        }
        XCTAssertEqual(try repo.git("rev-list", "--count", "HEAD").trimmingCharacters(in: .whitespacesAndNewlines), "1")
    }

    private var sealBinary: URL {
        // Under `swift test` the test bundle sits in the products directory next to the `seal` executable,
        // which Package.swift builds as a dependency of this test target.
        Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("seal")
    }
}

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
        return out + err
    }

    struct CommandFailed: Error, CustomStringConvertible {
        let command: String
        let status: Int32
        let stderr: String
        var description: String { "\(command) exited \(status): \(stderr)" }
    }
}
