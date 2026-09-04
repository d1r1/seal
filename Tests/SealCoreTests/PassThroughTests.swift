import Foundation
import XCTest
@testable import SealCore

final class PassThroughTests: XCTestCase {
    private var stub: RecordingSSHKeygen!

    override func setUpWithError() throws {
        stub = try RecordingSSHKeygen()
    }

    override func tearDownWithError() throws {
        try stub.remove()
    }

    func testVerifyReachesSSHKeygenWithArgumentsUnchanged() throws {
        let arguments = ["-Y", "verify", "-n", "git", "-f", "/tmp/allowed_signers",
                         "-I", "me@d1r1.me", "-s", "/tmp/sig", "-r", "/tmp/buffer"]

        let exit = Seal.run(arguments: arguments, environment: stub.environment, workingDirectory: stub.directory) { _ in .denial }

        XCTAssertEqual(exit, Exit(status: 0))
        XCTAssertEqual(try stub.recordedArguments(), arguments)
    }

    func testFindPrincipalsReachesSSHKeygenWithArgumentsUnchanged() throws {
        let arguments = ["-Y", "find-principals", "-f", "/tmp/allowed_signers", "-s", "/tmp/sig"]
        _ = Seal.run(arguments: arguments, environment: stub.environment, workingDirectory: stub.directory) { _ in .denial }
        XCTAssertEqual(try stub.recordedArguments(), arguments)
    }

    func testCheckNovalidateReachesSSHKeygenWithArgumentsUnchanged() throws {
        let arguments = ["-Y", "check-novalidate", "-n", "git", "-s", "/tmp/sig", "-r", "/tmp/buffer"]
        _ = Seal.run(arguments: arguments, environment: stub.environment, workingDirectory: stub.directory) { _ in .denial }
        XCTAssertEqual(try stub.recordedArguments(), arguments)
    }

    func testMatchPrincipalsReachesSSHKeygenWithArgumentsUnchanged() throws {
        let arguments = ["-Y", "match-principals", "-f", "/tmp/allowed_signers", "-I", "me@d1r1.me"]
        _ = Seal.run(arguments: arguments, environment: stub.environment, workingDirectory: stub.directory) { _ in .denial }
        XCTAssertEqual(try stub.recordedArguments(), arguments)
    }

    func testPassThroughReportsSSHKeygenExitStatus() throws {
        let failing = try RecordingSSHKeygen(exitStatus: 255)
        defer { try? failing.remove() }
        let exit = Seal.run(arguments: ["-Y", "verify"], environment: failing.environment, workingDirectory: failing.directory) { _ in .denial }
        XCTAssertEqual(exit, Exit(status: 255))
    }
}

/// A fake `ssh-keygen` placed first on `PATH` that writes its arguments to a file, one per line.
struct RecordingSSHKeygen {
    let directory: URL
    var recordFile: URL { directory.appendingPathComponent("recorded-arguments") }

    init(exitStatus: Int32 = 0) throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("seal-stub-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let script = """
        #!/bin/sh
        printf '%s\\n' "$@" > "\(recordFile.path)"
        exit \(exitStatus)
        """
        let executable = directory.appendingPathComponent("ssh-keygen")
        try script.write(to: executable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
    }

    var environment: [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = directory.path + ":" + (environment["PATH"] ?? "/usr/bin:/bin")
        return environment
    }

    func recordedArguments() throws -> [String] {
        let contents = try String(contentsOf: recordFile, encoding: .utf8)
        return contents.split(separator: "\n", omittingEmptySubsequences: false).dropLast().map(String.init)
    }

    func remove() throws {
        try FileManager.default.removeItem(at: directory)
    }
}
