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

    // Signing through the built binary opens the Review and asks for Touch ID; the spec keeps that manual.

    private var sealBinary: URL {
        // Under `swift test` the test bundle sits in the products directory next to the `seal` executable,
        // which Package.swift builds as a dependency of this test target.
        Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appendingPathComponent("seal")
    }
}
