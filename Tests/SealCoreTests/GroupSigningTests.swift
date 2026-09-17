import CryptoKit
import Foundation
import XCTest
@testable import SealCore

/// A Signing request for the group key is signed by the FROST path: the Approval carries the unwrapped user
/// share, the helper signs with it and the Mac's share, and the result is an ordinary `ssh-ed25519` SSHSIG.
final class GroupSigningTests: XCTestCase {
    private var repo: ScratchRepository!
    private var group: GroupKey!
    private var userShare: SecretShare!
    private var groupKeyLine: String!

    override func setUpWithError() throws {
        repo = try ScratchRepository()
        group = GroupKey(directory: repo.directory.appendingPathComponent("support"))
        let key = P256.KeyAgreement.PrivateKey()
        let report = try Setup.run(in: group, helper: FrostHelperFixture.helper) { share in
            self.userShare = share
            return try SealedShare.seal(share, to: key, keyRepresentation: key.rawRepresentation)
        }
        groupKeyLine = report.groupPublicKey
        try repo.useGroupKey(groupKeyLine)
    }

    override func tearDownWithError() throws {
        try repo.remove()
    }

    private func run(_ request: ScratchRepository.CapturedSigningRequest, helper: FrostHelper? = nil,
                     review: (SigningRequest) -> Decision) -> Exit {
        Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory,
                 group: group, helper: helper ?? FrostHelperFixture.helper, review: review)
    }

    private func commitRequest(_ message: String) throws -> ScratchRepository.CapturedSigningRequest {
        try repo.commit(message: message, files: ["\(message).txt": "\(message)\n"])
        return try repo.groupSigningRequest(body: try repo.git("cat-file", "commit", "HEAD"), groupKeyLine: groupKeyLine)
    }

    func testTheRequestSelectsTheGroupKeyHolderWhenTheKeyFileIsTheGroupKey() throws {
        var reviewed: SigningRequest?
        _ = run(try commitRequest("which holder")) { reviewed = $0; return .denial }
        XCTAssertEqual(try XCTUnwrap(reviewed).keyHolder, .group)
    }

    func testARequestForAnotherKeyStillSelectsThePersonalKeyHolder() throws {
        let request = try repo.signingRequest(forCommitWithMessage: "personal")
        var reviewed: SigningRequest?

        let exit = run(request) { reviewed = $0; return .approval() }

        XCTAssertEqual(try XCTUnwrap(reviewed).keyHolder, .personal)
        XCTAssertEqual(exit, Exit(status: 0))
        // Signed by ssh-keygen with the throwaway personal key; verify against it, not the group.
        try "test@seal \(try String(contentsOf: repo.privateKey.appendingPathExtension("pub"), encoding: .utf8))"
            .write(to: repo.allowedSigners, atomically: true, encoding: .utf8)
        XCTAssertNoThrow(try repo.verify(request))
    }

    func testApprovalWithTheUserShareWritesAGroupSignatureThatVerifies() throws {
        let request = try commitRequest("group signed")

        let exit = run(request) { _ in .approval(userShare) }

        XCTAssertEqual(exit, Exit(status: 0))
        XCTAssertTrue(FileManager.default.fileExists(atPath: request.signatureFile.path))
        XCTAssertNoThrow(try repo.verify(request))
        let pem = try String(contentsOf: request.signatureFile, encoding: .utf8)
        XCTAssertTrue(pem.hasPrefix("-----BEGIN SSH SIGNATURE-----"), pem)
    }

    func testATagIsSignedByTheGroupKeyToo() throws {
        try repo.commit(message: "tagged")
        try repo.git("-c", "tag.gpgsign=false", "tag", "-a", "-m", "v1", "v1")
        let request = try repo.groupSigningRequest(body: try repo.git("cat-file", "tag", "v1"), groupKeyLine: groupKeyLine)

        let exit = run(request) { _ in .approval(userShare) }

        XCTAssertEqual(exit, Exit(status: 0))
        XCTAssertNoThrow(try repo.verify(request))
    }

    func testDenialLeavesNoSignatureAndExitsOne() throws {
        let request = try commitRequest("denied")

        let exit = run(request) { _ in .denial }

        XCTAssertEqual(exit, Exit(status: 1, message: "seal: signing denied"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testAMissingMacShareIsAKeyHolderFailureWithNoSignature() throws {
        try FileManager.default.removeItem(at: group.macShareFile)
        let request = try commitRequest("no mac share")

        let exit = run(request) { _ in .approval(userShare) }

        XCTAssertEqual(exit.status, 2)
        let message = try XCTUnwrap(exit.message)
        XCTAssertTrue(message.hasPrefix("seal: seal-frost exited"), message)
        XCTAssertTrue(message.contains("share-mac.json"), message)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testAMissingHelperIsAKeyHolderFailure() throws {
        let request = try commitRequest("no helper")

        let exit = run(request, helper: FrostHelper(executable: repo.directory.appendingPathComponent("no-such-helper"))) { _ in
            .approval(userShare)
        }

        XCTAssertEqual(exit.status, 2)
        XCTAssertTrue(try XCTUnwrap(exit.message).contains("no-such-helper"))
    }

    func testAnApprovalWithoutTheUserShareCannotSignWithTheGroupKey() throws {
        let request = try commitRequest("no share")

        let exit = run(request) { _ in .approval() }

        XCTAssertEqual(exit.status, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testAFailureDecisionIsAKeyHolderFailure() throws {
        let request = try commitRequest("unwrap broke")

        let exit = run(request) { _ in .failure("cannot unwrap the user share: biometry changed") }

        XCTAssertEqual(exit, Exit(status: 2, message: "seal: cannot unwrap the user share: biometry changed"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testTheEnvelopeIsWhatOpenSSHExpects() throws {
        let request = try commitRequest("envelope")
        XCTAssertEqual(run(request) { _ in .approval(userShare) }, Exit(status: 0))

        let check = Process()
        check.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        check.arguments = ["-Y", "check-novalidate", "-n", "git", "-s", request.signatureFile.path]
        check.standardInput = try FileHandle(forReadingFrom: request.bufferFile)
        check.standardOutput = Pipe(); check.standardError = Pipe()
        try check.run(); check.waitUntilExit()

        XCTAssertEqual(check.terminationStatus, 0)
    }
}
