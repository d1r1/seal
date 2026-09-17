import Foundation
import XCTest
@testable import SealCore

/// A Signing request from git: the commit body is parsed, shown in the Review, and signed only after Approval.
final class SigningRequestTests: XCTestCase {
    private var repo: ScratchRepository!

    override func setUpWithError() throws {
        repo = try ScratchRepository()
    }

    override func tearDownWithError() throws {
        try repo.remove()
    }

    func testReviewShowsCommitMessageVerbatimWithParagraphsAndTrailers() throws {
        let message = """
        Add the Review window

        The body has a second paragraph
        that wraps across lines.

        Co-authored-by: Someone <someone@example.com>
        Signed-off-by: Seal Test <test@seal>
        """
        let request = try repo.signingRequest(forCommitWithMessage: message)
        var reviewed: SigningRequest?

        _ = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { reviewed = $0; return .denial }

        XCTAssertEqual(try XCTUnwrap(reviewed).message, message + "\n")
    }

    func testApprovalWritesSignatureNextToBufferFileThatVerifies() throws {
        let request = try repo.signingRequest(forCommitWithMessage: "approved")

        let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in .approval() }

        XCTAssertEqual(exit, Exit(status: 0))
        XCTAssertTrue(FileManager.default.fileExists(atPath: request.signatureFile.path))
        XCTAssertNoThrow(try repo.verify(request))
    }

    func testDenialExitsOneWithSigningDeniedAndWritesNoSignature() throws {
        let request = try repo.signingRequest(forCommitWithMessage: "denied")

        let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in .denial }

        XCTAssertEqual(exit, Exit(status: 1, message: "seal: signing denied"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testMalformedBodyExitsThreeWithoutOpeningReview() throws {
        let request = try repo.signingRequest(body: "not a commit body at all")
        var reviewOpened = false

        let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in reviewOpened = true; return .approval() }

        XCTAssertEqual(exit.status, 3)
        XCTAssertTrue(try XCTUnwrap(exit.message).hasPrefix("seal: malformed request"), "\(exit)")
        XCTAssertFalse(reviewOpened)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testBodyMissingRequiredHeaderExitsThree() throws {
        let body = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nno author or committer\n"
        let request = try repo.signingRequest(body: body)

        let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in .approval() }

        XCTAssertEqual(exit.status, 3)
    }

    func testAgentFlagFromGitDoesNotSwallowBufferFile() throws {
        let request = try repo.signingRequest(forCommitWithMessage: "with -U")
        let arguments = Array(request.arguments.dropLast()) + ["-U", request.bufferFile.path]
        var reviewed: SigningRequest?

        _ = Seal.run(arguments: arguments, environment: repo.environment, workingDirectory: repo.directory) { reviewed = $0; return .denial }

        XCTAssertEqual(try XCTUnwrap(reviewed).message, "with -U\n")
    }

    func testMissingBufferFileArgumentExitsThree() throws {
        let exit = Seal.run(arguments: ["-Y", "sign", "-n", "git", "-f", repo.privateKey.path],
                            environment: repo.environment, workingDirectory: repo.directory) { _ in .approval() }

        XCTAssertEqual(exit.status, 3)
    }

    func testUnreachableKeyHolderExitsTwoWithSSHKeygenMessage() throws {
        let request = try repo.signingRequest(forCommitWithMessage: "no key")
        let arguments = request.arguments.map { $0 == repo.privateKey.path ? "/nonexistent/key" : $0 }

        let exit = Seal.run(arguments: arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in .approval() }

        XCTAssertEqual(exit.status, 2)
        let message = try XCTUnwrap(exit.message)
        XCTAssertTrue(message.hasPrefix("seal: ") && message.contains("/nonexistent/key"), message)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testTagBodyMissingRequiredHeaderExitsThree() throws {
        let body = "object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\ntype commit\ntag v1\n\nno tagger\n"
        let request = try repo.signingRequest(body: body)

        let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in .approval() }

        XCTAssertEqual(exit.status, 3)
        XCTAssertTrue(try XCTUnwrap(exit.message).contains("tagger"), "\(exit)")
    }
}
