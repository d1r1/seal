import Foundation
import XCTest
@testable import SealCore

/// Every ending other than a signature is distinguishable from git's side, leaves no signature file,
/// and no Review outlives the git that asked for it.
final class FailureSemanticsTests: XCTestCase {
    private var repo: ScratchRepository!

    override func setUpWithError() throws {
        repo = try ScratchRepository()
    }

    override func tearDownWithError() throws {
        try repo.remove()
    }

    private func run(_ request: ScratchRepository.CapturedSigningRequest, arguments: [String]? = nil,
                     environment: [String: String]? = nil, decision: Decision) -> Exit {
        Seal.run(arguments: arguments ?? request.arguments, environment: environment ?? repo.environment,
                 workingDirectory: repo.directory) { _ in decision }
    }

    func testMissingAgentSocketExitsTwoWithSSHKeygenMessageAndNoSignature() throws {
        let request = try repo.signingRequest(forCommitWithMessage: "no agent")
        // What git passes when `user.signingkey` is a public key held by an agent: `-U` plus the `.pub` file.
        let arguments = Array(request.arguments.dropLast()).map { $0 == repo.privateKey.path ? $0 + ".pub" : $0 }
            + ["-U", request.bufferFile.path]
        var environment = repo.environment
        environment["SSH_AUTH_SOCK"] = repo.directory.appendingPathComponent("no-such-agent.sock").path

        let exit = run(request, arguments: arguments, environment: environment, decision: .approval())

        XCTAssertEqual(exit.status, 2)
        let message = try XCTUnwrap(exit.message)
        XCTAssertTrue(message.hasPrefix("seal: ssh-keygen exited"), message)
        XCTAssertTrue(message.lowercased().contains("agent"), message)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testKeyHolderFailureRemovesAStaleSignatureFile() throws {
        let request = try repo.signingRequest(forCommitWithMessage: "stale")
        try Data("stale".utf8).write(to: request.signatureFile)
        let arguments = request.arguments.map { $0 == repo.privateKey.path ? "/nonexistent/key" : $0 }

        let exit = run(request, arguments: arguments, decision: .approval())

        XCTAssertEqual(exit.status, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testTheThreeFailureStatusesAndMessagesAreDistinct() throws {
        let denied = run(try repo.signingRequest(forCommitWithMessage: "denied"), decision: .denial)
        let malformed = run(try repo.signingRequest(body: "garbage"), decision: .approval())
        let unreachable = try repo.signingRequest(forCommitWithMessage: "unreachable")
        let failed = run(unreachable, arguments: unreachable.arguments.map { $0 == repo.privateKey.path ? "/nonexistent/key" : $0 },
                         decision: .approval())

        XCTAssertEqual(denied, Exit(status: 1, message: "seal: signing denied"))
        XCTAssertEqual(malformed.status, 3)
        XCTAssertEqual(try XCTUnwrap(malformed.message).split(separator: "\n").count, 1, "one-line reason")
        XCTAssertTrue(try XCTUnwrap(malformed.message).hasPrefix("seal: malformed request: "))
        XCTAssertEqual(failed.status, 2)
        XCTAssertEqual(Exit.abandoned.status, 1)
        XCTAssertNotEqual(Exit.abandoned.message, denied.message)
    }

    func testOverlappingRequestsEachGetTheirOwnReviewAndApprovingOneDoesNotSignTheOther() throws {
        let approved = try repo.signingRequest(forCommitWithMessage: "approved")
        let denied = try repo.signingRequest(forCommitWithMessage: "denied")
        let bothOpen = DispatchGroup()
        bothOpen.enter(); bothOpen.enter()
        var exits: [String: Exit] = [:]
        let lock = NSLock()

        // Each Review blocks until the other one is open too, so both requests are pending at the same time.
        DispatchQueue.concurrentPerform(iterations: 2) { i in
            let request = i == 0 ? approved : denied
            let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in
                bothOpen.leave()
                XCTAssertEqual(bothOpen.wait(timeout: .now() + 10), .success, "the other Review never opened")
                return i == 0 ? .approval() : .denial
            }
            lock.lock(); exits[i == 0 ? "approved" : "denied"] = exit; lock.unlock()
        }

        XCTAssertEqual(exits["approved"], Exit(status: 0))
        XCTAssertEqual(exits["denied"], Exit(status: 1, message: "seal: signing denied"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: approved.signatureFile.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: denied.signatureFile.path))
        XCTAssertNoThrow(try repo.verify(approved))
    }

    func testParentWatchFiresWhenTheWatchedProcessIsKilled() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["30"]
        try child.run()
        let fired = expectation(description: "watched process exited")
        let watch = ParentWatch.onExit(of: child.processIdentifier) { fired.fulfill() }

        kill(child.processIdentifier, SIGKILL)

        wait(for: [fired], timeout: 5)
        watch.cancel()
        child.waitUntilExit()
    }

    func testParentWatchFiresAtOnceForAProcessThatIsAlreadyGone() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run()
        child.waitUntilExit()
        let fired = expectation(description: "handler fired for a finished process")

        let watch = ParentWatch.onExit(of: child.processIdentifier) { fired.fulfill() }

        wait(for: [fired], timeout: 5)
        watch.cancel()
    }
}
