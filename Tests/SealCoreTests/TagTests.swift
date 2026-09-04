import Foundation
import XCTest
@testable import SealCore

/// A signed tag gets the same Review as a commit: tag name, tagged object, tagger, message, and the
/// tagged commit's Changes, all read from genuine tag bodies out of a real repository.
final class TagTests: XCTestCase {
    private var repo: ScratchRepository!

    override func setUpWithError() throws {
        repo = try ScratchRepository()
    }

    override func tearDownWithError() throws {
        try repo.remove()
    }

    private func review(_ request: ScratchRepository.CapturedSigningRequest) throws -> SigningRequest {
        var reviewed: SigningRequest?
        _ = Seal.run(arguments: request.arguments, environment: repo.environment,
                     workingDirectory: repo.directory) { reviewed = $0; return .denial }
        return try XCTUnwrap(reviewed)
    }

    private func tag(in reviewed: SigningRequest) throws -> SignedObject.Tag {
        guard case .tag(let tag) = reviewed.object else {
            XCTFail("expected a tag, got \(reviewed.object)")
            throw XCTSkip()
        }
        return tag
    }

    func testTagBodyIsParsedIntoNameObjectTypeTaggerAndMessage() throws {
        try repo.commit(message: "root")
        let head = try repo.git("rev-parse", "HEAD").trimmingCharacters(in: .whitespacesAndNewlines)
        let message = "Release 1.0\n\nFirst cut.\n"

        let reviewed = try review(try repo.signingRequest(forTag: "v1.0", message: message))

        let tag = try tag(in: reviewed)
        XCTAssertEqual(tag.name, "v1.0")
        XCTAssertEqual(tag.object, head)
        XCTAssertEqual(tag.type, "commit")
        XCTAssertTrue(tag.tagger.hasPrefix("Seal Test <test@seal>"), tag.tagger)
        XCTAssertEqual(reviewed.message, message)
    }

    func testTagOnCommitShowsThatCommitsChangesAgainstItsParent() throws {
        try repo.commit(message: "root", files: ["kept.txt": "one\n"])
        try repo.commit(message: "add two lines", files: ["added.txt": "a\nb\n"])
        let parent = try repo.git("rev-parse", "HEAD~1").trimmingCharacters(in: .whitespacesAndNewlines)

        let reviewed = try review(try repo.signingRequest(forTag: "v1", message: "v1"))

        XCTAssertEqual(reviewed.changes.count, 1)
        let changes = try XCTUnwrap(reviewed.changes.first)
        XCTAssertEqual(changes.parent, parent)
        XCTAssertTrue(changes.stat.contains("added.txt | 2 ++"), changes.stat)
        XCTAssertFalse(changes.stat.contains("kept.txt"), changes.stat)
    }

    func testTagOnAnOlderCommitSummarisesThatCommitNotHead() throws {
        try repo.commit(message: "root")
        try repo.commit(message: "tagged", files: ["tagged.txt": "t\n"])
        try repo.commit(message: "later", files: ["later.txt": "l\n"])

        let reviewed = try review(try repo.signingRequest(forTag: "v1", on: "HEAD~1", message: "v1"))

        let changes = try XCTUnwrap(reviewed.changes.first)
        XCTAssertTrue(changes.stat.contains("tagged.txt"), changes.stat)
        XCTAssertFalse(changes.stat.contains("later.txt"), changes.stat)
    }

    func testTagOnRootCommitShowsChangesAgainstTheEmptyTree() throws {
        try repo.commit(message: "root", files: ["first.txt": "hello\n"])

        let reviewed = try review(try repo.signingRequest(forTag: "v0", message: "v0"))

        let changes = try XCTUnwrap(reviewed.changes.first)
        XCTAssertNil(changes.parent)
        XCTAssertTrue(changes.stat.contains("first.txt | 1 +"), changes.stat)
    }

    func testTagOnMergeCommitShowsOneChangesBlockPerParent() throws {
        try repo.commit(message: "root")
        try repo.git("checkout", "-q", "-b", "main-line")
        try repo.commit(message: "ours", files: ["ours.txt": "o\n"])
        try repo.git("checkout", "-q", "-b", "topic", "HEAD~1")
        try repo.commit(message: "theirs", files: ["theirs.txt": "t\n"])
        try repo.git("checkout", "-q", "main-line")
        try repo.git("-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "--no-edit", "topic")

        let reviewed = try review(try repo.signingRequest(forTag: "v2", message: "v2"))

        XCTAssertEqual(reviewed.changes.count, 2)
        XCTAssertTrue(try XCTUnwrap(reviewed.changes.first).stat.contains("theirs.txt"))
        XCTAssertTrue(try XCTUnwrap(reviewed.changes.last).stat.contains("ours.txt"))
    }

    func testTagOnBlobSaysWhatItPointsAt() throws {
        try repo.commit(message: "root", files: ["file.txt": "contents\n"])
        let blob = try repo.git("rev-parse", "HEAD:file.txt").trimmingCharacters(in: .whitespacesAndNewlines)

        let reviewed = try review(try repo.signingRequest(forTag: "blob-tag", on: blob, message: "a blob"))

        let tag = try tag(in: reviewed)
        XCTAssertEqual(tag.type, "blob")
        XCTAssertEqual(reviewed.changes, [ChangeSummary(parent: nil, stat: "points at blob \(blob.prefix(7))")])
    }

    func testApprovedTagSignatureVerifies() throws {
        try repo.commit(message: "root")
        let request = try repo.signingRequest(forTag: "v1", message: "v1")

        let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in .approval }

        XCTAssertEqual(exit, Exit(status: 0))
        XCTAssertNoThrow(try repo.verify(request))
    }

    func testDeniedTagWritesNoSignature() throws {
        try repo.commit(message: "root")
        let request = try repo.signingRequest(forTag: "v1", message: "v1")

        let exit = Seal.run(arguments: request.arguments, environment: repo.environment, workingDirectory: repo.directory) { _ in .denial }

        XCTAssertEqual(exit.status, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }
}
