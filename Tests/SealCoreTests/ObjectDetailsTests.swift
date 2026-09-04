import Foundation
import XCTest
@testable import SealCore

/// The Review shows what the commit is: branch, author and committer, and the change summary
/// between the signed tree and each parent, all read from a real repository.
final class ObjectDetailsTests: XCTestCase {
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

    private func commit(in reviewed: SigningRequest) throws -> SignedObject.Commit {
        guard case .commit(let commit) = reviewed.object else { throw XCTSkip("not a commit: \(reviewed.object)") }
        return commit
    }

    func testBranchIsTheSymbolicRefOfHead() throws {
        try repo.commit(message: "root")
        try repo.git("checkout", "-q", "-b", "feature")
        try repo.commit(message: "on feature")

        let reviewed = try review(try repo.signingRequestForHead())

        XCTAssertEqual(reviewed.branch, "feature")
    }

    func testDetachedHeadIsNamedDetached() throws {
        try repo.commit(message: "root")
        try repo.git("checkout", "-q", "--detach")
        try repo.commit(message: "off branch")

        let reviewed = try review(try repo.signingRequestForHead())

        XCTAssertEqual(reviewed.branch, "detached")
    }

    func testAuthorAndCommitterAreShownSeparatelyWhenTheyDiffer() throws {
        try repo.commit(message: "root")
        try repo.git("-c", "user.name=Someone Else", "-c", "user.email=else@example.com",
                     "commit", "-q", "--allow-empty", "--author=Seal Test <test@seal>", "-m", "rebased by someone else")

        let reviewed = try review(try repo.signingRequestForHead())

        let commit = try commit(in: reviewed)
        XCTAssertTrue(commit.author.hasPrefix("Seal Test <test@seal>"), commit.author)
        XCTAssertTrue(commit.committer.hasPrefix("Someone Else <else@example.com>"), commit.committer)
    }

    func testChangesIsDiffStatBetweenParentTreeAndSignedTree() throws {
        try repo.commit(message: "root", files: ["kept.txt": "one\n"])
        try repo.commit(message: "add two lines", files: ["added.txt": "a\nb\n"])

        let reviewed = try review(try repo.signingRequestForHead())

        XCTAssertEqual(reviewed.changes.count, 1)
        let changes = try XCTUnwrap(reviewed.changes.first)
        XCTAssertEqual(changes.parent, try commit(in: reviewed).parents.first)
        XCTAssertTrue(changes.stat.contains("added.txt | 2 ++"), changes.stat)
        XCTAssertTrue(changes.stat.contains("1 file changed, 2 insertions(+)"), changes.stat)
        XCTAssertFalse(changes.stat.contains("kept.txt"), changes.stat)
    }

    func testRootCommitShowsChangesAgainstTheEmptyTree() throws {
        try repo.commit(message: "root", files: ["first.txt": "hello\n"])

        let reviewed = try review(try repo.signingRequestForHead())

        XCTAssertEqual(try commit(in: reviewed).parents, [])
        XCTAssertEqual(reviewed.changes.count, 1)
        let changes = try XCTUnwrap(reviewed.changes.first)
        XCTAssertNil(changes.parent)
        XCTAssertTrue(changes.stat.contains("first.txt | 1 +"), changes.stat)
        XCTAssertTrue(changes.stat.contains("1 file changed, 1 insertion(+)"), changes.stat)
    }

    func testMergeCommitShowsOneChangesBlockPerParent() throws {
        try repo.commit(message: "root")
        try repo.git("checkout", "-q", "-b", "main-line")
        try repo.commit(message: "ours", files: ["ours.txt": "o\n"])
        try repo.git("checkout", "-q", "-b", "topic", "HEAD~1")
        try repo.commit(message: "theirs", files: ["theirs.txt": "t\n"])
        try repo.git("checkout", "-q", "main-line")
        try repo.git("-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "--no-edit", "topic")

        let reviewed = try review(try repo.signingRequestForHead())

        let merge = try commit(in: reviewed)
        XCTAssertEqual(merge.parents.count, 2)
        XCTAssertEqual(reviewed.changes.map(\.parent), merge.parents)
        let againstOurs = try XCTUnwrap(reviewed.changes.first)
        XCTAssertTrue(againstOurs.stat.contains("theirs.txt | 1 +"), againstOurs.stat)
        XCTAssertFalse(againstOurs.stat.contains("ours.txt"), againstOurs.stat)
        let againstTheirs = try XCTUnwrap(reviewed.changes.last)
        XCTAssertTrue(againstTheirs.stat.contains("ours.txt | 1 +"), againstTheirs.stat)
        XCTAssertFalse(againstTheirs.stat.contains("theirs.txt"), againstTheirs.stat)
    }
}
