import Foundation
import XCTest
@testable import SealCore

/// The card's fields are computed from the Signing request alone: title and body from the message, Problem,
/// Why and Risks from its trailers, the counts from the stat, the hashes from the signed body.
final class CardTests: XCTestCase {
    private func request(message: String, parents: [String] = ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"],
                         stats: [String]? = nil, branch: String = "feat/widget") -> SigningRequest {
        let commit = SignedObject.Commit(tree: "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3", parents: parents,
                                         author: "d1r1 <me@d1r1.me> 1 +0000", committer: "d1r1 <me@d1r1.me> 1 +0000")
        let stat = stats ?? [" a.swift | 4 ++--\n b.swift | 6 ++++--\n 2 files changed, 6 insertions(+), 4 deletions(-)"]
        let changes = zip(parents.isEmpty ? [nil] : parents.map(Optional.some), stat).map { ChangeSummary(parent: $0, stat: $1) }
        return SigningRequest(origin: Origin(session: "s", directory: "/Users/me/dev/fluent-connect-service", command: "git commit"),
                              object: .commit(commit), message: message, branch: branch, changes: changes, keyHolder: .group, namespace: "git", keyLine: nil,
                              arguments: [], bufferFile: URL(fileURLWithPath: "/tmp/buffer"))
    }

    func testTitleIsTheFirstLineAndBodyTheRestVerbatim() {
        let card = Card(request(message: "feat(widget): read Privy id\n\nParagraph one.\n\nRisks: none known\n"))

        XCTAssertEqual(card.title, "feat(widget): read Privy id")
        XCTAssertEqual(card.body, "Paragraph one.\n\nRisks: none known")
    }

    func testProblemWhyAndRisksComeFromTheTrailersAtTheEnd() {
        let message = """
        feat(widget): read Privy id from session

        Some prose about the change.

        Problem: widget asked Privy twice; id already in session
        Why: one source (session); no second round-trip
        Risks: session shape change breaks older SDK
          no migration
        Co-authored-by: Someone <s@example.com>

        """
        let card = Card(request(message: message))

        XCTAssertEqual(card.problem, "widget asked Privy twice; id already in session")
        XCTAssertEqual(card.why, "one source (session); no second round-trip")
        XCTAssertEqual(card.risks, "session shape change breaks older SDK no migration")
    }

    func testTrailerKeysAreCaseInsensitive() {
        let card = Card(request(message: "t\n\nrisks: lower case\nWHY: shouting\n"))
        XCTAssertEqual(card.risks, "lower case")
        XCTAssertEqual(card.why, "shouting")
    }

    func testALineInTheMiddleOfTheBodyIsNotATrailer() {
        let message = "t\n\nWhy: this is prose, not a trailer\nand it continues here without a colon key.\n\nMore prose.\n"
        let card = Card(request(message: message))
        XCTAssertEqual(card.why, "—")
    }

    func testMissingTrailersShowADash() {
        let card = Card(request(message: "just a title\n"))
        XCTAssertEqual(card.problem, "—")
        XCTAssertEqual(card.why, "—")
        XCTAssertEqual(card.risks, "—")
        XCTAssertNil(card.body)
    }

    func testSummaryHasTheCountsAndTheShortHashes() {
        let card = Card(request(message: "t\n"))
        XCTAssertEqual(card.summary, "2 files · +6 −4 · parent a1b2c3d → tree e4f5a6b")
    }

    func testSummaryForASingleFileAndOnlyInsertions() {
        let card = Card(request(message: "t\n", stats: [" a | 1 +\n 1 file changed, 1 insertion(+)"]))
        XCTAssertEqual(card.summary, "1 file · +1 −0 · parent a1b2c3d → tree e4f5a6b")
    }

    func testSummaryOfARootCommitNamesTheEmptyParent() {
        let card = Card(request(message: "t\n", parents: [], stats: [" a | 1 +\n 1 file changed, 1 insertion(+)"]))
        XCTAssertEqual(card.summary, "1 file · +1 −0 · no parent → tree e4f5a6b")
    }

    func testSummaryOfAMergeListsEachParent() {
        let card = Card(request(message: "t\n", parents: ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1"],
                                stats: [" x | 1 +\n 1 file changed, 1 insertion(+)", " y | 2 ++\n 1 file changed, 2 insertions(+)"]))
        XCTAssertEqual(card.summary, "parents a1b2c3d, b2c3d4e → tree e4f5a6b")
    }

    func testHeaderNamesTheRepositoryDirectoryAndTheBranch() {
        let card = Card(request(message: "t\n"))
        XCTAssertEqual(card.header, "fluent-connect-service · feat/widget")
    }

    func testAttestationsAreAStubThatSaysSo() {
        let card = Card(request(message: "t\n"))
        XCTAssertEqual(card.attestations.count, 2)
        XCTAssertTrue(card.attestations.allSatisfy { $0.contains("stub") && $0.contains("✅") }, "\(card.attestations)")
        XCTAssertTrue(card.attestations[0].contains("implementer"))
        XCTAssertTrue(card.attestations[1].contains("reviewer"))
    }

    func testATagCardUsesTheTagNameAndTheTaggedCommit() {
        let tag = SignedObject.Tag(name: "v1.2.0", object: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2", type: "commit", tagger: "d1r1 <me@d1r1.me> 1 +0000")
        let request = SigningRequest(origin: Origin(session: "s", directory: "/x/repo", command: "git tag"), object: .tag(tag),
                                     message: "release\n", branch: "main",
                                     changes: [ChangeSummary(parent: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", stat: " a | 1 +\n 1 file changed, 1 insertion(+)")],
                                     keyHolder: .personal, namespace: "git", keyLine: nil, arguments: [], bufferFile: URL(fileURLWithPath: "/tmp/b"))
        let card = Card(request)
        XCTAssertEqual(card.header, "repo · tag v1.2.0")
        XCTAssertEqual(card.summary, "1 file · +1 −0 · tag → commit c3d4e5f")
    }
}
