import Foundation
import XCTest
@testable import SealCore

/// The Review opens with where the Signing request came from: Session, Directory, Command, resolved from
/// the environment, the process tree, and Claude Code's session records, never blank.
final class OriginTests: XCTestCase {
    private var repo: ScratchRepository!
    private var records: URL!
    private let me = ProcessInfo.processInfo.processIdentifier

    override func setUpWithError() throws {
        repo = try ScratchRepository()
        records = repo.directory.appendingPathComponent("claude-projects")
        try FileManager.default.createDirectory(at: records, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try repo.remove()
    }

    /// A synthetic ancestry: this process <- git (pid 500) <- zsh (600) <- Ghostty (700) <- launchd (1).
    private var ancestry: ProcessTable {
        let parents: [pid_t: pid_t] = [me: 500, 500: 600, 600: 700, 700: 1]
        let paths: [pid_t: String] = [500: "/opt/homebrew/bin/git", 600: "/bin/zsh",
                                      700: "/Applications/Ghostty.app/Contents/MacOS/ghostty", 1: "/sbin/launchd"]
        let arguments: [pid_t: [String]] = [500: ["git", "commit", "-m", "hello world"], 600: ["-zsh"]]
        return ProcessTable(parent: { parents[$0] }, arguments: { arguments[$0] }, executablePath: { paths[$0] })
    }

    private func origin(environment: [String: String] = [:], processTable: ProcessTable? = nil) throws -> Origin {
        var env = repo.environment
        env["CLAUDE_CODE_SESSION_ID"] = nil
        env["CLAUDE_SESSION_ID"] = nil
        environment.forEach { env[$0.key] = $0.value }
        let request = try repo.signingRequest(forCommitWithMessage: "origin")
        var reviewed: SigningRequest?
        _ = Seal.run(arguments: request.arguments, environment: env, workingDirectory: repo.directory,
                     processTable: processTable ?? ancestry, sessionRecords: records) { reviewed = $0; return .denial }
        return try XCTUnwrap(reviewed).origin
    }

    private func writeTranscript(sessionId: String, project: String = "-Users-someone-project", lines: [String]) throws {
        let dir = records.appendingPathComponent(project)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try (lines.joined(separator: "\n") + "\n").write(to: dir.appendingPathComponent("\(sessionId).jsonl"),
                                                          atomically: true, encoding: .utf8)
    }

    func testDirectoryIsTheWorkingDirectoryGitRanSealIn() throws {
        XCTAssertEqual(try origin().directory, repo.directory.path)
    }

    func testCommandIsTheParentProcessArgumentList() throws {
        XCTAssertEqual(try origin().command, "git commit -m hello world")
    }

    func testCommandIsUnknownWhenTheParentCannotBeRead() throws {
        let table = ProcessTable(parent: { _ in nil }, arguments: { _ in nil }, executablePath: { _ in nil })
        XCTAssertEqual(try origin(processTable: table).command, "unknown")
    }

    func testSessionIsTheCustomTitleWhenOneWasSet() throws {
        let id = "44301c23-c9e2-4713-afaf-9b463bd96f58"
        try writeTranscript(sessionId: id, lines: [
            #"{"type":"user","message":{"role":"user","content":"hi"},"sessionId":"\#(id)"}"#,
            #"{"type":"ai-title","aiTitle":"Generated title","sessionId":"\#(id)"}"#,
            #"{"type":"custom-title","customTitle":"my-renamed-session","sessionId":"\#(id)"}"#,
            #"{"type":"ai-title","aiTitle":"Later generated title","sessionId":"\#(id)"}"#,
        ])

        XCTAssertEqual(try origin(environment: ["CLAUDE_CODE_SESSION_ID": id]).session, "my-renamed-session")
    }

    func testSessionIsTheLatestGeneratedTitleWithoutACustomOne() throws {
        let id = "1dc91443-7dec-41e3-bf5d-ccda3f0a1f0a"
        try writeTranscript(sessionId: id, lines: [
            #"{"type":"ai-title","aiTitle":"First title","sessionId":"\#(id)"}"#,
            #"{"type":"ai-title","aiTitle":"Implement 05","sessionId":"\#(id)"}"#,
        ])

        XCTAssertEqual(try origin(environment: ["CLAUDE_CODE_SESSION_ID": id]).session, "Implement 05")
    }

    func testSessionFallsBackToTheShortIdWhenRecordsAreMissing() throws {
        let id = "eea3ae48-2afb-42e0-be30-df891959438a"
        XCTAssertEqual(try origin(environment: ["CLAUDE_CODE_SESSION_ID": id]).session, "eea3ae48")
    }

    func testSessionFallsBackToTheShortIdWhenTheTranscriptIsUnreadable() throws {
        let id = "47e624a0-a59b-416c-8d5e-bd9c043c10f0"
        try writeTranscript(sessionId: id, lines: ["this is not json {{{", #"{"type":"ai-title"}"#])

        XCTAssertEqual(try origin(environment: ["CLAUDE_CODE_SESSION_ID": id]).session, "47e624a0")
    }

    func testSessionIsTheNearestApplicationAncestorWithoutASessionId() throws {
        XCTAssertEqual(try origin().session, "Ghostty (pid 700)")
    }

    func testSessionIsUnknownWhenNoAncestorIsAnApplication() throws {
        let parents: [pid_t: pid_t] = [me: 500, 500: 1]
        let paths: [pid_t: String] = [500: "/usr/bin/git", 1: "/sbin/launchd"]
        let table = ProcessTable(parent: { parents[$0] }, arguments: { _ in ["git"] }, executablePath: { paths[$0] })
        XCTAssertEqual(try origin(processTable: table).session, "unknown")
    }

    func testLiveProcessTableReadsThisProcessesOwnParentAndArguments() throws {
        let table = ProcessTable.live
        let parent = try XCTUnwrap(table.parent(me))
        XCTAssertGreaterThan(parent, 1)
        XCTAssertNotNil(table.arguments(parent))
        XCTAssertEqual(table.arguments(me)?.first, CommandLine.arguments.first)
        XCTAssertEqual(table.executablePath(me), Bundle.main.executableURL?.resolvingSymlinksInPath().path)
    }
}
