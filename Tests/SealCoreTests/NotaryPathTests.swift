import Foundation
import XCTest
@testable import SealCore

/// The agent path (seal-frost ADR 0003, decision 1; the contract in `~/dev/ws/desk/docs/notary-protocol.md`):
/// with `PASEO_AGENT_ID` set, Seal forwards the Signing request to the notary's socket instead of opening the card
/// and writes the signature the notary returns.
final class NotaryPathTests: XCTestCase {
    private var repo: ScratchRepository!
    private var notary: FakeNotary!
    private let agentId = "0cc62a59-70d4-4686-ac46-9a72ef6c3947"

    override func setUpWithError() throws {
        repo = try ScratchRepository()
        notary = try FakeNotary()
    }

    override func tearDownWithError() throws {
        notary.stop()
        try repo.remove()
    }

    private var agentEnvironment: [String: String] {
        var environment = repo.environment
        environment["PASEO_AGENT_ID"] = agentId
        return environment
    }

    /// What git passes for a literal `user.signingkey`: the public key line in a temporary `-f` file.
    private func agentSigningRequest(body: String) throws -> ScratchRepository.CapturedSigningRequest {
        try repo.groupSigningRequest(body: body, groupKeyLine: try publicKeyLine())
    }

    private func publicKeyLine() throws -> String {
        try String(contentsOf: repo.privateKey.appendingPathExtension("pub"), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// A real signature over `body` by the scratch repository's key, as the notary would return it.
    private func signature(of body: String) throws -> String {
        let file = repo.directory.appendingPathComponent("notary-body-\(UUID().uuidString)")
        try Data(body.utf8).write(to: file)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-Y", "sign", "-n", "git", "-f", repo.privateKey.path, file.path]
        process.environment = repo.environment
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        return try String(contentsOf: file.appendingPathExtension("sig"), encoding: .utf8)
    }

    private func signedAnswer(_ request: [String: Any]?) -> String {
        guard let body = request?["body"] as? String, let signature = try? signature(of: body) else {
            return #"{"v":1,"ok":false,"status":"error","reason":"fake notary got no body"}"#
        }
        return FakeNotary.line(["v": 1, "ok": true, "signature": signature])
    }

    /// Runs Seal on the request against the fake notary; `reviewed` says whether the card was asked for.
    private func run(_ request: ScratchRepository.CapturedSigningRequest,
                     environment: [String: String]? = nil) -> (exit: Exit, reviewed: Bool) {
        var reviewed = false
        let exit = Seal.run(arguments: request.arguments, environment: environment ?? agentEnvironment,
                            workingDirectory: repo.directory, notary: NotarySocket(path: notary.path)) { _ in
            reviewed = true
            return .denial
        }
        return (exit, reviewed)
    }

    func testACommitFromAnAgentIsSignedByTheNotaryWithoutTheCard() throws {
        try repo.commit(message: "from an agent")
        let body = try repo.git("cat-file", "commit", "HEAD")
        let request = try agentSigningRequest(body: body)
        notary.serve(answer: signedAnswer)

        let outcome = run(request)

        XCTAssertEqual(outcome.exit, Exit(status: 0))
        XCTAssertFalse(outcome.reviewed)
        let received = try XCTUnwrap(notary.received())
        XCTAssertEqual(received["v"] as? Int, 1)
        XCTAssertEqual(received["action"] as? String, "sign")
        XCTAssertEqual(received["namespace"] as? String, "git")
        XCTAssertEqual(received["key"] as? String, try publicKeyLine())
        XCTAssertEqual(received["body"] as? String, body)
        let origin = try XCTUnwrap(received["origin"] as? [String: Any])
        XCTAssertEqual(origin["directory"] as? String, repo.directory.path)
        XCTAssertEqual(origin["branch"] as? String, try repo.git("symbolic-ref", "--short", "HEAD")
            .trimmingCharacters(in: .whitespacesAndNewlines))
        XCTAssertEqual(origin["paseoAgentId"] as? String, agentId)
        XCTAssertNotNil(origin["command"] as? String)
        XCTAssertNil(origin["card"])
        XCTAssertNil(received["card"])
        XCTAssertEqual(try Data(contentsOf: request.signatureFile), Data(try signature(ofReturnedBy: notary).utf8))
        XCTAssertNoThrow(try repo.verify(request))
    }

    func testAnAnnotatedTagFromAnAgentIsSignedByTheNotary() throws {
        try repo.commit(message: "tagged")
        try repo.git("-c", "tag.gpgsign=false", "tag", "-a", "-m", "release", "v1")
        let body = try repo.git("cat-file", "tag", "v1")
        let request = try agentSigningRequest(body: body)
        notary.serve(answer: signedAnswer)

        let outcome = run(request)

        XCTAssertEqual(outcome.exit, Exit(status: 0))
        XCTAssertFalse(outcome.reviewed)
        XCTAssertEqual(try XCTUnwrap(notary.received())["body"] as? String, body)
        XCTAssertNoThrow(try repo.verify(request))
    }

    func testTheClientDoesNotHalfCloseBeforeTheResponseArrives() throws {
        try repo.commit(message: "keep the socket open")
        let request = try agentSigningRequest(body: try repo.git("cat-file", "commit", "HEAD"))
        notary.serve(answer: signedAnswer)

        let outcome = run(request)

        XCTAssertEqual(outcome.exit, Exit(status: 0))
        _ = notary.received()
        XCTAssertEqual(notary.clientHalfClosed, false)
    }

    private func assertRefusedOrFailed(answer: String, exit expected: Exit,
                                       file: StaticString = #filePath, line: UInt = #line) throws {
        try repo.commit(message: "answered \(expected.status)")
        let request = try agentSigningRequest(body: try repo.git("cat-file", "commit", "HEAD"))
        try Data("stale".utf8).write(to: request.signatureFile)
        notary.serve { _ in answer }

        let outcome = run(request)

        XCTAssertEqual(outcome.exit, expected, file: file, line: line)
        XCTAssertFalse(outcome.reviewed, file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path), file: file, line: line)
    }

    func testARefusalExitsOneWithTheNotarysReasonAndNoSignature() throws {
        try assertRefusedOrFailed(
            answer: #"{"v":1,"ok":false,"status":"refused","reason":"policy: desk commit is never (policy.yaml line 12)"}"#,
            exit: Exit(status: 1, message: "seal: signing denied: policy: desk commit is never (policy.yaml line 12)"))
    }

    func testAnErrorExitsTwoWithTheNotarysReasonAndNoSignature() throws {
        try assertRefusedOrFailed(answer: #"{"v":1,"ok":false,"status":"error","reason":"key file unreadable"}"#,
                                  exit: Exit(status: 2, message: "seal: notary: key file unreadable"))
    }

    func testAResponseThatIsNotJSONExitsTwoAsMalformed() throws {
        try assertRefusedOrFailed(answer: "signed, trust me",
                                  exit: Exit(status: 2, message: "seal: notary: malformed response: not a JSON object"))
    }

    func testASignedResponseWithoutASignatureExitsTwoAsMalformed() throws {
        try assertRefusedOrFailed(answer: #"{"v":1,"ok":true}"#,
                                  exit: Exit(status: 2, message: "seal: notary: malformed response: no signature"))
    }

    func testAResponseInAnUnknownVersionExitsTwoAsMalformed() throws {
        try assertRefusedOrFailed(answer: #"{"v":2,"ok":true,"signature":"-----BEGIN SSH SIGNATURE-----\n"}"#,
                                  exit: Exit(status: 2, message: "seal: notary: malformed response: unknown version 2"))
    }

    func testAnAbsentSocketExitsTwoNamingThePathAndLeavesNoSignature() throws {
        try repo.commit(message: "nobody listens")
        let request = try agentSigningRequest(body: try repo.git("cat-file", "commit", "HEAD"))
        notary.stop()

        let outcome = run(request)

        XCTAssertEqual(outcome.exit, Exit(status: 2, message: "seal: notary socket not found at \(notary.path.path)"))
        XCTAssertFalse(outcome.reviewed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: request.signatureFile.path))
    }

    func testWithoutAPaseoAgentIdTheCardOpensAsBefore() throws {
        try repo.commit(message: "from the terminal")
        let request = try agentSigningRequest(body: try repo.git("cat-file", "commit", "HEAD"))

        XCTAssertTrue(run(request, environment: repo.environment).reviewed)
    }

    func testAnEmptyPaseoAgentIdCountsAsUnset() throws {
        try repo.commit(message: "empty id")
        let request = try agentSigningRequest(body: try repo.git("cat-file", "commit", "HEAD"))
        var environment = repo.environment
        environment["PASEO_AGENT_ID"] = ""

        XCTAssertTrue(run(request, environment: environment).reviewed)
    }

    private func signature(ofReturnedBy notary: FakeNotary) throws -> String {
        let answer = try XCTUnwrap(notary.answered)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(answer.utf8)) as? [String: Any])
        return try XCTUnwrap(object["signature"] as? String)
    }
}

/// A notary on a temporary unix socket that takes one connection: it reads one request line, records it, and
/// answers with the line the test scripts. It also records whether the client half-closed before the answer.
final class FakeNotary {
    let path: URL
    private let listener: Int32
    private let finished = DispatchSemaphore(value: 0)
    private var serving = false
    private var request: [String: Any]?
    private(set) var answered: String?
    private(set) var clientHalfClosed: Bool?

    init() throws {
        // sun_path holds 104 bytes; the per-user temporary directory is too deep for a socket name.
        path = URL(fileURLWithPath: "/tmp/seal-notary-\(UUID().uuidString.prefix(8)).sock")
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            _ = path.path.utf8CString.withUnsafeBytes { buffer.copyBytes(from: $0) }
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, listen(listener, 1) == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
    }

    static func line(_ object: [String: Any]) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    /// Accepts one connection in the background and answers it with `answer(request)`, sent without a newline
    /// when the script already ends with one.
    func serve(answer: @escaping ([String: Any]?) -> String) {
        serving = true
        DispatchQueue.global().async { [self] in
            defer { finished.signal() }
            let connection = accept(listener, nil, nil)
            guard connection >= 0 else { return }
            defer { close(connection) }
            var line = Data()
            var byte: UInt8 = 0
            while read(connection, &byte, 1) == 1, byte != UInt8(ascii: "\n") { line.append(byte) }
            request = try? JSONSerialization.jsonObject(with: line) as? [String: Any]
            clientHalfClosed = Self.sawEndOfFile(on: connection)
            let reply = answer(request)
            answered = reply
            let bytes = Array((reply.hasSuffix("\n") ? reply : reply + "\n").utf8)
            _ = bytes.withUnsafeBytes { write(connection, $0.baseAddress, $0.count) }
        }
    }

    /// Whether the peer's write side is closed: readable within a short wait and a peek reads zero bytes.
    private static func sawEndOfFile(on connection: Int32) -> Bool {
        var poller = pollfd(fd: connection, events: Int16(POLLIN), revents: 0)
        guard poll(&poller, 1, 300) > 0 else { return false }
        var byte: UInt8 = 0
        return recv(connection, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == 0
    }

    /// The request the notary read, once it has answered.
    func received() -> [String: Any]? {
        finish()
        return request
    }

    private func finish() {
        if serving { _ = finished.wait(timeout: .now() + 5); serving = false }
    }

    func stop() {
        // Wakes a pending accept when the client never connected.
        shutdown(listener, SHUT_RDWR)
        close(listener)
        finish()
        unlink(path.path)
    }
}
