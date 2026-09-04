import Foundation
import XCTest
@testable import SealCore

/// Until the Review exists, a Signing request is refused as malformed and nothing is written.
final class SigningRequestTests: XCTestCase {
    private var stub: RecordingSSHKeygen!
    private var bufferFile: URL!
    private var signingRequest: [String] { ["-Y", "sign", "-n", "git", "-f", "/tmp/key.pub", bufferFile.path] }

    override func setUpWithError() throws {
        stub = try RecordingSSHKeygen()
        bufferFile = stub.directory.appendingPathComponent("buffer")
        try Data("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n".utf8).write(to: bufferFile)
    }

    override func tearDownWithError() throws {
        try stub.remove()
    }

    func testSignExitsWithMalformedRequestStatusAndOneLineMessage() throws {
        let exit = Seal.run(arguments: signingRequest, environment: stub.environment)

        XCTAssertEqual(exit.status, 3)
        let message = try XCTUnwrap(exit.message)
        XCTAssertTrue(message.hasPrefix("seal: "), message)
        XCTAssertFalse(message.contains("\n"), message)
    }

    func testSignWritesNoSignatureFileAndNeverReachesSSHKeygen() throws {
        _ = Seal.run(arguments: signingRequest, environment: stub.environment)

        let signatureFile = bufferFile.appendingPathExtension("sig")
        XCTAssertFalse(FileManager.default.fileExists(atPath: signatureFile.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: stub.recordFile.path))
    }

    func testMissingModeExitsWithMalformedRequestStatus() {
        XCTAssertEqual(Seal.run(arguments: [], environment: stub.environment).status, 3)
        XCTAssertEqual(Seal.run(arguments: ["-Y"], environment: stub.environment).status, 3)
        XCTAssertEqual(Seal.run(arguments: ["-f", "/tmp/key.pub"], environment: stub.environment).status, 3)
    }

    func testUnknownModeExitsWithMalformedRequestStatus() {
        let exit = Seal.run(arguments: ["-Y", "encrypt", "-f", "/tmp/key.pub"], environment: stub.environment)
        XCTAssertEqual(exit.status, 3)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stub.recordFile.path))
    }
}
