import CryptoKit
import Foundation
import XCTest
@testable import SealCore

/// The user's share wrapped to a key-agreement key: in production the Secure Enclave key behind Touch ID,
/// here a software P-256 key through the same code path.
final class SealedShareTests: XCTestCase {
    private let share = SecretShare(Data("{\"identifier\":\"01\",\"signing_share\":\"...\"}".utf8))

    func testOpensToTheShareItSealedWithTheSameKey() throws {
        let key = P256.KeyAgreement.PrivateKey()

        let sealed = try SealedShare.seal(share, to: key, keyRepresentation: key.rawRepresentation)

        XCTAssertEqual(try sealed.open(with: key), share)
        XCTAssertEqual(sealed.keyRepresentation, key.rawRepresentation)
    }

    func testDoesNotOpenWithAnotherKey() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let sealed = try SealedShare.seal(share, to: key, keyRepresentation: key.rawRepresentation)

        XCTAssertThrowsError(try sealed.open(with: P256.KeyAgreement.PrivateKey()))
    }

    func testDoesNotOpenWhenTheCiphertextIsTampered() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let sealed = try SealedShare.seal(share, to: key, keyRepresentation: key.rawRepresentation)
        var bytes = sealed.ciphertext
        bytes[bytes.count / 2] ^= 0x01
        let tampered = SealedShare(keyRepresentation: sealed.keyRepresentation, ephemeralPublicKey: sealed.ephemeralPublicKey,
                                   ciphertext: bytes)

        XCTAssertThrowsError(try tampered.open(with: key))
    }

    func testSurvivesTheFileRoundTripAndTheFileHoldsNoPlaintext() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let sealed = try SealedShare.seal(share, to: key, keyRepresentation: key.rawRepresentation)
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("share-\(UUID().uuidString).sealed")
        defer { try? FileManager.default.removeItem(at: file) }

        try sealed.write(to: file)
        let read = try SealedShare(contentsOf: file)

        XCTAssertEqual(try read.open(with: key), share)
        let raw = try Data(contentsOf: file)
        XCTAssertNil(raw.range(of: share.bytes), "the sealed file must not contain the share")
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
    }

    func testASecretShareNeverPrintsItsBytes() {
        XCTAssertFalse("\(share)".contains("identifier"))
        XCTAssertFalse(String(describing: share).contains("signing_share"))
    }
}
