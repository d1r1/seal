import CryptoKit
import Foundation
import XCTest
@testable import SealCore

/// The group key's home under the support directory, and Setup filling it once.
final class GroupKeyTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("seal-support-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func runSetup(_ wrap: SetupReport.Wrap? = nil) throws -> SetupReport {
        let key = P256.KeyAgreement.PrivateKey()
        return try Setup.run(in: GroupKey(directory: directory), helper: FrostHelperFixture.helper,
                             wrap: wrap ?? { share in try SealedShare.seal(share, to: key, keyRepresentation: key.rawRepresentation) })
    }

    private func mode(of file: URL) throws -> Int? {
        try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int
    }

    func testNoGroupKeyBeforeSetup() {
        XCTAssertFalse(GroupKey(directory: directory).exists)
    }

    func testSetupWritesTheFourFilesWithTheirModes() throws {
        let report = try runSetup()

        let group = GroupKey(directory: directory)
        XCTAssertTrue(group.exists)
        XCTAssertEqual(try group.publicKeyLine(), report.groupPublicKey)
        XCTAssertTrue(report.groupPublicKey.hasPrefix("ssh-ed25519 AAAA"), report.groupPublicKey)
        XCTAssertEqual(try mode(of: group.publicKeyFile), 0o644)
        XCTAssertEqual(try mode(of: group.publicKeyPackageFile), 0o644)
        XCTAssertEqual(try mode(of: group.macShareFile), 0o600)
        XCTAssertEqual(try mode(of: group.sealedUserShareFile), 0o600)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: Data(contentsOf: group.macShareFile)) as? [String: Any])
    }

    func testSetupSealsTheUserShareAndHandsBackOnlyTheRecoveryShare() throws {
        var sealedShare: SecretShare?
        let key = P256.KeyAgreement.PrivateKey()
        let report = try runSetup { share in
            sealedShare = share
            return try SealedShare.seal(share, to: key, keyRepresentation: key.rawRepresentation)
        }

        let group = GroupKey(directory: directory)
        let opened = try SealedShare(contentsOf: group.sealedUserShareFile).open(with: key)
        XCTAssertEqual(opened, sealedShare)
        let mac = try Data(contentsOf: group.macShareFile)
        XCTAssertNotEqual(opened.bytes, mac)
        XCTAssertNotEqual(report.recoveryShare.bytes, mac)
        XCTAssertNotEqual(report.recoveryShare, opened)
        // Three distinct key packages with identifiers 1, 2, 3, in the order user, Mac, recovery.
        func identifier(_ data: Data) throws -> String {
            try XCTUnwrap((try JSONSerialization.jsonObject(with: data) as? [String: Any])?["identifier"] as? String)
        }
        XCTAssertEqual(try identifier(opened.bytes), "0100000000000000000000000000000000000000000000000000000000000000")
        XCTAssertEqual(try identifier(mac), "0200000000000000000000000000000000000000000000000000000000000000")
        XCTAssertEqual(try identifier(report.recoveryShare.bytes), "0300000000000000000000000000000000000000000000000000000000000000")
    }

    func testSetupRefusesWhenAGroupKeyAlreadyExists() throws {
        _ = try runSetup()
        let before = try Data(contentsOf: GroupKey(directory: directory).macShareFile)

        XCTAssertThrowsError(try runSetup()) { error in
            XCTAssertTrue("\(error)".contains("already"), "\(error)")
        }
        XCTAssertEqual(try Data(contentsOf: GroupKey(directory: directory).macShareFile), before)
    }

    func testIsGroupKeyComparesTheKeyBlobNotTheComment() throws {
        let report = try runSetup()
        let group = GroupKey(directory: directory)
        let blob = report.groupPublicKey.split(separator: " ").prefix(2).joined(separator: " ")
        let renamed = directory.appendingPathComponent("renamed.pub")
        try "\(blob) another comment\n".write(to: renamed, atomically: true, encoding: .utf8)
        let other = directory.appendingPathComponent("other.pub")
        try "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB4Vf1YHuUOa7dq5c4TrOgWWbQ4KM6zNk6qgQsbw5J1x other\n"
            .write(to: other, atomically: true, encoding: .utf8)

        XCTAssertTrue(group.isGroupKey(fileAt: group.publicKeyFile.path))
        XCTAssertTrue(group.isGroupKey(fileAt: renamed.path))
        XCTAssertFalse(group.isGroupKey(fileAt: other.path))
        XCTAssertFalse(group.isGroupKey(fileAt: directory.appendingPathComponent("missing.pub").path))
    }

    func testIsGroupKeyIsFalseWithoutAGroup() throws {
        let other = FileManager.default.temporaryDirectory.appendingPathComponent("k-\(UUID().uuidString).pub")
        try "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB4Vf1YHuUOa7dq5c4TrOgWWbQ4KM6zNk6qgQsbw5J1x\n".write(to: other, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: other) }
        XCTAssertFalse(GroupKey(directory: directory).isGroupKey(fileAt: other.path))
    }
}
