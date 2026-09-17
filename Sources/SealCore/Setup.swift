import Foundation

/// What `seal setup` leaves for the user: the group key line and the recovery share, shown once.
public struct SetupReport {
    public typealias Wrap = (SecretShare) throws -> SealedShare

    public let groupPublicKey: String
    public let recoveryShare: SecretShare
}

/// `seal setup` (ADR 0002, point 6): the dealer runs in the helper; the user's share is sealed by `wrap`
/// (the Secure Enclave in the executable, a software key in tests); the Mac's share and the public pieces
/// are written under the group directory; the recovery share is returned and never written.
public enum Setup {
    public struct Refused: Error, CustomStringConvertible {
        public let reason: String
        public var description: String { reason }
    }

    public static func run(in group: GroupKey, helper: FrostHelper, wrap: SetupReport.Wrap) throws -> SetupReport {
        guard !group.exists else {
            throw Refused(reason: "a group key already exists in \(group.directory.path); remove the directory to start a new group")
        }
        let generated = try helper.keygen()
        let user = generated.shares[0], mac = generated.shares[1], recovery = generated.shares[2]
        let sealed = try wrap(user)

        let files = FileManager.default
        try files.createDirectory(at: group.directory, withIntermediateDirectories: true,
                                  attributes: [.posixPermissions: 0o700])
        try write(mac.bytes, to: group.macShareFile, mode: 0o600)
        try sealed.write(to: group.sealedUserShareFile)
        try write(generated.publicKeyPackage, to: group.publicKeyPackageFile, mode: 0o644)
        let line = GroupKey.blob(of: generated.groupPublicKey).map { "\($0) seal-group" } ?? generated.groupPublicKey
        try write(Data((line + "\n").utf8), to: group.publicKeyFile, mode: 0o644)
        return SetupReport(groupPublicKey: line, recoveryShare: recovery)
    }

    private static func write(_ data: Data, to file: URL, mode: Int) throws {
        try data.write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
    }
}
