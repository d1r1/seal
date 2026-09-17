import CryptoKit
import Foundation

/// One FROST key package as the helper reads it (JSON bytes). Never printed: its description is redacted.
public struct SecretShare: Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let bytes: Data

    public init(_ bytes: Data) {
        self.bytes = bytes
    }

    public var description: String { "SecretShare(redacted)" }
    public var debugDescription: String { description }
}

/// A P-256 key that can agree on a shared secret: the Secure Enclave key behind Touch ID in the `seal`
/// executable, a software key in tests. Both CryptoKit types already have this shape.
public protocol KeyAgreementPrivateKey {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: KeyAgreementPrivateKey {}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: KeyAgreementPrivateKey {}

/// The user's share encrypted to a key-agreement key (ADR 0002, point 3): ECDH with an ephemeral P-256
/// key, HKDF-SHA256, ChaCha20-Poly1305. The file also carries the wrapping key's own representation
/// (the Secure Enclave blob), so that opening needs the file and the enclave, nothing else.
public struct SealedShare: Codable, Equatable {
    public let keyRepresentation: Data
    public let ephemeralPublicKey: Data
    public let ciphertext: Data

    private static let salt = Data("seal sealed share v1".utf8)

    public init(keyRepresentation: Data, ephemeralPublicKey: Data, ciphertext: Data) {
        self.keyRepresentation = keyRepresentation
        self.ephemeralPublicKey = ephemeralPublicKey
        self.ciphertext = ciphertext
    }

    public static func seal(_ share: SecretShare, to key: some KeyAgreementPrivateKey, keyRepresentation: Data) throws -> SealedShare {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: key.publicKey)
        let symmetric = derive(secret, ephemeral: ephemeral.publicKey, recipient: key.publicKey)
        let box = try ChaChaPoly.seal(share.bytes, using: symmetric)
        return SealedShare(keyRepresentation: keyRepresentation, ephemeralPublicKey: ephemeral.publicKey.x963Representation,
                           ciphertext: box.combined)
    }

    /// The share, given the key the file was sealed to. With the Secure Enclave key this is where Touch ID happens.
    public func open(with key: some KeyAgreementPrivateKey) throws -> SecretShare {
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        let secret = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        let symmetric = Self.derive(secret, ephemeral: ephemeral, recipient: key.publicKey)
        return SecretShare(try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: ciphertext), using: symmetric))
    }

    private static func derive(_ secret: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey,
                               recipient: P256.KeyAgreement.PublicKey) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                       sharedInfo: ephemeral.x963Representation + recipient.x963Representation,
                                       outputByteCount: 32)
    }

    public init(contentsOf file: URL) throws {
        self = try JSONDecoder().decode(SealedShare.self, from: Data(contentsOf: file))
    }

    /// Writes the file with mode 0600.
    public func write(to file: URL) throws {
        try JSONEncoder().encode(self).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}
