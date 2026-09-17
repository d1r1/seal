import CryptoKit
import Foundation
import LocalAuthentication
import SealCore

/// `seal setup`: the group key, once (ADR 0002, point 6). The user's share is sealed to a new Secure Enclave
/// key whose use needs the current Touch ID enrolment (device password as fallback); the enclave enforces
/// that on every unwrap. Prints the recovery share and the hand steps; changes no git config.
enum SetupCommand {
    static func run(group: GroupKey, helper: FrostHelper) -> Int32 {
        let report: SetupReport
        do {
            report = try Setup.run(in: group, helper: helper) { share in
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: try UserShare.accessControl())
                return try SealedShare.seal(share, to: key, keyRepresentation: key.dataRepresentation)
            }
        } catch {
            FileHandle.standardError.write(Data("seal: setup failed: \(error)\n".utf8))
            return 2
        }
        let key = report.groupPublicKey
        print("""
        Group key created in \(group.directory.path)
          share-mac.json      Seal's share (0600)
          share-user.sealed   your share, sealed to the Secure Enclave; Touch ID unwraps it per signature

        Recovery share: shown once, never written by Seal. Store it in 1Password now.
        \(String(decoding: report.recoveryShare.bytes, as: UTF8.self))

        Group public key:
        \(key)

        Hand steps (Seal changes no git config):
          1. Register the key on GitHub as a *signing* key: https://github.com/settings/ssh/new
          2. Allowed signers: echo '<email> namespaces="git" \(key)' >> ~/.config/git/allowed_signers
          3. Signing key: git config --global user.signingkey 'key::\(key)'
        """)
        return 0
    }
}

/// The user's share on this Mac: sealed to a Secure Enclave key, unwrapped by Touch ID.
enum UserShare {
    static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                            [.privateKeyUsage, .biometryCurrentSet], &error) else {
            let reason = error.map { "\($0.takeRetainedValue())" } ?? "unknown"
            throw NSError(domain: "seal", code: 1, userInfo: [NSLocalizedDescriptionKey: "cannot create access control: \(reason)"])
        }
        return control
    }

    /// Opens the sealed share with the enclave key through `context`, so the prompt is the card's own.
    static func unwrap(_ group: GroupKey, context: LAContext) throws -> SecretShare {
        let sealed = try SealedShare(contentsOf: group.sealedUserShareFile)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: sealed.keyRepresentation,
                                                                 authenticationContext: context)
        return try sealed.open(with: key)
    }
}
