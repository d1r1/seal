import Foundation

/// The personal key's holder (ADR 0001): `ssh-keygen -Y sign` over the inherited `SSH_AUTH_SOCK` (the 1Password
/// agent), or a key file when `-f` names one. Seal never sees that key.
/// Called only after Approval; the signature file is whatever `ssh-keygen` writes next to the buffer file.
enum KeyHolder {
    static func sign(_ request: SigningRequest, environment: [String: String]) -> Exit {
        let result: SSHKeygen.Result
        do {
            result = try SSHKeygen.run(request.arguments, environment: environment, capturingStderr: true)
        } catch let failure as SSHKeygen.CannotRun {
            return .keyHolderFailure(failure.reason)
        } catch {
            return .keyHolderFailure(error.localizedDescription)
        }
        guard result.status == 0 else {
            // ssh-keygen writes the signature only on success; make sure nothing stale or partial is left behind.
            try? FileManager.default.removeItem(at: request.bufferFile.appendingPathExtension("sig"))
            return .keyHolderFailure("ssh-keygen exited \(result.status)" + (result.stderr.isEmpty ? "" : ": \(result.stderr)"))
        }
        return .signed
    }

    /// git's arguments without `-Y sign`: the helper's `sign` command takes the rest as `ssh-keygen` would.
    static func withoutMode(_ arguments: [String]) -> [String] {
        var rest = arguments
        if let flag = rest.firstIndex(of: "-Y") {
            rest.removeSubrange(flag...min(flag + 1, rest.count - 1))
        }
        return rest
    }
}

/// The group key's holder (ADR 0002): the `seal-frost` helper, given git's own `-Y sign` arguments, Seal's share
/// through the group directory and the user's unwrapped share on stdin. The helper writes `<buffer>.sig`; on any
/// failure nothing is left behind.
enum GroupKeyHolder {
    static func sign(_ request: SigningRequest, share: SecretShare, group: GroupKey, helper: FrostHelper) -> Exit {
        let result: FrostHelper.Result
        do {
            result = try helper.run(["sign"] + KeyHolder.withoutMode(request.arguments), stdin: share.bytes,
                                    environment: ["SEAL_FROST_HOME": group.directory.path])
        } catch let failure as FrostHelper.Failed {
            return .keyHolderFailure(failure.reason)
        } catch {
            return .keyHolderFailure(error.localizedDescription)
        }
        guard result.status == 0 else {
            try? FileManager.default.removeItem(at: request.bufferFile.appendingPathExtension("sig"))
            return .keyHolderFailure("seal-frost exited \(result.status)" + (result.stderr.isEmpty ? "" : ": \(result.stderr)"))
        }
        return .signed
    }
}
