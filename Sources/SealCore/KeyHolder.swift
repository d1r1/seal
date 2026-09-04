import Foundation

/// The program that owns the private key: `ssh-keygen -Y sign` over the inherited `SSH_AUTH_SOCK`
/// (the 1Password agent), or a key file when `-f` names one. Seal never sees the key.
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
            return .keyHolderFailure("ssh-keygen exited \(result.status)" + (result.stderr.isEmpty ? "" : ": \(result.stderr)"))
        }
        return .signed
    }
}
