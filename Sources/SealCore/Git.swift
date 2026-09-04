import Foundation

/// The repository git ran Seal in: its working directory and the environment git gave. Read only, through
/// `git` from `PATH`: the branch, and `diff --stat` between hashes taken from the signed body.
struct Repository {
    let workingDirectory: URL
    let environment: [String: String]

    struct GitFailed: Error {
        let status: Int32
        let stderr: String
    }

    func git(_ arguments: String...) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["git"] + arguments
        process.currentDirectoryURL = workingDirectory
        process.environment = environment
        let stdout = Pipe(), stderr = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        // Drain both pipes concurrently so a chatty stderr cannot block git while stdout is read.
        var err = Data()
        let drained = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            err = stderr.fileHandleForReading.readDataToEndOfFile()
            drained.signal()
        }
        let out = String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        drained.wait()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw GitFailed(status: process.terminationStatus,
                            stderr: String(decoding: err, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return out
    }

    /// The symbolic ref of `HEAD`, or "detached" when there is none. Any other git failure is named,
    /// not passed off as a detached head.
    func branch() -> String {
        do {
            return try git("symbolic-ref", "--short", "-q", "HEAD").trimmingCharacters(in: .whitespacesAndNewlines)
        } catch let failed as GitFailed where failed.status == 1 && failed.stderr.isEmpty {
            return "detached"
        } catch let failed as GitFailed {
            return "unknown: \(failed.stderr)"
        } catch {
            return "unknown: \(error.localizedDescription)"
        }
    }

    /// `diff --stat` from each parent to the signed tree; a root commit is compared with the empty tree.
    /// A git failure is shown in place of the stat rather than blocking the Review.
    func changes(from parents: [String], to tree: String) -> [ChangeSummary] {
        let bases: [(parent: String?, hash: String)] = parents.isEmpty
            ? [(nil, emptyTree())]
            : parents.map { ($0, $0) }
        return bases.map { base in
            let stat: String
            do {
                stat = try git("diff", "--stat", base.hash, tree)
            } catch let failed as GitFailed {
                stat = "git diff --stat failed: \(failed.stderr)"
            } catch {
                stat = "git diff --stat failed: \(error.localizedDescription)"
            }
            return ChangeSummary(parent: base.parent, stat: stat.trimmingCharacters(in: .newlines))
        }
    }

    /// The empty tree's hash under the repository's object format.
    private func emptyTree() -> String {
        let hash = try? git("hash-object", "-t", "tree", "/dev/null")
        return (hash ?? "4b825dc642cb6eb9a060e54bf8d69288fbee4904").trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
