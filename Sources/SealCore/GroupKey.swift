import Foundation

/// The group key's home (ADR 0002, point 3): the public key, the FROST public key package, the Mac's share and
/// the user's sealed share, under Seal's support directory. The recovery share is never here.
public struct GroupKey {
    public let directory: URL

    public static let defaultDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/seal")

    public init(directory: URL = defaultDirectory) {
        self.directory = directory
    }

    public var publicKeyFile: URL { directory.appendingPathComponent("group.pub") }
    public var publicKeyPackageFile: URL { directory.appendingPathComponent("group.json") }
    public var macShareFile: URL { directory.appendingPathComponent("share-mac.json") }
    public var sealedUserShareFile: URL { directory.appendingPathComponent("share-user.sealed") }

    /// A group key exists once its public key has been written; Setup writes it last.
    public var exists: Bool { FileManager.default.fileExists(atPath: publicKeyFile.path) }

    struct Missing: Error, CustomStringConvertible {
        let file: URL
        var description: String { "no group key: \(file.path) is missing" }
    }

    /// The one OpenSSH line of `group.pub`.
    public func publicKeyLine() throws -> String {
        guard let data = FileManager.default.contents(atPath: publicKeyFile.path) else { throw Missing(file: publicKeyFile) }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Whether the key file git named with `-f` holds the group key: the key type and blob are compared,
    /// the comment is not. False whenever either file cannot be read.
    public func isGroupKey(fileAt path: String) -> Bool {
        guard exists, let named = FileManager.default.contents(atPath: path),
              let mine = try? publicKeyLine() else { return false }
        return Self.blob(of: String(decoding: named, as: UTF8.self)) == Self.blob(of: mine)
    }

    static func blob(of line: String) -> String? {
        let fields = line.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ", omittingEmptySubsequences: true)
        guard fields.count >= 2 else { return nil }
        return fields[0] + " " + fields[1]
    }
}
