import Foundation

/// Where a Signing request came from: the Session it was issued in, the directory, and the git command line
/// that triggered it. Resolved without user input; never blank.
public struct Origin: Equatable {
    /// A Claude Code session's title (custom, else generated, else the short id), or the nearest application
    /// ancestor of this process with its pid, or "unknown" when the process tree gives nothing.
    public let session: String
    /// The working directory git ran Seal in.
    public let directory: String
    /// The full argument list of the parent process (git), space-joined, or "unknown" when it cannot be read.
    public let command: String
    /// The pid of the nearest application ancestor (the terminal or editor the request came from), when there
    /// is one, so the Review can bring it forward.
    public let applicationPid: pid_t?

    public init(session: String, directory: String, command: String, applicationPid: pid_t? = nil) {
        self.session = session
        self.directory = directory
        self.command = command
        self.applicationPid = applicationPid
    }

    static func resolve(environment: [String: String], workingDirectory: URL, processTable: ProcessTable,
                        sessionRecords: URL) -> Origin {
        let me = ProcessInfo.processInfo.processIdentifier
        let command = processTable.parent(me).flatMap(processTable.arguments)?.joined(separator: " ")
        let application = processTable.nearestApplication(above: me)
        return Origin(session: session(environment: environment, application: application, sessionRecords: sessionRecords),
                      directory: workingDirectory.path,
                      command: command.flatMap { $0.isEmpty ? nil : $0 } ?? "unknown",
                      applicationPid: application?.pid)
    }

    private static func session(environment: [String: String], application: ProcessTable.Application?,
                                sessionRecords: URL) -> String {
        if let id = environment["CLAUDE_CODE_SESSION_ID"] ?? environment["CLAUDE_SESSION_ID"], !id.isEmpty {
            return SessionRecords(directory: sessionRecords).title(of: id) ?? String(id.prefix(8))
        }
        if let application {
            return "\(application.name) (pid \(application.pid))"
        }
        return "unknown"
    }
}

/// Claude Code's local session transcripts: `<records>/<project>/<session id>.jsonl`, one JSON object per line.
/// A title is the last `custom-title` line if any, else the last `ai-title` line. Best effort over an
/// undocumented format: any failure reads as "no title".
struct SessionRecords {
    let directory: URL

    func title(of sessionId: String) -> String? {
        // The session id names the file; the project directory is a mangled cwd, so look in every project.
        guard sessionId.range(of: "^[A-Za-z0-9-]+$", options: .regularExpression) != nil,
              let projects = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        else { return nil }
        for project in projects {
            let transcript = project.appendingPathComponent("\(sessionId).jsonl")
            guard let data = FileManager.default.contents(atPath: transcript.path) else { continue }
            return title(inTranscript: data)
        }
        return nil
    }

    private func title(inTranscript data: Data) -> String? {
        var custom: String?, generated: String?
        for line in data.split(separator: UInt8(ascii: "\n")) {
            // Only title lines are decoded; the rest of the transcript is skipped by a cheap substring check.
            guard line.contains("title".utf8) else { continue }
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                  let type = object["type"] as? String else { continue }
            switch type {
            case "custom-title": custom = object["customTitle"] as? String
            case "ai-title": generated = object["aiTitle"] as? String
            default: continue
            }
        }
        return [custom, generated].compactMap { $0 }.first { !$0.isEmpty }
    }
}

private extension Data {
    func contains<S: Sequence>(_ needle: S) -> Bool where S.Element == UInt8 {
        let bytes = Array(needle)
        guard !bytes.isEmpty, count >= bytes.count else { return false }
        return withUnsafeBytes { buffer -> Bool in
            let raw = buffer.bindMemory(to: UInt8.self)
            for start in 0...(raw.count - bytes.count) where raw[start] == bytes[0] {
                if (1..<bytes.count).allSatisfy({ raw[start + $0] == bytes[$0] }) { return true }
            }
            return false
        }
    }
}

/// The process tree as three lookups by pid, so tests can supply a synthetic ancestry.
/// `live` reads the kernel's process table.
public struct ProcessTable {
    public var parent: (pid_t) -> pid_t?
    public var arguments: (pid_t) -> [String]?
    public var executablePath: (pid_t) -> String?

    public init(parent: @escaping (pid_t) -> pid_t?, arguments: @escaping (pid_t) -> [String]?,
                executablePath: @escaping (pid_t) -> String?) {
        self.parent = parent
        self.arguments = arguments
        self.executablePath = executablePath
    }

    struct Application: Equatable {
        let name: String
        let pid: pid_t
    }

    /// The closest ancestor whose executable lives in an application bundle (`<Name>.app/Contents/MacOS/`).
    func nearestApplication(above pid: pid_t) -> Application? {
        var current = pid
        var visited: Set<pid_t> = [pid]
        while let next = parent(current), next > 1, visited.insert(next).inserted {
            if let path = executablePath(next), let name = Self.bundleName(of: path) {
                return Application(name: name, pid: next)
            }
            current = next
        }
        return nil
    }

    static func bundleName(of executablePath: String) -> String? {
        let components = executablePath.split(separator: "/").map(String.init)
        guard let macOS = components.lastIndex(of: "MacOS"), macOS >= 2,
              components[macOS - 1] == "Contents", components[macOS - 2].hasSuffix(".app")
        else { return nil }
        return String(components[macOS - 2].dropLast(4))
    }

    public static let live = ProcessTable(parent: LiveProcessTable.parent, arguments: LiveProcessTable.arguments,
                                          executablePath: LiveProcessTable.executablePath)
}

/// Darwin's process table through `sysctl` and `proc_pidpath`.
enum LiveProcessTable {
    static func parent(_ pid: pid_t) -> pid_t? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&name, UInt32(name.count), &info, &size, nil, 0) == 0, size > 0 else { return nil }
        return info.kp_eproc.e_ppid
    }

    /// `KERN_PROCARGS2`: an argc word, the executable path, NULs, then argc NUL-terminated arguments.
    static func arguments(_ pid: pid_t) -> [String]? {
        var name: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&name, UInt32(name.count), nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&name, UInt32(name.count), &buffer, &size, nil, 0) == 0 else { return nil }
        let argc = Int(buffer.withUnsafeBytes { $0.load(as: Int32.self) })
        var index = MemoryLayout<Int32>.size
        // Skip the executable path and the padding NULs after it.
        while index < size, buffer[index] != 0 { index += 1 }
        while index < size, buffer[index] == 0 { index += 1 }
        var arguments: [String] = []
        while arguments.count < argc, index < size {
            let start = index
            while index < size, buffer[index] != 0 { index += 1 }
            arguments.append(String(decoding: buffer[start..<index], as: UTF8.self))
            index += 1
        }
        return arguments
    }

    static func executablePath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN)) // PROC_PIDPATHINFO_MAXSIZE, not exported to Swift
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }
}
