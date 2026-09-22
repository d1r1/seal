import Foundation

/// The notary's unix socket (seal-frost ADR 0003, decision 1). The protocol is the contract in Desk,
/// `docs/notary-protocol.md`: one JSON request line, one JSON response line, one request per connection.
public struct NotarySocket {
    public let path: URL

    public static let defaultPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/notary/notary.sock")

    public init(path: URL = defaultPath) {
        self.path = path
    }

    struct NotFound: Error {}

    struct Failed: Error {
        let reason: String
    }

    /// Connects, writes `line` and a newline, reads one response line, closes. The write side is never
    /// half-closed: bun's unix-socket server drops a half-closed connection before it answers, and the newline
    /// already ends the request. No timeout of its own: a request the notary asks the user about waits for them.
    func exchange(_ line: Data) throws -> Data {
        let connection = socket(AF_UNIX, SOCK_STREAM, 0)
        guard connection >= 0 else { throw Failed(reason: "cannot open a socket: \(String(cString: strerror(errno)))") }
        defer { close(connection) }
        var noSigpipe: Int32 = 1
        setsockopt(connection, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_un()
        let pathBytes = Array(path.path.utf8CString)
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw Failed(reason: "socket path too long: \(path.path)")
        }
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            pathBytes.withUnsafeBytes { buffer.copyBytes(from: $0) }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(connection, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            if errno == ENOENT || errno == ECONNREFUSED { throw NotFound() }
            throw Failed(reason: "cannot connect to \(path.path): \(String(cString: strerror(errno)))")
        }

        var request = line
        request.append(UInt8(ascii: "\n"))
        try request.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = write(connection, buffer.baseAddress! + offset, buffer.count - offset)
                if written < 0, errno == EINTR { continue }
                guard written > 0 else { throw Failed(reason: "cannot write the request: \(String(cString: strerror(errno)))") }
                offset += written
            }
        }

        var response = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(connection, &chunk, chunk.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw Failed(reason: "cannot read the response: \(String(cString: strerror(errno)))") }
            if count == 0 { return response }
            response.append(contentsOf: chunk[..<count])
            if let newline = response.firstIndex(of: UInt8(ascii: "\n")) { return response[..<newline] }
        }
    }
}

/// The agent path: the Signing request goes to the notary and its answer decides the exit. No card, no Touch ID.
enum Notary {
    /// The request line of the contract. It carries no key: the notary signs with its own key, so whatever `-f`
    /// names is ignored on the agent path and nothing from its file reaches the notary.
    static func requestLine(for request: SigningRequest) throws -> Data {
        var origin: [String: Any] = ["directory": request.origin.directory, "branch": request.branch,
                                     "command": request.origin.command]
        origin["paseoAgentId"] = request.origin.paseoAgentId
        let object: [String: Any] = ["v": 1, "action": "sign", "namespace": request.namespace,
                                     "body": request.body, "origin": origin]
        return try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
    }

    static func sign(_ request: SigningRequest, socket: NotarySocket) -> Exit {
        let signatureFile = request.bufferFile.appendingPathExtension("sig")
        let exit = outcome(request, socket: socket, signatureFile: signatureFile)
        if exit.status != 0 {
            // Nothing stale or partial is left behind, as with the other Key holders.
            try? FileManager.default.removeItem(at: signatureFile)
        }
        return exit
    }

    private static func outcome(_ request: SigningRequest, socket: NotarySocket, signatureFile: URL) -> Exit {
        let response: Data
        do {
            response = try socket.exchange(try requestLine(for: request))
        } catch is NotarySocket.NotFound {
            return .notaryNotFound(at: socket.path)
        } catch let failed as NotarySocket.Failed {
            return .notaryFailure(failed.reason)
        } catch {
            return .notaryFailure(error.localizedDescription)
        }
        switch Response.parse(response) {
        case .signed(let signature):
            do {
                try Data(signature.utf8).write(to: signatureFile)
            } catch {
                return .keyHolderFailure("cannot write \(signatureFile.path): \(error.localizedDescription)")
            }
            return .signed
        case .refused(let reason):
            return .notaryRefusal(reason)
        case .error(let reason):
            return .notaryFailure(reason)
        case .malformed(let detail):
            return .notaryFailure("malformed response: \(detail)")
        }
    }

    enum Response: Equatable {
        case signed(String)
        case refused(String)
        case error(String)
        case malformed(String)

        static func parse(_ line: Data) -> Response {
            guard !line.isEmpty else { return .malformed("no response line") }
            guard let object = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else {
                return .malformed("not a JSON object")
            }
            // JSONSerialization reads `true` as 1 and 1 as true; the contract's types are checked exactly.
            guard let version = object["v"] as? NSNumber, !version.isBoolean else { return .malformed("no version") }
            guard version == 1 else { return .malformed("unknown version \(version)") }
            guard let ok = object["ok"] as? NSNumber, ok.isBoolean else { return .malformed("no ok") }
            if ok.boolValue {
                guard let signature = object["signature"] as? String, !signature.isEmpty else {
                    return .malformed("no signature")
                }
                return .signed(signature)
            }
            guard let reason = object["reason"] as? String else { return .malformed("no reason") }
            switch object["status"] as? String {
            case "refused": return .refused(reason)
            case "error": return .error(reason)
            case let status?: return .malformed("unknown status '\(status)'")
            case nil: return .malformed("no status")
            }
        }
    }
}

private extension NSNumber {
    var isBoolean: Bool { CFGetTypeID(self) == CFBooleanGetTypeID() }
}
