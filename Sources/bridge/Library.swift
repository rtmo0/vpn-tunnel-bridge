import BridgeCore
import Foundation

/// Saved tunnel configs in ~/Library/Application Support/Bridge/Tunnels.
enum TunnelLibrary {
    static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Bridge/Tunnels", isDirectory: true)
    }

    static func url(for name: String) -> URL { directory.appendingPathComponent("\(name).conf") }

    static func names() -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return files.filter { $0.hasSuffix(".conf") }.map { String($0.dropLast(5)) }.sorted()
    }

    static func save(_ text: String, as name: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let url = url(for: name)
        try Data(text.utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func load(_ name: String) throws -> String {
        try String(contentsOf: url(for: name), encoding: .utf8)
    }

    static func remove(_ name: String) throws {
        try FileManager.default.removeItem(at: url(for: name))
    }
}

enum HelperClient {
    struct Unavailable: Error, CustomStringConvertible {
        let reason: String
        var description: String {
            "Cannot reach bridge-helper (\(reason)).\nInstall it with: sudo scripts/install.sh"
        }
    }

    static func send(_ request: HelperRequest, timeout: Int = 60) throws -> HelperResponse {
        let fd: Int32
        do {
            fd = try UnixSocket.connect(path: HelperProtocol.socketPath, timeout: timeout)
        } catch {
            throw Unavailable(reason: "\(error)")
        }
        defer { close(fd) }
        let data = try JSONEncoder.bridge.encode(request)
        try UnixSocket.writeAll(fd, String(decoding: data, as: UTF8.self) + "\n")
        let line = try UnixSocket.read(fd, until: "\n", limit: 4 << 20)
        guard !line.isEmpty else { throw Unavailable(reason: "connection closed") }
        return try JSONDecoder.bridge.decode(HelperResponse.self, from: Data(line.utf8))
    }
}
