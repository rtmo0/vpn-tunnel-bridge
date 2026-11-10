import BridgeCore
import Foundation

public struct SavedTunnel: Hashable, Sendable {
    public let name: String
    public let kind: TunnelKind
    public let url: URL
}

/// Saved tunnel configs in ~/Library/Application Support/Bridge/Tunnels
/// (`<name>.conf` for WireGuard/AmneziaWG, `<name>.ovpn` for OpenVPN).
public enum TunnelLibrary {
    public static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Bridge/Tunnels", isDirectory: true)
    }

    public static func list() -> [SavedTunnel] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.compactMap { url -> SavedTunnel? in
            let ext = url.pathExtension.lowercased()
            guard ext == "conf" || ext == "ovpn" else { return nil }
            let name = url.deletingPathExtension().lastPathComponent
            let kind: TunnelKind
            if ext == "ovpn" {
                kind = .openvpn
            } else {
                kind = (try? String(contentsOf: url, encoding: .utf8)).map(TunnelKind.detect) ?? .amneziawg
            }
            return SavedTunnel(name: name, kind: kind, url: url)
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    public static func find(_ name: String) -> SavedTunnel? { list().first { $0.name == name } }

    public static func load(_ name: String) throws -> (text: String, kind: TunnelKind) {
        guard let saved = find(name) else { throw ClientError("No saved tunnel named '\(name)'") }
        return (try String(contentsOf: saved.url, encoding: .utf8), saved.kind)
    }

    /// A config read from disk, made self-contained.
    public struct Loaded: Sendable {
        public var suggestedName: String
        public var kind: TunnelKind
        public var text: String
        public var embedded: OpenVPNConfig.EmbeddedSecrets
        public var warnings: [String]

        public init(suggestedName: String, kind: TunnelKind, text: String,
                    embedded: OpenVPNConfig.EmbeddedSecrets, warnings: [String]) {
            self.suggestedName = suggestedName
            self.kind = kind
            self.text = text
            self.embedded = embedded
            self.warnings = warnings
        }
    }

    /// Reads and validates a config file. OpenVPN files get their referenced
    /// certificates and keys embedded.
    public static func read(fileAt url: URL) throws -> Loaded {
        let raw: String
        do {
            raw = try String(contentsOf: url, encoding: .utf8)
        } catch {
            raw = try String(contentsOf: url, encoding: .isoLatin1)
        }
        let name = TunnelName.sanitized(url.deletingPathExtension().lastPathComponent)
        let kind = TunnelKind.detect(raw)
        switch kind {
        case .amneziawg, .wireguard:
            let config = try TunnelConfig.parse(raw)
            return Loaded(suggestedName: name, kind: kind, text: raw,
                          embedded: .init(), warnings: config.warnings)
        case .openvpn:
            let config = try OpenVPNConfig.parse(raw)
            let (inlined, embedded) = try config.inliningFiles(relativeTo: url.deletingLastPathComponent())
            return Loaded(suggestedName: name, kind: .openvpn, text: inlined.render(), embedded: embedded, warnings: [])
        }
    }

    /// Imports a config file into the library and returns the saved entry.
    @discardableResult
    public static func importFile(at url: URL, as requestedName: String? = nil) throws -> SavedTunnel {
        let loaded = try read(fileAt: url)
        var name = requestedName.map(TunnelName.sanitized) ?? loaded.suggestedName
        if requestedName == nil {
            var counter = 2
            let base = name
            while find(name) != nil {
                name = "\(base)-\(counter)"
                counter += 1
            }
        }
        guard TunnelName.isValid(name) else { throw ClientError("'\(name)' is not a valid tunnel name") }

        if loaded.embedded.username != nil || loaded.embedded.password != nil {
            try? Keychain.saveCredentials(username: loaded.embedded.username ?? "",
                                          password: loaded.embedded.password ?? "", for: name)
        }
        if let passphrase = loaded.embedded.keyPassphrase {
            try? Keychain.savePassphrase(passphrase, for: name)
        }
        return try save(loaded.text, kind: loaded.kind, as: name)
    }

    @discardableResult
    public static func save(_ text: String, kind: TunnelKind, as name: String) throws -> SavedTunnel {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        // Replace any existing entry with the same name but another extension.
        if let existing = find(name) { try? FileManager.default.removeItem(at: existing.url) }
        let url = directory.appendingPathComponent("\(name).\(kind == .openvpn ? "ovpn" : "conf")")
        try Data(text.utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return SavedTunnel(name: name, kind: kind, url: url)
    }

    public static func remove(_ name: String) throws {
        guard let saved = find(name) else { throw ClientError("No saved tunnel named '\(name)'") }
        try FileManager.default.removeItem(at: saved.url)
        Keychain.deleteAll(for: name)
    }
}

public struct ClientError: Error, CustomStringConvertible, LocalizedError {
    public let description: String
    public let code: HelperErrorCode?

    public init(_ description: String, code: HelperErrorCode? = nil) {
        self.description = description
        self.code = code
    }

    public var errorDescription: String? { description }
}
