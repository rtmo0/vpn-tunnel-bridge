import BridgeCore
import Foundation

public struct SavedTunnel: Hashable, Sendable {
    public let name: String
    public let kind: TunnelKind
    public let url: URL
}

/// Saved tunnel configs in ~/Library/Application Support/Bridge/Tunnels
/// (`<name>.conf` for WireGuard/AmneziaWG, `<name>.ovpn` for OpenVPN, and
/// `<name>.vless` / `.trojan` / `.hy2` holding a share link).
public enum TunnelLibrary {
    public static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Bridge/Tunnels", isDirectory: true)
    }

    public static func list() -> [SavedTunnel] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.compactMap { url -> SavedTunnel? in
            let ext = url.pathExtension.lowercased()
            let linkKinds: [String: TunnelKind] = ["vless": .vless, "trojan": .trojan, "hy2": .hysteria2]
            guard ext == "conf" || ext == "ovpn" || linkKinds[ext] != nil else { return nil }
            let name = url.deletingPathExtension().lastPathComponent
            let kind: TunnelKind
            if ext == "ovpn" {
                kind = .openvpn
            } else if let linkKind = linkKinds[ext] {
                kind = linkKind
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
        if kind == .openvpn || kind.usesXray, let links = try? proxyLinks(in: raw) {
            guard links.count == 1 else {
                throw ClientError("The file holds \(links.count) links; import it as a list instead")
            }
            return try loadedLink(links[0], fallbackName: name)
        }
        switch kind {
        case .vless, .trojan, .hysteria2:
            throw ClientError("No supported links in the file")
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

    // MARK: Share links (VLESS, Trojan, Hysteria 2)

    /// Share links in pasted text or a file: one per line (comments and other
    /// lines are skipped), or a base64 subscription.
    public static func proxyLinks(in text: String) throws -> [String] {
        func links(_ text: String) -> [String] {
            text.split(whereSeparator: \.isNewline).map { ProxyLink.normalized(String($0)) }
                .filter(ProxyLink.isLink)
        }
        var found = links(text)
        if found.isEmpty {
            // Subscriptions are usually the same list encoded as (url-safe) base64.
            let compact = text.filter { !$0.isWhitespace }
            var b64 = compact.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            while b64.count % 4 != 0 { b64.append("=") }
            if let data = Data(base64Encoded: b64), let decoded = String(data: data, encoding: .utf8) {
                found = links(decoded)
            }
        }
        guard !found.isEmpty else { throw ClientError("No vless://, trojan:// or hysteria2:// links found") }
        return found
    }

    public static func loadedLink(_ link: String, fallbackName: String) throws -> Loaded {
        let config = try ProxyLink.parse(link)
        let name = config.remark.map(TunnelName.sanitized) ?? fallbackName
        return Loaded(suggestedName: name == "tunnel" ? fallbackName : name, kind: config.kind,
                      text: ProxyLink.normalized(link), embedded: .init(), warnings: [])
    }

    /// Imports every share link in `text` (e.g. pasted from the clipboard).
    /// Links that fail are reported in `errors`; the rest are saved.
    public static func importLinks(_ text: String) throws -> (saved: [SavedTunnel], errors: [String]) {
        var saved: [SavedTunnel] = []
        var errors: [String] = []
        for (index, link) in try proxyLinks(in: text).enumerated() {
            do {
                let fallback = "\(ProxyLink.kind(of: link)?.fileExtension ?? "link")-\(index + 1)"
                saved.append(try store(try loadedLink(link, fallbackName: fallback), as: nil))
            } catch {
                errors.append("Link \(index + 1): \(error.localizedDescription)")
            }
        }
        return (saved, errors)
    }

    /// Imports a config file into the library and returns the saved entries
    /// (a file of VLESS links gives one tunnel per link).
    @discardableResult
    public static func importFile(at url: URL, as requestedName: String? = nil) throws -> [SavedTunnel] {
        let raw = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        let kind = TunnelKind.detect(raw)
        if requestedName == nil, kind == .openvpn || kind.usesXray, let links = try? proxyLinks(in: raw), links.count > 1 {
            let result = try importLinks(raw)
            if !result.errors.isEmpty { throw ClientError(result.errors.joined(separator: "\n")) }
            return result.saved
        }
        return [try store(try read(fileAt: url), as: requestedName)]
    }

    private static func store(_ loaded: Loaded, as requestedName: String?) throws -> SavedTunnel {
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
        let url = directory.appendingPathComponent("\(name).\(kind.fileExtension)")
        try Data(text.utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return SavedTunnel(name: name, kind: kind, url: url)
    }

    public static func remove(_ name: String) throws {
        guard let saved = find(name) else { throw ClientError("No saved tunnel named '\(name)'") }
        try FileManager.default.removeItem(at: saved.url)
        try? FileManager.default.removeItem(at: settingsURL(name))
        Keychain.deleteAll(for: name)
    }

    // MARK: Settings (routing / DNS overrides)

    static func settingsURL(_ name: String) -> URL { directory.appendingPathComponent("\(name).bridge.json") }

    public static func settings(for name: String) -> TunnelSettings {
        guard let data = try? Data(contentsOf: settingsURL(name)),
              let settings = try? JSONDecoder().decode(TunnelSettings.self, from: data) else { return TunnelSettings() }
        return settings
    }

    public static func saveSettings(_ settings: TunnelSettings, for name: String) throws {
        try settings.validate()
        let url = settingsURL(name)
        if settings.isDefault {
            try? FileManager.default.removeItem(at: url)
            return
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(settings).write(to: url, options: .atomic)
    }

    // MARK: Editing

    /// Validates and saves an edited configuration, keeping the tunnel's name.
    public static func updateConfig(_ text: String, for name: String) throws -> SavedTunnel {
        let kind = TunnelKind.detect(text)
        switch kind {
        case .amneziawg, .wireguard: _ = try TunnelConfig.parse(text)
        case .vless, .trojan, .hysteria2:
            _ = try ProxyLink.parse(text)
            return try save(ProxyLink.normalized(text), kind: kind, as: name)
        case .openvpn:
            let config = try OpenVPNConfig.parse(text)
            _ = try config.prepared(tunnel: name, managementSocket: "/dev/null", eventCommand: "true")
        }
        return try save(text, kind: kind, as: name)
    }

    /// Renames a tunnel together with its settings and saved passwords.
    public static func rename(_ name: String, to newName: String) throws -> SavedTunnel {
        guard TunnelName.isValid(newName) else {
            throw ClientError("Use letters, digits, “-”, “_” and “.” (up to 40 characters)")
        }
        guard find(newName) == nil else { throw ClientError("A tunnel named “\(newName)” already exists") }
        let (text, kind) = try load(name)
        let saved = try save(text, kind: kind, as: newName)
        if FileManager.default.fileExists(atPath: settingsURL(name).path) {
            try? FileManager.default.moveItem(at: settingsURL(name), to: settingsURL(newName))
        }
        if let creds = Keychain.credentials(for: name) {
            try? Keychain.saveCredentials(username: creds.username, password: creds.password, for: newName)
        }
        if let passphrase = Keychain.passphrase(for: name) { try? Keychain.savePassphrase(passphrase, for: newName) }
        if let old = list().first(where: { $0.name == name }) { try? FileManager.default.removeItem(at: old.url) }
        Keychain.deleteAll(for: name)
        return saved
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
