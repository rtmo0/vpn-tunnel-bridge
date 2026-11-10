import Foundation

/// A parsed WireGuard / AmneziaWG configuration in wg-quick format.
///
/// Unlike clients that keep a fixed allow-list and silently drop the rest,
/// every key in the file is either applied or rejected with a clear error.
public struct TunnelConfig: Equatable, Sendable {
    public struct Peer: Equatable, Sendable {
        public var publicKey: String
        public var presharedKey: String?
        public var endpoint: Endpoint?
        public var allowedIPs: [IPNetwork] = []
        public var persistentKeepalive: String?
    }

    /// A device-level parameter that is passed to the backend over UAPI.
    public struct DeviceParameter: Equatable, Sendable {
        /// Canonical name as written in .conf files, e.g. `HeaderProtectionKey`.
        public let name: String
        /// Name of the UAPI key, e.g. `header_protection_key`.
        public let uapiKey: String
        /// Value as written in the config (secrets stay base64 here).
        public let value: String
        public let isSecret: Bool
    }

    public var privateKey: String
    public var addresses: [IPNetwork] = []
    public var dnsServers: [IPAddress] = []
    public var dnsSearchDomains: [String] = []
    /// Tunnel DNS answers only `dnsSearchDomains` (split DNS); set by TunnelSettings.
    public var dnsOnlyForDomains = false
    public var mtu: Int?
    public var deviceParameters: [DeviceParameter] = []
    public var peers: [Peer] = []
    /// Non-fatal notes, e.g. keys that are accepted but intentionally ignored.
    public var warnings: [String] = []

    /// True when any AmneziaWG obfuscation parameter is present.
    public var usesAmneziaObfuscation: Bool {
        deviceParameters.contains { DeviceKeys.amneziaKeys.contains($0.name) }
    }

    /// True when some peer routes all IPv4 or IPv6 traffic.
    public var isFullTunnel: Bool {
        peers.contains { $0.allowedIPs.contains { $0.isDefaultRoute } }
    }

    public func parameter(_ name: String) -> DeviceParameter? {
        deviceParameters.first { $0.name.lowercased() == name.lowercased() }
    }
}

public struct Endpoint: Equatable, Sendable, CustomStringConvertible {
    public var host: String
    public var port: UInt16

    public init?(_ string: String) {
        let s = string.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            guard rest.hasPrefix(":"), let port = UInt16(rest.dropFirst()), !host.isEmpty else { return nil }
            self.host = host
            self.port = port
        } else {
            guard let colon = s.lastIndex(of: ":") else { return nil }
            let host = String(s[..<colon])
            guard let port = UInt16(s[s.index(after: colon)...]), !host.isEmpty, !host.contains(":") else {
                return nil
            }
            self.host = host
            self.port = port
        }
    }

    public var description: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

public struct ConfigError: Error, Equatable, CustomStringConvertible {
    public let message: String
    public let line: Int?

    public init(_ message: String, line: Int? = nil) {
        self.message = message
        self.line = line
    }

    public var description: String {
        if let line { return "Line \(line): \(message)" }
        return message
    }
}

/// Mapping of every [Interface] key the AmneziaWG backend understands.
enum DeviceKeys {
    enum Kind { case number, range, text, key, bool, fwmark }

    struct Spec {
        let name: String
        let uapiKey: String
        let kind: Kind
    }

    static let all: [Spec] = [
        Spec(name: "ListenPort", uapiKey: "listen_port", kind: .number),
        Spec(name: "FwMark", uapiKey: "fwmark", kind: .fwmark),
        Spec(name: "Jc", uapiKey: "jc", kind: .number),
        Spec(name: "Jmin", uapiKey: "jmin", kind: .number),
        Spec(name: "Jmax", uapiKey: "jmax", kind: .number),
        Spec(name: "S1", uapiKey: "s1", kind: .number),
        Spec(name: "S2", uapiKey: "s2", kind: .number),
        Spec(name: "S3", uapiKey: "s3", kind: .number),
        Spec(name: "S4", uapiKey: "s4", kind: .number),
        Spec(name: "H1", uapiKey: "h1", kind: .range),
        Spec(name: "H2", uapiKey: "h2", kind: .range),
        Spec(name: "H3", uapiKey: "h3", kind: .range),
        Spec(name: "H4", uapiKey: "h4", kind: .range),
        Spec(name: "I1", uapiKey: "i1", kind: .text),
        Spec(name: "I2", uapiKey: "i2", kind: .text),
        Spec(name: "I3", uapiKey: "i3", kind: .text),
        Spec(name: "I4", uapiKey: "i4", kind: .text),
        Spec(name: "I5", uapiKey: "i5", kind: .text),
        Spec(name: "HeaderProtectionKey", uapiKey: "header_protection_key", kind: .key),
        Spec(name: "ContentPaddingAddition", uapiKey: "content_padding_addition", kind: .range),
        Spec(name: "RekeyAfterTime", uapiKey: "rekey_after_time", kind: .range),
        Spec(name: "RekeyTimeout", uapiKey: "rekey_timeout", kind: .range),
        Spec(name: "RejectAfterTime", uapiKey: "reject_after_time", kind: .range),
        Spec(name: "KeepaliveTimeout", uapiKey: "keepalive_timeout", kind: .range),
        Spec(name: "MaxHandshakeAttempts", uapiKey: "max_handshake_attempts", kind: .range),
        Spec(name: "RandomTrailers", uapiKey: "random_trailers", kind: .bool),
        Spec(name: "DisableCookies", uapiKey: "disable_cookies", kind: .bool),
    ]

    static let byLowercasedName: [String: Spec] =
        Dictionary(uniqueKeysWithValues: all.map { ($0.name.lowercased(), $0) })

    static let amneziaKeys: Set<String> = [
        "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
        "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
    ]
}

extension TunnelConfig {
    /// wg-quick keys that Bridge accepts but does not act on.
    private static let ignoredInterfaceKeys: [String: String] = [
        "table": "Table is ignored: Bridge manages routes itself.",
        "preup": "PreUp is ignored: Bridge never runs scripts from config files.",
        "postup": "PostUp is ignored: Bridge never runs scripts from config files.",
        "predown": "PreDown is ignored: Bridge never runs scripts from config files.",
        "postdown": "PostDown is ignored: Bridge never runs scripts from config files.",
        "saveconfig": "SaveConfig is ignored.",
    ]

    public static func parse(_ text: String) throws -> TunnelConfig {
        enum Section { case none, interface, peer }

        var section = Section.none
        var sawInterface = false
        var privateKey: String?
        var config = TunnelConfig(privateKey: "")
        var currentPeer: Peer?
        var seenDeviceKeys = Set<String>()

        func finishPeer(line: Int) throws {
            guard let peer = currentPeer else { return }
            guard !peer.publicKey.isEmpty else { throw ConfigError("[Peer] has no PublicKey", line: line) }
            config.peers.append(peer)
            currentPeer = nil
        }

        let lines = text.components(separatedBy: .newlines)
        for (index, rawLine) in lines.enumerated() {
            let lineNumber = index + 1
            var line = rawLine
            if let hash = line.firstIndex(of: "#") { line = String(line[..<hash]) }
            line = line.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }

            if line.hasPrefix("[") {
                let name = line.lowercased()
                switch name {
                case "[interface]":
                    try finishPeer(line: lineNumber)
                    if sawInterface { throw ConfigError("Duplicate [Interface] section", line: lineNumber) }
                    sawInterface = true
                    section = .interface
                case "[peer]":
                    try finishPeer(line: lineNumber)
                    currentPeer = Peer(publicKey: "")
                    section = .peer
                default:
                    throw ConfigError("Unknown section \(line)", line: lineNumber)
                }
                continue
            }

            guard let eq = line.firstIndex(of: "=") else {
                throw ConfigError("Expected 'Key = Value'", line: lineNumber)
            }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            let lower = key.lowercased()

            switch section {
            case .none:
                throw ConfigError("'\(key)' appears before any section", line: lineNumber)

            case .interface:
                switch lower {
                case "privatekey":
                    guard WireGuardKey.decode(base64: value) != nil else {
                        throw ConfigError("PrivateKey is not a valid 32-byte base64 key", line: lineNumber)
                    }
                    privateKey = value
                case "address":
                    for item in splitList(value) {
                        guard let net = IPNetwork(item) else {
                            throw ConfigError("Invalid Address '\(item)'", line: lineNumber)
                        }
                        config.addresses.append(net)
                    }
                case "dns":
                    for item in splitList(value) {
                        if let ip = IPAddress(item) {
                            config.dnsServers.append(ip)
                        } else {
                            config.dnsSearchDomains.append(item)
                        }
                    }
                case "mtu":
                    guard let mtu = Int(value), (576...65535).contains(mtu) else {
                        throw ConfigError("Invalid MTU '\(value)'", line: lineNumber)
                    }
                    config.mtu = mtu
                default:
                    if let note = ignoredInterfaceKeys[lower] {
                        config.warnings.append(note)
                    } else if let spec = DeviceKeys.byLowercasedName[lower] {
                        guard !seenDeviceKeys.contains(spec.name) else {
                            throw ConfigError("Duplicate \(spec.name)", line: lineNumber)
                        }
                        seenDeviceKeys.insert(spec.name)
                        let normalized = try normalize(value, as: spec, line: lineNumber)
                        config.deviceParameters.append(DeviceParameter(
                            name: spec.name, uapiKey: spec.uapiKey, value: normalized,
                            isSecret: spec.kind == .key))
                    } else {
                        throw ConfigError(
                            "Unknown [Interface] key '\(key)'. The AmneziaWG backend does not support it; "
                                + "remove it or update Bridge.", line: lineNumber)
                    }
                }

            case .peer:
                switch lower {
                case "publickey":
                    guard WireGuardKey.decode(base64: value) != nil else {
                        throw ConfigError("PublicKey is not a valid 32-byte base64 key", line: lineNumber)
                    }
                    currentPeer?.publicKey = value
                case "presharedkey":
                    guard WireGuardKey.decode(base64: value) != nil else {
                        throw ConfigError("PresharedKey is not a valid 32-byte base64 key", line: lineNumber)
                    }
                    currentPeer?.presharedKey = value
                case "endpoint":
                    guard let endpoint = Endpoint(value) else {
                        throw ConfigError("Invalid Endpoint '\(value)'", line: lineNumber)
                    }
                    currentPeer?.endpoint = endpoint
                case "allowedips":
                    for item in splitList(value) {
                        guard let net = IPNetwork(item) else {
                            throw ConfigError("Invalid AllowedIPs entry '\(item)'", line: lineNumber)
                        }
                        currentPeer?.allowedIPs.append(net)
                    }
                case "persistentkeepalive":
                    let v = value.lowercased() == "off" ? "0" : value
                    guard isRange(v) else {
                        throw ConfigError("Invalid PersistentKeepalive '\(value)'", line: lineNumber)
                    }
                    currentPeer?.persistentKeepalive = v
                case "advancedsecurity":
                    config.warnings.append("AdvancedSecurity is ignored: the userspace backend has no such option.")
                default:
                    throw ConfigError("Unknown [Peer] key '\(key)'", line: lineNumber)
                }
            }
        }
        try finishPeer(line: lines.count)

        guard sawInterface else { throw ConfigError("Missing [Interface] section") }
        guard let privateKey else { throw ConfigError("Missing PrivateKey in [Interface]") }
        guard !config.peers.isEmpty else { throw ConfigError("No [Peer] section") }
        guard !config.addresses.isEmpty else { throw ConfigError("Missing Address in [Interface]") }
        let keys = config.peers.map(\.publicKey)
        guard Set(keys).count == keys.count else { throw ConfigError("Two peers have the same PublicKey") }
        config.privateKey = privateKey
        return config
    }

    private static func splitList(_ value: String) -> [String] {
        value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// `123` or `123-456`.
    private static func isRange(_ value: String) -> Bool {
        let parts = value.split(separator: "-", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count) else { return false }
        return parts.allSatisfy { !$0.isEmpty && UInt32($0) != nil }
    }

    private static func normalize(_ value: String, as spec: DeviceKeys.Spec, line: Int) throws -> String {
        func fail() -> ConfigError { ConfigError("Invalid \(spec.name) '\(value)'", line: line) }
        switch spec.kind {
        case .number:
            guard UInt32(value) != nil else { throw fail() }
            return value
        case .range:
            guard isRange(value) else { throw fail() }
            return value
        case .text:
            guard !value.isEmpty else { throw fail() }
            return value
        case .key:
            guard WireGuardKey.decode(base64: value) != nil else {
                throw ConfigError("\(spec.name) is not a valid 32-byte base64 key", line: line)
            }
            return value
        case .bool:
            switch value.lowercased() {
            case "true", "on", "yes", "1": return "true"
            case "false", "off", "no", "0": return "false"
            default: throw fail()
            }
        case .fwmark:
            if value.lowercased() == "off" { return "0" }
            if value.lowercased().hasPrefix("0x"), let n = UInt32(value.dropFirst(2), radix: 16) { return String(n) }
            guard UInt32(value) != nil else { throw fail() }
            return value
        }
    }
}
