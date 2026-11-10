import Foundation

/// Messages exchanged between Bridge clients (app, CLI) and `bridge-helper`.
///
/// Framing: one JSON object per line over the helper's Unix socket.
public enum HelperProtocol {
    public static let socketPath = "/var/run/bridge/helper.sock"
    public static let launchdLabel = "com.rtmo0.bridge.helper"
    public static let installDirectory = "/Library/PrivilegedHelperTools/com.rtmo0.bridge.helper"
    /// Bump when the request/response format or helper behaviour changes,
    /// so the app knows to reinstall the helper.
    public static let version = 3
}

/// Secrets supplied by the client for a single connection attempt.
public struct TunnelSecrets: Codable, Sendable, Equatable {
    public var username: String?
    public var password: String?
    public var keyPassphrase: String?
    /// Response to an OpenVPN static challenge (e.g. an OTP code).
    public var challengeResponse: String?

    public init(username: String? = nil, password: String? = nil, keyPassphrase: String? = nil,
                challengeResponse: String? = nil) {
        self.username = username
        self.password = password
        self.keyPassphrase = keyPassphrase
        self.challengeResponse = challengeResponse
    }
}

public struct HelperRequest: Codable, Sendable {
    public enum Command: String, Codable, Sendable {
        case up, down, downAll, status, ping
        /// Sent by OpenVPN's route-up/down hook (runs as root) back to the helper.
        case openvpnEvent
    }

    public var command: Command
    public var name: String?
    public var config: String?
    public var secrets: TunnelSecrets?
    public var settings: TunnelSettings?
    public var event: String?
    public var environment: [String: String]?

    public init(command: Command, name: String? = nil, config: String? = nil, secrets: TunnelSecrets? = nil,
                settings: TunnelSettings? = nil, event: String? = nil, environment: [String: String]? = nil) {
        self.command = command
        self.name = name
        self.config = config
        self.secrets = secrets
        self.settings = settings
        self.event = event
        self.environment = environment
    }
}

/// Machine-readable failure reasons the client can react to.
public enum HelperErrorCode: String, Codable, Sendable {
    case credentialsRequired, authenticationFailed, keyPassphraseRequired, keyPassphraseFailed
    case challengeRequired, alreadyConnected, notConnected, invalidConfig, unsupported
}

public struct TunnelStatus: Codable, Sendable {
    public struct Peer: Codable, Sendable {
        public var publicKey: String
        public var endpoint: String?
        public var lastHandshake: Date?
        public var rxBytes: UInt64
        public var txBytes: UInt64

        public init(publicKey: String, endpoint: String?, lastHandshake: Date?, rxBytes: UInt64, txBytes: UInt64) {
            self.publicKey = publicKey
            self.endpoint = endpoint
            self.lastHandshake = lastHandshake
            self.rxBytes = rxBytes
            self.txBytes = txBytes
        }
    }

    public var name: String
    public var kind: TunnelKind
    public var interface: String
    public var pid: Int32
    public var startedAt: Date
    /// True when traffic can flow (recent handshake / OpenVPN CONNECTED).
    public var connected: Bool
    /// Human-readable state, e.g. "Connected", "Waiting for handshake", "Reconnecting".
    public var state: String
    public var server: String?
    public var addresses: [String]
    public var dnsServers: [String]
    public var fullTunnel: Bool
    public var lastHandshake: Date?
    public var rxBytes: UInt64
    public var txBytes: UInt64
    public var peers: [Peer]
    public var warnings: [String]

    public init(name: String, kind: TunnelKind, interface: String, pid: Int32, startedAt: Date, connected: Bool,
                state: String, server: String?, addresses: [String], dnsServers: [String], fullTunnel: Bool,
                lastHandshake: Date?, rxBytes: UInt64, txBytes: UInt64, peers: [Peer], warnings: [String]) {
        self.name = name
        self.kind = kind
        self.interface = interface
        self.pid = pid
        self.startedAt = startedAt
        self.connected = connected
        self.state = state
        self.server = server
        self.addresses = addresses
        self.dnsServers = dnsServers
        self.fullTunnel = fullTunnel
        self.lastHandshake = lastHandshake
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.peers = peers
        self.warnings = warnings
    }
}

public struct HelperResponse: Codable, Sendable {
    public var ok: Bool
    public var error: String?
    public var errorCode: HelperErrorCode?
    /// Extra data for some errors, e.g. the static challenge text.
    public var errorDetail: String?
    public var tunnels: [TunnelStatus]?
    public var helperVersion: Int?
    /// Version of the app that installed the helper (from its `version` file).
    public var helperBuild: String?
    public var capabilities: [TunnelKind]?

    public init(ok: Bool, error: String? = nil, errorCode: HelperErrorCode? = nil, errorDetail: String? = nil,
                tunnels: [TunnelStatus]? = nil, capabilities: [TunnelKind]? = nil) {
        self.ok = ok
        self.error = error
        self.errorCode = errorCode
        self.errorDetail = errorDetail
        self.tunnels = tunnels
        self.helperVersion = HelperProtocol.version
        self.capabilities = capabilities
    }

    public static func failure(_ message: String, code: HelperErrorCode? = nil, detail: String? = nil) -> HelperResponse {
        HelperResponse(ok: false, error: message, errorCode: code, errorDetail: detail)
    }
}

public enum TunnelName {
    /// Tunnel names are used in file names and log paths, so keep them simple.
    public static func isValid(_ name: String) -> Bool {
        guard (1...40).contains(name.count), !name.hasPrefix(".") else { return false }
        return name.unicodeScalars.allSatisfy {
            ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || "-_.".unicodeScalars.contains($0)
        }
    }

    /// Turns a file name like "My Server (NL).ovpn" into "My-Server-NL".
    public static func sanitized(_ raw: String) -> String {
        var out = ""
        for scalar in raw.unicodeScalars {
            if scalar.isASCII && (CharacterSet.alphanumerics.contains(scalar) || "-_.".unicodeScalars.contains(scalar)) {
                out.unicodeScalars.append(scalar)
            } else if !out.hasSuffix("-") {
                out.append("-")
            }
        }
        out = out.trimmingCharacters(in: CharacterSet(charactersIn: "-."))
        if out.isEmpty { out = "tunnel" }
        return String(out.prefix(40))
    }
}

public extension JSONEncoder {
    static var bridge: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }
}

public extension JSONDecoder {
    static var bridge: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}
