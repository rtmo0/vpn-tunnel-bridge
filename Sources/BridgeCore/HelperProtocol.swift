import Foundation

/// Messages exchanged between the `bridge` client and `bridge-helper`.
///
/// Framing: one JSON object per line over the helper's Unix socket.
public enum HelperProtocol {
    public static let socketPath = "/var/run/bridge/helper.sock"
    public static let launchdLabel = "com.rtmo0.bridge.helper"
    public static let version = 1
}

public struct HelperRequest: Codable, Sendable {
    public enum Command: String, Codable, Sendable {
        case up, down, downAll, status, ping
    }

    public var command: Command
    public var name: String?
    public var config: String?

    public init(command: Command, name: String? = nil, config: String? = nil) {
        self.command = command
        self.name = name
        self.config = config
    }
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
    public var interface: String
    public var pid: Int32
    public var startedAt: Date
    public var addresses: [String]
    public var dnsServers: [String]
    public var fullTunnel: Bool
    public var amnezia: Bool
    public var peers: [Peer]
    public var warnings: [String]

    public init(name: String, interface: String, pid: Int32, startedAt: Date, addresses: [String],
                dnsServers: [String], fullTunnel: Bool, amnezia: Bool, peers: [Peer], warnings: [String]) {
        self.name = name
        self.interface = interface
        self.pid = pid
        self.startedAt = startedAt
        self.addresses = addresses
        self.dnsServers = dnsServers
        self.fullTunnel = fullTunnel
        self.amnezia = amnezia
        self.peers = peers
        self.warnings = warnings
    }

    public var lastHandshake: Date? { peers.compactMap(\.lastHandshake).max() }
    public var rxBytes: UInt64 { peers.reduce(0) { $0 + $1.rxBytes } }
    public var txBytes: UInt64 { peers.reduce(0) { $0 + $1.txBytes } }
}

public struct HelperResponse: Codable, Sendable {
    public var ok: Bool
    public var error: String?
    public var tunnels: [TunnelStatus]?
    public var helperVersion: Int?

    public init(ok: Bool, error: String? = nil, tunnels: [TunnelStatus]? = nil) {
        self.ok = ok
        self.error = error
        self.tunnels = tunnels
        self.helperVersion = HelperProtocol.version
    }

    public static func failure(_ message: String) -> HelperResponse { HelperResponse(ok: false, error: message) }
}

public enum TunnelName {
    /// Tunnel names are used in file names and log paths, so keep them simple.
    public static func isValid(_ name: String) -> Bool {
        guard (1...40).contains(name.count) else { return false }
        return name.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) && $0.isASCII || "-_.".unicodeScalars.contains($0)
        } && !name.hasPrefix(".")
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
