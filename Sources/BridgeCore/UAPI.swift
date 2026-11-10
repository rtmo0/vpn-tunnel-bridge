import Foundation

/// Builds and parses messages of the WireGuard cross-platform UAPI protocol
/// (https://www.wireguard.com/xplatform/), as extended by AmneziaWG.
public enum UAPI {
    /// Builds a complete `set=1` transaction for `config`.
    ///
    /// - Parameter endpoints: resolved `ip:port` / `[ip]:port` per peer public key (base64).
    ///   Peers without an entry are configured without an endpoint.
    public static func setRequest(for config: TunnelConfig, endpoints: [String: String]) throws -> String {
        var lines = ["set=1"]

        guard let privateHex = WireGuardKey.hex(fromBase64: config.privateKey) else {
            throw ConfigError("PrivateKey is not a valid key")
        }
        lines.append("private_key=\(privateHex)")

        for parameter in config.deviceParameters {
            let value: String
            if parameter.isSecret {
                guard let hex = WireGuardKey.hex(fromBase64: parameter.value) else {
                    throw ConfigError("\(parameter.name) is not a valid key")
                }
                value = hex
            } else {
                value = parameter.value
            }
            guard !value.contains("\n") else { throw ConfigError("\(parameter.name) contains a line break") }
            lines.append("\(parameter.uapiKey)=\(value)")
        }

        lines.append("replace_peers=true")
        for peer in config.peers {
            guard let publicHex = WireGuardKey.hex(fromBase64: peer.publicKey) else {
                throw ConfigError("Peer PublicKey is not a valid key")
            }
            lines.append("public_key=\(publicHex)")
            if let psk = peer.presharedKey {
                guard let pskHex = WireGuardKey.hex(fromBase64: psk) else {
                    throw ConfigError("Peer PresharedKey is not a valid key")
                }
                lines.append("preshared_key=\(pskHex)")
            }
            if let endpoint = endpoints[peer.publicKey] {
                lines.append("endpoint=\(endpoint)")
            }
            if let keepalive = peer.persistentKeepalive {
                lines.append("persistent_keepalive_interval=\(keepalive)")
            }
            lines.append("replace_allowed_ips=true")
            for ip in peer.allowedIPs {
                lines.append("allowed_ip=\(ip.masked)")
            }
        }
        return lines.joined(separator: "\n") + "\n\n"
    }

    public static let getRequest = "get=1\n\n"

    public struct PeerStatus: Equatable, Sendable {
        public var publicKey: String  // base64
        public var endpoint: String?
        public var lastHandshake: Date?
        public var rxBytes: UInt64 = 0
        public var txBytes: UInt64 = 0
    }

    public struct DeviceStatus: Equatable, Sendable {
        public var listenPort: UInt16?
        public var peers: [PeerStatus] = []

        public init(listenPort: UInt16? = nil, peers: [PeerStatus] = []) {
            self.listenPort = listenPort
            self.peers = peers
        }
    }

    public struct ProtocolError: Error, CustomStringConvertible {
        public let errno: Int32
        public var description: String {
            "backend rejected the configuration (errno \(errno): \(String(cString: strerror(errno))))"
        }
    }

    /// Returns the `errno=` value of a UAPI response (0 when absent).
    public static func errno(in response: String) -> Int32 {
        for line in response.split(separator: "\n") where line.hasPrefix("errno=") {
            return Int32(line.dropFirst("errno=".count)) ?? -1
        }
        return 0
    }

    public static func parseGetResponse(_ response: String) throws -> DeviceStatus {
        let code = errno(in: response)
        if code != 0 { throw ProtocolError(errno: code) }

        var status = DeviceStatus()
        var peer: PeerStatus?
        var handshakeSec: Int64 = 0
        var handshakeNsec: Int64 = 0

        func flush() {
            guard var p = peer else { return }
            if handshakeSec > 0 || handshakeNsec > 0 {
                p.lastHandshake = Date(timeIntervalSince1970: Double(handshakeSec) + Double(handshakeNsec) / 1e9)
            }
            status.peers.append(p)
            peer = nil
            handshakeSec = 0
            handshakeNsec = 0
        }

        for line in response.split(separator: "\n") {
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq]
            let value = String(line[line.index(after: eq)...])
            switch key {
            case "public_key":
                flush()
                peer = PeerStatus(publicKey: WireGuardKey.base64(fromHex: value) ?? value)
            case "listen_port" where peer == nil:
                status.listenPort = UInt16(value)
            case "endpoint":
                peer?.endpoint = value
            case "last_handshake_time_sec":
                handshakeSec = Int64(value) ?? 0
            case "last_handshake_time_nsec":
                handshakeNsec = Int64(value) ?? 0
            case "rx_bytes":
                peer?.rxBytes = UInt64(value) ?? 0
            case "tx_bytes":
                peer?.txBytes = UInt64(value) ?? 0
            default:
                break
            }
        }
        flush()
        return status
    }
}
