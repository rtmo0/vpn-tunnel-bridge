import Foundation

/// A share link for a protocol Bridge runs through Xray-core: VLESS, Trojan or Hysteria 2.
///
/// Xray creates the utun and turns its packets into proxy connections; the
/// helper treats every such tunnel the same way, only the outbound differs.
public enum ProxyLink: Equatable, Sendable {
    case vless(VLESSConfig)
    case trojan(TrojanConfig)
    case hysteria2(Hysteria2Config)

    static let schemes: [String: TunnelKind] = [
        "vless": .vless, "trojan": .trojan, "hysteria2": .hysteria2, "hy2": .hysteria2,
    ]

    /// The protocol of a share link, or nil when `text` isn't one.
    public static func kind(of text: String) -> TunnelKind? {
        let trimmed = normalized(text)
        guard let end = trimmed.range(of: "://") else { return nil }
        return schemes[trimmed[..<end.lowerBound].lowercased()]
    }

    public static func isLink(_ text: String) -> Bool { kind(of: text) != nil }

    /// The link exactly as Bridge stores it: one line, no surrounding whitespace.
    public static func normalized(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func parse(_ text: String) throws -> ProxyLink {
        switch kind(of: text) {
        case .vless: return .vless(try VLESSConfig.parse(text))
        case .trojan: return .trojan(try TrojanConfig.parse(text))
        case .hysteria2: return .hysteria2(try Hysteria2Config.parse(text))
        default:
            throw ConfigError("Not a supported link (vless://, trojan://, hysteria2:// or hy2://)")
        }
    }

    public var kind: TunnelKind {
        switch self {
        case .vless: .vless
        case .trojan: .trojan
        case .hysteria2: .hysteria2
        }
    }

    public var host: String {
        switch self {
        case .vless(let c): c.host
        case .trojan(let c): c.host
        case .hysteria2(let c): c.host
        }
    }

    public var port: UInt16 {
        switch self {
        case .vless(let c): c.port
        case .trojan(let c): c.port
        case .hysteria2(let c): c.port
        }
    }

    public var endpoint: String { Endpoint.format(host: host, port: port) }

    public var remark: String? {
        switch self {
        case .vless(let c): c.remark
        case .trojan(let c): c.remark
        case .hysteria2(let c): c.remark
        }
    }

    /// Rows for the Manage window and `bridge check` (no secrets).
    public var summary: [(name: String, value: String)] {
        let rows: [(String, String)]
        switch self {
        case .vless(let c): rows = c.summary
        case .trojan(let c): rows = c.stream.summary
        case .hysteria2(let c): rows = c.summary
        }
        return rows.map { (name: $0.0, value: $0.1) }
    }

    // MARK: Routing

    /// DNS used when the user hasn't chosen servers: share links carry none.
    public static let defaultDNS = ["1.1.1.1", "1.0.0.1"]

    /// Applies routing and DNS overrides the same way as for WireGuard. Without
    /// overrides the tunnel takes all IPv4 and IPv6 traffic.
    public func routing(_ settings: TunnelSettings) throws -> ProxyRouting {
        let carrier = TunnelConfig(
            privateKey: "", addresses: [], dnsServers: Self.defaultDNS.compactMap(IPAddress.init),
            peers: [TunnelConfig.Peer(publicKey: "proxy", endpoint: Endpoint(endpoint),
                                      allowedIPs: [IPNetwork("0.0.0.0/0")!, IPNetwork("::/0")!])])
        let (config, bypass) = try carrier.applying(settings)
        return ProxyRouting(networks: config.peers[0].allowedIPs, bypass: bypass, dnsServers: config.dnsServers,
                            dnsSearchDomains: config.dnsSearchDomains, dnsOnlyForDomains: config.dnsOnlyForDomains)
    }

    // MARK: Xray configuration

    /// Reached through the tunnel to tell whether it works: any HTTP answer counts.
    /// (A TCP handshake alone proves nothing: the TUN stack accepts every connection.)
    public static let probeTargets = (ipv4: IPAddress("1.1.1.1")!, ipv6: IPAddress("2606:4700:4700::1111")!)
    public static let probePort: UInt16 = 80

    func xrayOutbound(address: String) -> [String: Any] {
        switch self {
        case .vless(let c): c.xrayOutbound(address: address)
        case .trojan(let c): c.xrayOutbound(address: address)
        case .hysteria2(let c): c.xrayOutbound(address: address)
        }
    }

    /// Builds the Xray JSON configuration.
    ///
    /// - Parameters:
    ///   - address: the server IP Bridge resolved (Xray must not resolve it through the tunnel).
    ///   - interface: the `utunN` name Xray creates.
    ///   - gateway: point-to-point prefix of the utun, e.g. `198.18.0.1/30` (local side is the next address).
    ///   - probePorts: localhost ports forwarded through the tunnel to `probeTargets` (IPv4, IPv6),
    ///     for health checks and to find out whether the server reaches IPv6.
    ///   - profile: rule-based routing; `directInterface` is the uplink its direct traffic is bound to.
    public func xrayConfiguration(address: String, interface: String, gateway: String, mtu: Int,
                                  probePorts: (ipv4: UInt16, ipv6: UInt16), profile: RoutingProfile? = nil,
                                  directInterface: String? = nil) throws -> Data {
        func probe(_ tag: String, port: UInt16, target: IPAddress) -> [String: Any] {
            ["tag": tag, "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": Int(port),
             "settings": ["address": "\(target)", "port": Int(Self.probePort), "network": "tcp"]]
        }
        var outbound = xrayOutbound(address: address)
        outbound["tag"] = "proxy"
        var root: [String: Any] = [
            "log": ["loglevel": "warning", "access": "none", "dnsLog": false],
            "inbounds": [
                ["tag": "tun", "protocol": "tun", "port": 0,
                 "settings": ["name": interface, "mtu": mtu, "gateway": [gateway]]],
                probe("probe4", port: probePorts.ipv4, target: Self.probeTargets.ipv4),
                probe("probe6", port: probePorts.ipv6, target: Self.probeTargets.ipv6),
            ],
            "outbounds": [outbound],
        ]
        if let profile {
            guard let directInterface else { throw ConfigError("No network interface for direct traffic") }
            profile.apply(to: &root, directInterface: directInterface)
        }
        return try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys,
                                                                           .withoutEscapingSlashes])
    }
}

/// What the helper sets up around a proxy tunnel, after Bridge settings are applied.
public struct ProxyRouting: Equatable, Sendable {
    /// Networks sent into the tunnel. IPv6 ones are routed only once the
    /// server has proven it can reach IPv6.
    public var networks: [IPNetwork]
    /// Networks that keep using the physical uplink.
    public var bypass: [IPNetwork]
    public var dnsServers: [IPAddress]
    public var dnsSearchDomains: [String]
    public var dnsOnlyForDomains: Bool

    public var ipv4Networks: [IPNetwork] { networks.filter { !$0.isIPv6 } }
    public var ipv6Networks: [IPNetwork] { networks.filter(\.isIPv6) }
    public var isFullTunnel: Bool { networks.contains { $0.isDefaultRoute && !$0.isIPv6 } }
}
