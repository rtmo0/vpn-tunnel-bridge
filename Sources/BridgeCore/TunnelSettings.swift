import Foundation

/// Per-tunnel overrides chosen in the app, stored next to the config and
/// applied by the helper on top of it. The config file itself is never changed.
public struct TunnelSettings: Codable, Equatable, Sendable {
    public enum Routing: String, Codable, Sendable, CaseIterable {
        /// Use AllowedIPs / pushed routes from the configuration.
        case config
        /// Send all IPv4 and IPv6 traffic through the tunnel.
        case allTraffic
        /// Send only `networks` through the tunnel (split tunnelling).
        case onlyListed
        /// Send everything except `networks` through the tunnel.
        case allExceptListed
    }

    public enum DNSMode: String, Codable, Sendable, CaseIterable {
        /// DNS servers from the configuration (or pushed by an OpenVPN server).
        case config
        /// `dnsServers` below.
        case custom
        /// Leave the system DNS alone.
        case system
    }

    public var routing: Routing = .config
    /// CIDRs (or single addresses) for `.onlyListed` / `.allExceptListed`.
    public var networks: [String] = []
    /// Keep private ranges (10/8, 172.16/12, 192.168/16, link-local) off the tunnel.
    public var excludeLocalNetworks = false

    public var dnsMode: DNSMode = .config
    public var dnsServers: [String] = []
    /// When not empty, the tunnel's DNS answers only these domains (split DNS).
    public var splitDNSDomains: [String] = []

    public init() {}

    public var isDefault: Bool { self == TunnelSettings() }

    public static let localNetworks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]

    /// Throws a readable error for malformed entries.
    public func validate() throws {
        for item in networks where IPNetwork(item) == nil {
            throw ConfigError("“\(item)” is not a network (use e.g. 10.0.0.0/8 or 192.168.1.10)")
        }
        if (routing == .onlyListed || routing == .allExceptListed) && networks.isEmpty {
            throw ConfigError("Add at least one network for this routing mode")
        }
        if dnsMode == .custom {
            if dnsServers.isEmpty { throw ConfigError("Add at least one DNS server") }
            for item in dnsServers where IPAddress(item) == nil {
                throw ConfigError("“\(item)” is not an IP address")
            }
        }
        for domain in splitDNSDomains where domain.contains(" ") || domain.isEmpty {
            throw ConfigError("“\(domain)” is not a domain name")
        }
    }

    var parsedNetworks: [IPNetwork] { networks.compactMap(IPNetwork.init) }
}

extension TunnelConfig {
    /// Applies routing and DNS overrides.
    ///
    /// - Returns: the adjusted config and networks that must bypass the tunnel
    ///   (routed via the current uplink instead).
    public func applying(_ settings: TunnelSettings) throws -> (config: TunnelConfig, bypass: [IPNetwork]) {
        try settings.validate()
        var config = self
        var bypass: [IPNetwork] = []
        let everything = [IPNetwork("0.0.0.0/0")!, IPNetwork("::/0")!]

        if settings.routing != .config {
            guard config.peers.count == 1 else {
                throw ConfigError("Routing overrides work with single-peer configs; edit AllowedIPs instead")
            }
            switch settings.routing {
            case .config: break
            case .allTraffic: config.peers[0].allowedIPs = everything
            case .onlyListed: config.peers[0].allowedIPs = settings.parsedNetworks
            case .allExceptListed:
                config.peers[0].allowedIPs = everything
                bypass += settings.parsedNetworks
            }
        }
        if settings.excludeLocalNetworks && config.isFullTunnel {
            bypass += TunnelSettings.localNetworks.compactMap(IPNetwork.init)
        }

        switch settings.dnsMode {
        case .config: break
        case .custom: config.dnsServers = settings.dnsServers.compactMap(IPAddress.init)
        case .system:
            config.dnsServers = []
            config.dnsSearchDomains = []
        }
        if !settings.splitDNSDomains.isEmpty && !config.dnsServers.isEmpty {
            config.dnsSearchDomains = settings.splitDNSDomains
            config.dnsOnlyForDomains = true
        }
        return (config, bypass)
    }
}

extension OpenVPNConfig {
    /// Applies routing and DNS overrides as extra OpenVPN directives.
    public func applying(_ settings: TunnelSettings) throws -> OpenVPNConfig {
        try settings.validate()
        var out = self
        func add(_ name: String, _ args: String...) { out.directives.append(Directive(name: name, args: args)) }
        func netmask(_ prefix: Int) -> String {
            let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << UInt32(32 - prefix)
            return [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xFF) }.joined(separator: ".")
        }
        func route(_ net: IPNetwork, viaUplink: Bool) {
            let m = net.masked
            if m.isIPv6 {
                if !viaUplink { add("route-ipv6", m.description) }
            } else if viaUplink {
                add("route", "\(m.address)", netmask(m.prefix), "net_gateway")
            } else {
                add("route", "\(m.address)", netmask(m.prefix))
            }
        }

        switch settings.routing {
        case .config:
            break
        case .allTraffic:
            add("redirect-gateway", "def1", "ipv6")
        case .onlyListed:
            // Ignore the server's routes but keep everything else it pushes (DNS, addresses).
            add("pull-filter", "ignore", "redirect-gateway")
            add("pull-filter", "ignore", "route ")
            add("pull-filter", "ignore", "route-ipv6 ")
            for net in settings.parsedNetworks { route(net, viaUplink: false) }
        case .allExceptListed:
            add("redirect-gateway", "def1")
            for net in settings.parsedNetworks { route(net, viaUplink: true) }
        }
        if settings.excludeLocalNetworks {
            for net in TunnelSettings.localNetworks.compactMap(IPNetwork.init) { route(net, viaUplink: true) }
        }

        switch settings.dnsMode {
        case .config: break
        case .custom, .system:
            add("pull-filter", "ignore", "dhcp-option DNS")
            add("pull-filter", "ignore", "dns server")
            if settings.dnsMode == .custom {
                for server in settings.dnsServers { add("dhcp-option", "DNS", server) }
            }
        }
        if !settings.splitDNSDomains.isEmpty {
            for domain in settings.splitDNSDomains { add("dhcp-option", "DOMAIN", domain) }
            add("setenv", "BRIDGE_DNS_SPLIT", "1")
        }
        return out
    }
}
