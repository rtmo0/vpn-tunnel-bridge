import Foundation

/// A rule-based routing profile in the format used by Happ and RoscomVPN
/// (`routing.json`, or a `happ://routing/add/<base64>` link): which sites and
/// networks go through the proxy, go direct or are blocked, and which DNS
/// servers resolve them.
///
/// It applies to tunnels that run through Xray (VLESS, Trojan, Hysteria 2).
/// Like the other parsers, unknown keys are rejected rather than ignored.
public struct RoutingProfile: Codable, Equatable, Sendable {
    public enum Action: String, Codable, Sendable { case block, proxy, direct }

    public struct DNSServer: Codable, Equatable, Sendable {
        /// `https://…/dns-query` for DNS over HTTPS, or a plain IP for DNS over UDP.
        public var address: String
        /// The server's IP: kept reachable, and used to resolve a DoH host name without a loop.
        public var ip: String
    }

    public var name: String
    /// Traffic no rule matches goes through the proxy (true) or direct (false).
    public var globalProxy: Bool
    public var remoteDNS: DNSServer
    public var domesticDNS: DNSServer
    public var geoipURL: String?
    public var geositeURL: String?
    public var hosts: [String: String] = [:]
    public var order: [Action] = [.block, .proxy, .direct]
    public var directSites: [String] = []
    public var directIPs: [String] = []
    public var proxySites: [String] = []
    public var proxyIPs: [String] = []
    public var blockSites: [String] = []
    public var blockIPs: [String] = []
    /// Xray `domainStrategy`: AsIs, IPIfNonMatch or IPOnDemand.
    public var domainStrategy = "IPIfNonMatch"
    public var lastUpdated: String?

    public var allRules: [String] { directSites + directIPs + proxySites + proxyIPs + blockSites + blockIPs }
    public var needsGeoIP: Bool { allRules.contains { $0.lowercased().hasPrefix("geoip:") } }
    public var needsGeoSite: Bool { allRules.contains { $0.lowercased().hasPrefix("geosite:") } }
    /// Some traffic leaves outside the tunnel (incompatible with the kill switch).
    public var sendsTrafficDirect: Bool { !globalProxy || !directSites.isEmpty || !directIPs.isEmpty }

    // MARK: Parsing

    static let knownKeys: Set<String> = [
        "Name", "GlobalProxy", "UseChunkFiles", "RemoteDns", "DomesticDns", "RemoteDNSType", "RemoteDNSDomain",
        "RemoteDNSIP", "DomesticDNSType", "DomesticDNSDomain", "DomesticDNSIP", "Geoipurl", "Geositeurl",
        "LastUpdated", "DnsHosts", "RouteOrder", "DirectSites", "DirectIp", "ProxySites", "ProxyIp", "BlockSites",
        "BlockIp", "DomainStrategy", "FakeDNS",
    ]

    /// Parses `routing.json` text or a `happ://routing/add/<base64>` (or `/onadd/`) link.
    public static func parse(_ text: String) throws -> RoutingProfile {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        var data = Data(trimmed.utf8)
        if trimmed.lowercased().hasPrefix("happ://routing/") {
            guard let encoded = trimmed.split(separator: "/").last.map(String.init),
                  let decoded = Data(base64URLEncoded: encoded.removingPercentEncoding ?? encoded) else {
                throw ConfigError("The happ://routing link does not contain a base64 profile")
            }
            data = decoded
        }
        guard let object = try? JSONSerialization.jsonObject(with: data), let json = object as? [String: Any] else {
            throw ConfigError("A routing profile must be a JSON object (like routing.json)")
        }
        if let unknown = json.keys.sorted().first(where: { !knownKeys.contains($0) }) {
            throw ConfigError("Unknown routing profile key “\(unknown)”")
        }

        func string(_ key: String) throws -> String? {
            switch json[key] {
            case nil, is NSNull: return nil
            case let s as String:
                let t = s.trimmingCharacters(in: .whitespaces)
                return t.isEmpty ? nil : t
            case let n as NSNumber: return n.stringValue
            default: throw ConfigError("“\(key)” must be text")
            }
        }
        func bool(_ key: String, default fallback: Bool) throws -> Bool {
            if let n = json[key] as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue }
            guard let s = try string(key)?.lowercased() else { return fallback }
            switch s {
            case "true", "1", "yes": return true
            case "false", "0", "no": return false
            default: throw ConfigError("“\(key)” must be true or false")
            }
        }
        func list(_ key: String) throws -> [String] {
            guard let value = json[key], !(value is NSNull) else { return [] }
            guard let items = value as? [Any] else { throw ConfigError("“\(key)” must be a list") }
            return try items.compactMap { item in
                guard let s = item as? String else { throw ConfigError("“\(key)” must be a list of text") }
                let t = s.trimmingCharacters(in: .whitespaces)
                return t.isEmpty ? nil : t
            }
        }
        func dns(_ prefix: String, legacy: String, fallback: String) throws -> DNSServer {
            let ip = try string("\(prefix)DNSIP") ?? string(legacy) ?? fallback
            guard IPAddress(ip) != nil else { throw ConfigError("“\(prefix)DNSIP” must be an IP address") }
            switch try string("\(prefix)DNSType")?.lowercased() ?? "dou" {
            case "doh":
                let url = try string("\(prefix)DNSDomain") ?? "https://\(ip)/dns-query"
                guard let parsed = URL(string: url), parsed.scheme?.lowercased() == "https", parsed.host != nil else {
                    throw ConfigError("“\(prefix)DNSDomain” must be an https:// DNS-over-HTTPS URL")
                }
                return DNSServer(address: url, ip: ip)
            case "dou", "udp":
                return DNSServer(address: ip, ip: ip)
            case let other:
                throw ConfigError("DNS type “\(other)” is not supported (DoH or DoU)")
            }
        }

        if try bool("FakeDNS", default: false) { throw ConfigError("FakeDNS is not supported") }

        var profile = RoutingProfile(
            name: try string("Name") ?? "Routing",
            globalProxy: try bool("GlobalProxy", default: true),
            remoteDNS: try dns("Remote", legacy: "RemoteDns", fallback: "1.1.1.1"),
            domesticDNS: try dns("Domestic", legacy: "DomesticDns", fallback: "77.88.8.8"))
        _ = try bool("UseChunkFiles", default: true)  // Happ's download format; nothing to do here.
        profile.geoipURL = try string("Geoipurl")
        profile.geositeURL = try string("Geositeurl")
        profile.lastUpdated = try string("LastUpdated")
        if let hosts = json["DnsHosts"] {
            guard let map = hosts as? [String: Any] else { throw ConfigError("“DnsHosts” must map names to addresses") }
            for (host, value) in map {
                guard let ip = value as? String, IPAddress(ip) != nil else {
                    throw ConfigError("“DnsHosts” entry \(host) must be an IP address")
                }
                profile.hosts[host] = ip
            }
        }
        if let order = try string("RouteOrder") {
            let actions = order.lowercased().split(separator: "-").map { Action(rawValue: String($0)) }
            guard actions.count == 3, Set(actions.compactMap { $0 }).count == 3 else {
                throw ConfigError("“RouteOrder” must list block, proxy and direct, e.g. block-proxy-direct")
            }
            profile.order = actions.compactMap { $0 }
        }
        profile.directSites = try list("DirectSites")
        profile.directIPs = try list("DirectIp")
        profile.proxySites = try list("ProxySites")
        profile.proxyIPs = try list("ProxyIp")
        profile.blockSites = try list("BlockSites")
        profile.blockIPs = try list("BlockIp")
        if let strategy = try string("DomainStrategy") {
            let allowed = ["AsIs", "IPIfNonMatch", "IPOnDemand"]
            guard let match = allowed.first(where: { $0.lowercased() == strategy.lowercased() }) else {
                throw ConfigError("“DomainStrategy” must be one of \(allowed.joined(separator: ", "))")
            }
            profile.domainStrategy = match
        }
        try profile.validate()
        return profile
    }

    func validate() throws {
        for (key, entries, isIP) in [("DirectSites", directSites, false), ("ProxySites", proxySites, false),
                                     ("BlockSites", blockSites, false), ("DirectIp", directIPs, true),
                                     ("ProxyIp", proxyIPs, true), ("BlockIp", blockIPs, true)] {
            for entry in entries {
                let lower = entry.lowercased()
                guard !lower.hasPrefix("ext:") else {
                    throw ConfigError("“\(entry)” in \(key): external rule files are not supported")
                }
                guard entry.allSatisfy({ !$0.isWhitespace && $0 != "\"" && $0 != "\\" }) || lower.hasPrefix("regexp:") else {
                    throw ConfigError("“\(entry)” in \(key) is not a valid rule")
                }
                if isIP, !lower.hasPrefix("geoip:"), IPNetwork(entry) == nil, IPAddress(entry) == nil {
                    throw ConfigError("“\(entry)” in \(key) is not an IP, network or geoip: rule")
                }
            }
        }
    }

    // MARK: Xray

    /// Adds DNS, outbounds and routing rules to an Xray configuration whose
    /// first outbound is the proxy (tag `proxy`).
    ///
    /// - Parameter directInterface: the physical interface direct traffic is bound
    ///   to (`IP_BOUND_IF`), so it can't loop back into the tunnel.
    func apply(to root: inout [String: Any], directInterface: String) {
        var outbounds = root["outbounds"] as? [[String: Any]] ?? []
        outbounds.append(["tag": "direct", "protocol": "freedom",
                          "streamSettings": ["sockopt": ["interface": directInterface, "domainStrategy": "UseIPv4"]]])
        outbounds.append(["tag": "block", "protocol": "blackhole"])
        // A and AAAA are answered by Xray's DNS; anything else is refused (REFUSED = 5).
        outbounds.append(["tag": "dns-out", "protocol": "dns", "settings": ["rules": [
            ["action": "hijack", "qType": "1,28"], ["action": "return", "rCode": 5],
        ]]])
        root["outbounds"] = outbounds

        // Learn domains from TLS/HTTP/QUIC so domain rules work; routing only, the proxy still gets the IP.
        if var inbounds = root["inbounds"] as? [[String: Any]], let index = inbounds.firstIndex(where: { $0["tag"] as? String == "tun" }) {
            inbounds[index]["sniffing"] = ["enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true]
            root["inbounds"] = inbounds
        }

        // DoH servers named by host: resolve them from the profile, never through the tunnel.
        var dnsHosts: [String: Any] = hosts
        for server in [remoteDNS, domesticDNS] {
            if let host = URL(string: server.address)?.host, IPAddress(host) == nil { dnsHosts[host] = server.ip }
        }
        let domesticDomains = directSites
        var servers: [Any] = []
        if !domesticDomains.isEmpty {
            servers.append(["address": domesticDNS.address, "domains": domesticDomains, "skipFallback": true])
        }
        servers.append(remoteDNS.address)
        root["dns"] = ["tag": "dns-internal", "hosts": dnsHosts, "servers": servers, "queryStrategy": "UseIPv4"]

        var rules: [[String: Any]] = [
            // Health checks must always test the proxy.
            ["inboundTag": ["probe4", "probe6"], "outboundTag": "proxy"],
            // The system resolver points into the tunnel; Xray answers.
            ["inboundTag": ["tun"], "port": "53", "outboundTag": "dns-out"],
            ["inboundTag": ["dns-internal"], "ip": [domesticDNS.ip], "outboundTag": "direct"],
            ["inboundTag": ["dns-internal"], "outboundTag": "proxy"],
        ]
        for action in order {
            let (sites, ips): ([String], [String])
            switch action {
            case .block: (sites, ips) = (blockSites, blockIPs)
            case .proxy: (sites, ips) = (proxySites, proxyIPs)
            case .direct: (sites, ips) = (directSites, directIPs)
            }
            // A rule with both domain and ip matches only when both do, so keep them apart.
            if !sites.isEmpty { rules.append(["domain": sites, "outboundTag": action.rawValue]) }
            if !ips.isEmpty { rules.append(["ip": ips, "outboundTag": action.rawValue]) }
        }
        rules.append(["network": "tcp,udp", "outboundTag": globalProxy ? "proxy" : "direct"])
        root["routing"] = ["domainStrategy": domainStrategy, "rules": rules]
    }
}
