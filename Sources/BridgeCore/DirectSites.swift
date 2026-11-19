import Foundation

/// Sites that go direct (through Wi-Fi or Ethernet) while a tunnel takes all traffic.
///
/// Routes know addresses, not names: the helper resolves each domain and routes its
/// addresses around the tunnel. It also points DNS for these domains at the physical
/// network's DNS server, so browsers and the helper get the same addresses, and so do
/// subdomains. Best effort: a site may use addresses its domain did not return (CDNs,
/// DNS over HTTPS in the browser), and another site sharing an address goes direct too.
public enum DirectSites {
    public static let maxDomains = 200
    /// Addresses routed per domain, so one huge answer cannot flood the routing table.
    public static let maxAddressesPerDomain = 32

    /// "https://www.Example.com/path", "*.example.com", "пример.рф." → the host name in
    /// lower case and punycode; nil if it is not a domain name.
    public static func normalize(_ raw: String) -> String? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let scheme = text.range(of: "://") { text = String(text[scheme.upperBound...]) }
        if let end = text.firstIndex(where: { "/?#".contains($0) }) { text = String(text[..<end]) }
        if let at = text.lastIndex(of: "@") { text = String(text[text.index(after: at)...]) }
        if let colon = text.lastIndex(of: ":"), text[text.index(after: colon)...].allSatisfy(\.isNumber) {
            text = String(text[..<colon])
        }
        if text.hasPrefix("*.") { text.removeFirst(2) }
        while text.hasSuffix(".") { text.removeLast() }
        guard !text.isEmpty, !text.contains(where: \.isWhitespace) else { return nil }
        if !text.allSatisfy(\.isASCII) {
            guard let host = URLComponents(string: "http://\(text)/")?.encodedHost else { return nil }
            text = host
        }
        text = text.lowercased()
        guard text.count <= 253, IPAddress(text) == nil else { return nil }
        let labels = text.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, !(labels.last!.allSatisfy(\.isNumber)) else { return nil }
        for label in labels {
            guard (1...63).contains(label.count), label.first != "-", label.last != "-",
                  label.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
            else { return nil }
        }
        return text
    }

    /// Normalizes a list, dropping repeats; throws a readable error for the first bad entry.
    public static func normalized(_ entries: [String]) throws -> [String] {
        var out: [String] = []
        for entry in entries {
            guard let domain = normalize(entry) else { throw ConfigError("“\(entry)” is not a domain name") }
            if !out.contains(domain) { out.append(domain) }
        }
        guard out.count <= maxDomains else { throw ConfigError("Use at most \(maxDomains) domains") }
        return out
    }

    /// Names the helper resolves for a domain: the domain and its `www.` host.
    public static func hostNames(for domain: String) -> [String] {
        domain.hasPrefix("www.") ? [domain] : [domain, "www.\(domain)"]
    }

    /// Addresses that must never be routed around the tunnel: they are local, special,
    /// or would let a domain's DNS answer pull arbitrary networks out of the tunnel.
    public static func isRoutable(_ ip: IPAddress) -> Bool {
        let blocked = [
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
            "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
            "::/8", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "2001:db8::/32",
        ].compactMap(IPNetwork.init)
        return !blocked.contains { $0.isIPv6 == ip.isIPv6 && $0.contains(ip) }
    }
}

/// How the helper is doing with one direct site (reported in the tunnel status).
public struct DirectSiteStatus: Codable, Equatable, Sendable {
    public var domain: String
    /// Addresses currently routed around the tunnel.
    public var addresses: Int
    /// The last lookup found no addresses (unknown name, or DNS not answering).
    public var unresolved: Bool
    /// IPv6 addresses that still go through the tunnel (the network has no IPv6).
    public var ipv6ThroughTunnel: Int

    public init(domain: String, addresses: Int, unresolved: Bool, ipv6ThroughTunnel: Int) {
        self.domain = domain
        self.addresses = addresses
        self.unresolved = unresolved
        self.ipv6ThroughTunnel = ipv6ThroughTunnel
    }
}
