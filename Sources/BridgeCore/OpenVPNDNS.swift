import Foundation

/// DNS settings of an OpenVPN connection, gathered by the helper itself.
///
/// OpenVPN's own DNS hook (`dns-updown`) is off: with privileges dropped it would
/// keep a root process around. The helper combines instead:
/// - `dns` options: the config's own and those the server pushes (read from the
///   PUSH_REPLY that the management interface logs);
/// - `dhcp-option DNS/DNS6/DOMAIN/…`, which OpenVPN passes to the route-up hook as
///   `foreign_option_N`.
/// `dns` options win, as they do in OpenVPN.
public struct OpenVPNDNS: Equatable, Sendable {
    public var servers: [String]
    public var domains: [String]
    /// The servers answer only for `domains` (`dns server N resolve-domains …`).
    public var splitDomainsOnly: Bool

    public init(servers: [String], domains: [String], splitDomainsOnly: Bool) {
        self.servers = servers
        self.domains = domains
        self.splitDomainsOnly = splitDomainsOnly
    }

    /// From `dns …` options (arguments after "dns"); nil if they name no server.
    public static func from(dnsOptions options: [[String]]) -> OpenVPNDNS? {
        // dns server <priority> address|resolve-domains|… ; dns search-domains …
        var byPriority: [Int: (addresses: [String], resolveDomains: [String])] = [:]
        var search: [String] = []
        for args in options {
            guard let kind = args.first?.lowercased() else { continue }
            if kind == "search-domains" {
                for domain in args.dropFirst() where !search.contains(domain) { search.append(domain) }
                continue
            }
            guard kind == "server", args.count >= 3, let priority = Int(args[1]) else { continue }
            var entry = byPriority[priority] ?? ([], [])
            switch args[2].lowercased() {
            case "address":
                for value in args.dropFirst(3) {
                    if let address = serverAddress(value), !entry.addresses.contains(address) {
                        entry.addresses.append(address)
                    }
                }
            case "resolve-domains":
                for domain in args.dropFirst(3) where !entry.resolveDomains.contains(domain) {
                    entry.resolveDomains.append(domain)
                }
            default:
                break  // dnssec, transport, sni: not something the system resolver can use
            }
            byPriority[priority] = entry
        }
        var servers: [String] = []
        var domains = search
        var splitOnly = false
        for priority in byPriority.keys.sorted() {
            let entry = byPriority[priority]!
            guard !entry.addresses.isEmpty else { continue }
            for address in entry.addresses where !servers.contains(address) { servers.append(address) }
            if !entry.resolveDomains.isEmpty {
                splitOnly = true
                for domain in entry.resolveDomains where !domains.contains(domain) { domains.append(domain) }
            }
        }
        guard !servers.isEmpty else { return nil }
        return OpenVPNDNS(servers: servers, domains: domains, splitDomainsOnly: splitOnly)
    }

    /// From the route-up hook's `foreign_option_N` (`dhcp-option …`); nil without servers.
    public static func from(foreignOptions env: [String: String]) -> OpenVPNDNS? {
        var servers: [String] = []
        var domains: [String] = []
        var index = 1
        while let option = env["foreign_option_\(index)"] {
            index += 1
            let parts = option.split(separator: " ").map(String.init)
            guard parts.count >= 3, parts[0] == "dhcp-option" else { continue }
            switch parts[1].uppercased() {
            case "DNS", "DNS6":
                if let address = serverAddress(parts[2]), !servers.contains(address) { servers.append(address) }
            case "DOMAIN", "DOMAIN-SEARCH", "ADAPTER-DOMAIN-SUFFIX":
                if !domains.contains(parts[2]) { domains.append(parts[2]) }
            default:
                break
            }
        }
        guard !servers.isEmpty else { return nil }
        return OpenVPNDNS(servers: servers, domains: domains, splitDomainsOnly: false)
    }

    /// The options of a PUSH_REPLY from a management log message such as
    /// `PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,dns server 0 address 10.0.0.1'`.
    /// Returns nil if the message is not a PUSH_REPLY.
    public static func pushedOptions(inLogMessage message: String) -> [[String]]? {
        guard let start = message.range(of: "PUSH_REPLY,") else { return nil }
        var body = message[start.upperBound...]
        if body.hasSuffix("'") { body = body.dropLast() }
        return body.split(separator: ",").compactMap { item in
            let tokens = (try? OpenVPNConfig.tokenize(String(item), line: 0)) ?? []
            return tokens.isEmpty ? nil : tokens
        }
    }

    /// Drops pushed options the config's `pull-filter`s ignore or reject, as OpenVPN does:
    /// the first filter whose text starts the option decides.
    public static func applying(pullFilters filters: [[String]], to options: [[String]]) -> [[String]] {
        let rules = filters.compactMap { args -> (accept: Bool, text: String)? in
            guard args.count >= 2 else { return nil }
            return (args[0].lowercased() == "accept", args[1])
        }
        return options.filter { option in
            let text = option.joined(separator: " ")
            return rules.first { text.hasPrefix($0.text) }?.accept ?? true
        }
    }

    /// "1.2.3.4", "1.2.3.4:53", "[fd00::1]:53", "fd00::1" → the address, or nil.
    static func serverAddress(_ value: String) -> String? {
        var host = value
        if host.hasPrefix("["), let close = host.firstIndex(of: "]") {
            host = String(host[host.index(after: host.startIndex)..<close])
        } else if host.filter({ $0 == ":" }).count == 1 {
            host = String(host.split(separator: ":")[0])
        }
        return IPAddress(host) != nil ? host : nil
    }
}
