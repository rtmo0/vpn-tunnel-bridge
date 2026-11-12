import Foundation

/// An OpenConnect profile (`.openconnect`): which server to log in to and how.
///
///     # Bridge OpenConnect profile
///     Protocol = anyconnect
///     Server = vpn.example.com/engineering
///     Username = alice
///     Group = Employees
///     ServerCert = pin-sha256:…
///
/// Sessions are created by logging in each time (passwords live in the
/// Keychain, one-time codes and SSO are asked for), so the file holds no secrets
/// except an optional client certificate. Unknown keys are rejected.
public struct OpenConnectConfig: Equatable, Sendable {
    public enum VPNProtocol: String, CaseIterable, Sendable {
        case anyconnect, fortinet, gp, nc, pulse, f5, array

        public var displayName: String {
            switch self {
            case .anyconnect: "Cisco AnyConnect / ocserv"
            case .fortinet: "Fortinet SSL VPN"
            case .gp: "Palo Alto GlobalProtect"
            case .nc: "Juniper Network Connect"
            case .pulse: "Pulse / Ivanti Connect Secure"
            case .f5: "F5 BIG-IP"
            case .array: "Array Networks"
            }
        }
    }

    public var vpnProtocol: VPNProtocol = .anyconnect
    /// `host`, `host:port`, `host/path` or a full `https://` URL.
    public var server: String
    public var username: String?
    /// Login group (AnyConnect "authgroup", GlobalProtect gateway…), picked automatically.
    public var group: String?
    /// `pin-sha256:…` of the server certificate, for servers with self-signed certificates.
    public var serverCert: String?
    public var userAgent: String?
    /// What the client reports itself as: linux, linux-64, win, mac-intel, android, apple-ios.
    public var reportedOS: String?
    /// Client certificate and key (PEM, or base64 PKCS#12 in `certificate`), embedded in the file.
    public var certificate: String?
    public var key: String?
    public var disableDTLS = false

    public init(vpnProtocol: VPNProtocol = .anyconnect, server: String) {
        self.vpnProtocol = vpnProtocol
        self.server = server
    }

    /// The URL handed to OpenConnect.
    public var url: String {
        server.lowercased().hasPrefix("https://") ? server : "https://\(server)"
    }

    /// The server's host name or IP, for name resolution and the kill switch.
    public var host: String {
        URL(string: url)?.host ?? server
    }

    static let reportedOSValues: Set<String> = ["linux", "linux-64", "win", "mac-intel", "android", "apple-ios"]

    // MARK: Parsing

    public static func looksLikeProfile(_ text: String) -> Bool {
        text.split(whereSeparator: \.isNewline).contains { line in
            let t = line.trimmingCharacters(in: .whitespaces).lowercased()
            return t.hasPrefix("server") && t.dropFirst(6).trimmingCharacters(in: .whitespaces).hasPrefix("=")
        } && !text.lowercased().contains("[interface]")
    }

    public static func parse(_ text: String) throws -> OpenConnectConfig {
        var values: [String: String] = [:]
        var block: (name: String, lines: [String])?
        func finishBlock() {
            if let current = block { values[current.name] = current.lines.joined(separator: "\n") + "\n" }
            block = nil
        }
        for (index, raw) in text.components(separatedBy: .newlines).enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if var current = block {
                // [Certificate] / [Key] hold PEM (base64 lines may end in "="), so they come
                // last in the file and run until the next section.
                if line.hasPrefix("[") {
                    finishBlock()
                } else {
                    if !line.isEmpty { current.lines.append(line) }
                    block = current
                    continue
                }
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                let name = line.dropFirst().dropLast().lowercased()
                guard name == "certificate" || name == "key" else {
                    throw ConfigError("Unknown section [\(name)]", line: index + 1)
                }
                guard values[String(name)] == nil else { throw ConfigError("[\(name)] appears twice", line: index + 1) }
                block = (String(name), [])
                continue
            }
            guard let eq = line.firstIndex(of: "=") else {
                throw ConfigError("Expected “Key = value”", line: index + 1)
            }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            guard values[key] == nil else { throw ConfigError("“\(key)” appears twice", line: index + 1) }
            values[key] = value
        }
        finishBlock()

        guard let server = values.removeValue(forKey: "server"), !server.isEmpty else {
            throw ConfigError("The profile has no “Server = …”")
        }
        var config = OpenConnectConfig(server: server)
        if let value = values.removeValue(forKey: "protocol") {
            guard let p = VPNProtocol(rawValue: value.lowercased()) else {
                throw ConfigError("Unknown protocol “\(value)” (use "
                    + VPNProtocol.allCases.map(\.rawValue).joined(separator: ", ") + ")")
            }
            config.vpnProtocol = p
        }
        func take(_ key: String) -> String? {
            guard let value = values.removeValue(forKey: key), !value.isEmpty else { return nil }
            return value
        }
        config.username = take("username")
        config.group = take("group")
        config.serverCert = take("servercert")
        config.userAgent = take("useragent")
        config.reportedOS = take("reportedos")
        config.certificate = take("certificate")
        config.key = take("key")
        if let value = take("nodtls") {
            guard let flag = ["true": true, "yes": true, "1": true, "false": false, "no": false, "0": false][value.lowercased()] else {
                throw ConfigError("“NoDTLS” must be true or false")
            }
            config.disableDTLS = flag
        }
        if let unknown = values.keys.sorted().first { throw ConfigError("Unknown key “\(unknown)”") }
        try config.validate()
        return config
    }

    func validate() throws {
        if server.contains("://") && !server.lowercased().hasPrefix("https://") {
            throw ConfigError("“\(server)” is not a server address (VPN servers use https://)")
        }
        guard let parsed = URL(string: url), parsed.scheme == "https", let host = parsed.host, !host.isEmpty else {
            throw ConfigError("“\(server)” is not a server address")
        }
        if let serverCert {
            let lower = serverCert.lowercased()
            guard lower.hasPrefix("pin-sha256:") || lower.hasPrefix("sha256:") || lower.hasPrefix("sha1:")
                    || serverCert.allSatisfy(\.isHexDigit) else {
                throw ConfigError("“ServerCert” must look like pin-sha256:…")
            }
        }
        if let reportedOS, !Self.reportedOSValues.contains(reportedOS) {
            throw ConfigError("“ReportedOS” must be one of " + Self.reportedOSValues.sorted().joined(separator: ", "))
        }
        if key != nil && certificate == nil { throw ConfigError("[Key] needs a [Certificate]") }
        for value in [username, group, userAgent, server].compactMap({ $0 }) where value.contains(where: \.isNewline) {
            throw ConfigError("Values must be on one line")
        }
    }

    public func render() -> String {
        var lines = ["# Bridge OpenConnect profile", "Protocol = \(vpnProtocol.rawValue)", "Server = \(server)"]
        if let username { lines.append("Username = \(username)") }
        if let group { lines.append("Group = \(group)") }
        if let serverCert { lines.append("ServerCert = \(serverCert)") }
        if let userAgent { lines.append("UserAgent = \(userAgent)") }
        if let reportedOS { lines.append("ReportedOS = \(reportedOS)") }
        if disableDTLS { lines.append("NoDTLS = true") }
        if let certificate { lines += ["", "[Certificate]", certificate.trimmingCharacters(in: .whitespacesAndNewlines)] }
        if let key { lines += ["", "[Key]", key.trimmingCharacters(in: .whitespacesAndNewlines)] }
        return lines.joined(separator: "\n") + "\n"
    }
}

/// What an OpenConnect server assigned, as OpenConnect passes it to its
/// `vpnc-script` (INTERNAL_IP4_*, CISCO_SPLIT_*, …), turned into Bridge routing.
public struct OpenConnectNetwork: Equatable, Sendable {
    public var interface: String
    public var gateway: String?
    public var ipv4: String?
    public var ipv4Network: IPNetwork?
    public var ipv6: IPNetwork?
    public var mtu: Int?
    public var dnsServers: [IPAddress] = []
    public var defaultDomain: String?
    public var splitDNS: [String] = []
    public var includes: [IPNetwork] = []
    public var excludes: [IPNetwork] = []
    public var banner: String?

    public init?(environment env: [String: String]) {
        guard let interface = env["TUNDEV"], !interface.isEmpty,
              interface.allSatisfy({ $0.isLetter || $0.isNumber }) else { return nil }
        self.interface = interface
        gateway = env["VPNGATEWAY"].flatMap { IPAddress($0) != nil ? $0 : nil }
        ipv4 = env["INTERNAL_IP4_ADDRESS"].flatMap { IPAddress($0).map { "\($0)" } }
        if let net = env["INTERNAL_IP4_NETADDR"], let len = env["INTERNAL_IP4_NETMASKLEN"] {
            ipv4Network = IPNetwork("\(net)/\(len)")
        }
        if let v6 = env["INTERNAL_IP6_NETMASK"] ?? env["INTERNAL_IP6_ADDRESS"] {
            ipv6 = IPNetwork(v6.contains("/") ? v6 : "\(v6)/128")
        }
        mtu = env["INTERNAL_IP4_MTU"].flatMap(Int.init)
        dnsServers = (env["INTERNAL_IP4_DNS"] ?? "").split(separator: " ").compactMap { IPAddress(String($0)) }
            + (env["INTERNAL_IP6_DNS"] ?? "").split(separator: " ").compactMap { IPAddress(String($0)) }
        defaultDomain = env["CISCO_DEF_DOMAIN"].flatMap { $0.isEmpty ? nil : $0.split(separator: " ").first.map(String.init) }
        splitDNS = (env["CISCO_SPLIT_DNS"] ?? "").split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
        banner = env["CISCO_BANNER"]

        func list(_ prefix: String, v6: Bool) -> [IPNetwork] {
            let count = Int(env[prefix] ?? "") ?? 0
            return (0..<min(count, 4096)).compactMap { i in
                guard let addr = env["\(prefix)_\(i)_ADDR"] else { return nil }
                let len = env["\(prefix)_\(i)_MASKLEN"] ?? (v6 ? "128" : "32")
                return IPNetwork("\(addr)/\(len)")
            }
        }
        includes = list("CISCO_SPLIT_INC", v6: false) + list("CISCO_IPV6_SPLIT_INC", v6: true)
        excludes = list("CISCO_SPLIT_EXC", v6: false) + list("CISCO_IPV6_SPLIT_EXC", v6: true)
    }

    /// Routes and DNS after Bridge settings are applied.
    public struct Plan: Equatable, Sendable {
        public var networks: [IPNetwork]
        public var bypass: [IPNetwork]
        public var dnsServers: [IPAddress]
        public var searchDomains: [String]
        public var dnsOnlyForDomains: Bool

        public var isFullTunnel: Bool { networks.contains { $0.isDefaultRoute && !$0.isIPv6 } }
    }

    public func plan(_ settings: TunnelSettings) throws -> Plan {
        // No split-include list means the server wants all traffic.
        var allowed = includes.filter { !$0.isIPv6 }
        if allowed.isEmpty { allowed = [IPNetwork("0.0.0.0/0")!] }
        if ipv6 != nil {
            let v6 = includes.filter(\.isIPv6)
            allowed += v6.isEmpty ? [IPNetwork("::/0")!] : v6
        }
        var carrier = TunnelConfig(privateKey: "", addresses: [], dnsServers: dnsServers,
                                   peers: [TunnelConfig.Peer(publicKey: "openconnect", endpoint: nil, allowedIPs: allowed)])
        if !splitDNS.isEmpty {
            carrier.dnsSearchDomains = splitDNS
            carrier.dnsOnlyForDomains = true
        } else if let defaultDomain {
            carrier.dnsSearchDomains = [defaultDomain]
        }
        let (config, bypass) = try carrier.applying(settings)
        // The server's own exclusions still apply unless the user chose the routes.
        let serverExcludes = settings.routing == .config || settings.routing == .allTraffic ? excludes : []
        return Plan(networks: config.peers[0].allowedIPs, bypass: bypass + serverExcludes,
                    dnsServers: config.dnsServers, searchDomains: config.dnsSearchDomains,
                    dnsOnlyForDomains: config.dnsOnlyForDomains)
    }
}
