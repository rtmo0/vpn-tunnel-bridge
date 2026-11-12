import Foundation

/// A VLESS server parsed from a share link (`vless://…`), as described in
/// XTLS/Xray-core discussion #716.
///
/// Like the other parsers, every query parameter is either applied or rejected:
/// a link is never connected with part of it silently ignored. Empty values
/// count as absent, because panels routinely emit `host=&path=`.
public struct VLESSConfig: Equatable, Sendable {
    public enum Security: String, Sendable { case none, tls, reality }
    public enum Transport: String, Sendable { case raw, ws, httpupgrade, grpc, xhttp }

    /// User ID: a UUID, or a 1–30 byte string that Xray maps to one.
    public var id: String
    public var host: String
    public var port: UInt16
    /// The `#name` part of the link.
    public var remark: String?
    public var encryption = "none"
    public var flow: String?
    public var security: Security = .none
    public var transport: Transport = .raw

    // TLS and REALITY
    public var serverName: String?
    public var fingerprint: String?
    public var alpn: [String] = []
    public var echConfigList: String?
    public var pinnedPeerCertSha256: String?
    public var verifyPeerCertByName: String?
    public var realityPassword: String?
    public var realityShortID: String?
    public var realityMldsa65Verify: String?
    public var realitySpiderX: String?

    // Transport
    public var path: String?
    public var hostHeader: String?
    public var serviceName: String?
    public var mode: String?
    public var authority: String?
    /// XHTTP `extra`: a JSON object passed to Xray as is.
    public var extra: String?

    public var endpoint: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    /// The link exactly as Bridge stores it: one line, no surrounding whitespace.
    public static func normalized(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func isLink(_ text: String) -> Bool {
        normalized(text).lowercased().hasPrefix("vless://")
    }

    // MARK: Parsing

    static let flows: Set<String> = ["xtls-rprx-vision", "xtls-rprx-vision-udp443"]
    static let grpcModes: Set<String> = ["gun", "multi"]
    static let xhttpModes: Set<String> = ["auto", "packet-up", "stream-up", "stream-one"]

    public static func parse(_ text: String) throws -> VLESSConfig {
        let link = normalized(text)
        guard !link.contains("\n") else {
            throw ConfigError("Expected one vless:// link; import several links as separate tunnels")
        }
        guard isLink(link) else { throw ConfigError("Not a vless:// link") }
        guard let url = URLComponents(string: link) else { throw ConfigError("The vless:// link is malformed") }

        guard let user = url.percentEncodedUser.flatMap({ $0.removingPercentEncoding }), !user.isEmpty else {
            throw ConfigError("The link has no user ID (vless://<uuid>@host:port)")
        }
        guard url.percentEncodedPassword == nil else {
            throw ConfigError("The user ID must not contain “:”")
        }
        guard UUID(uuidString: user) != nil || (1...30).contains(user.utf8.count) else {
            throw ConfigError("“\(user.prefix(8))…” is not a valid VLESS user ID")
        }
        guard var host = url.host, !host.isEmpty else { throw ConfigError("The link has no server address") }
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard let rawPort = url.port, (1...65535).contains(rawPort) else {
            throw ConfigError("The link has no server port (vless://<uuid>@\(host):<port>)")
        }
        guard url.path.isEmpty || url.path == "/" else {
            throw ConfigError("Unexpected path “\(url.path)” before “?” in the link")
        }

        var config = VLESSConfig(id: user, host: host, port: UInt16(rawPort))
        config.remark = url.fragment.flatMap { $0.isEmpty ? nil : $0 }

        // Collect parameters; duplicates are ambiguous.
        var params: [String: String] = [:]
        for item in url.queryItems ?? [] {
            guard params[item.name] == nil else { throw ConfigError("Parameter “\(item.name)” appears twice") }
            params[item.name] = item.value ?? ""
        }
        func take(_ name: String) -> String? {
            guard let value = params.removeValue(forKey: name) else { return nil }
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            return trimmed.isEmpty ? nil : trimmed
        }

        let type = take("type")?.lowercased() ?? "tcp"
        switch type {
        case "tcp", "raw": config.transport = .raw
        case "ws": config.transport = .ws
        case "httpupgrade": config.transport = .httpupgrade
        case "grpc": config.transport = .grpc
        case "xhttp", "splithttp": config.transport = .xhttp
        case "kcp", "http", "h2", "quic":
            throw ConfigError("Transport “\(type)” is not supported yet (raw, ws, httpupgrade, grpc and xhttp are)")
        default: throw ConfigError("Unknown transport “type=\(type)”")
        }

        if let encryption = take("encryption") {
            guard encryption.allSatisfy({ $0.isASCII && !$0.isWhitespace && $0 != "\"" && $0 != "\\" }) else {
                throw ConfigError("“encryption” contains invalid characters")
            }
            config.encryption = encryption
        }

        let security = take("security")?.lowercased() ?? "none"
        guard let parsedSecurity = Security(rawValue: security) else {
            throw ConfigError("Unknown “security=\(security)” (use none, tls or reality)")
        }
        config.security = parsedSecurity

        if let flow = take("flow")?.lowercased() {
            guard flows.contains(flow) else { throw ConfigError("Unknown flow “\(flow)”") }
            config.flow = flow
        }

        // Clients commonly add these with a harmless value.
        for name in ["allowInsecure", "insecure"] {
            if let value = take(name), !["0", "false"].contains(value.lowercased()) {
                throw ConfigError("“\(name)=\(value)” turns off certificate checks, which Bridge does not do. "
                    + "Pin the server certificate with “pcs=<sha256>” instead")
            }
        }
        if let value = take("packetEncoding"), value.lowercased() != "xudp" {
            throw ConfigError("“packetEncoding=\(value)” is not supported (only xudp)")
        }
        if let header = take("headerType"), header.lowercased() != "none" {
            throw ConfigError("“headerType=\(header)” (HTTP camouflage) is not supported yet")
        }

        config.serverName = take("sni")
        if let fp = take("fp")?.lowercased() {
            guard fp.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }) else {
                throw ConfigError("“fp=\(fp)” is not a TLS fingerprint name")
            }
            config.fingerprint = fp
        }
        if let alpn = take("alpn") {
            config.alpn = alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        config.echConfigList = take("ech")
        config.pinnedPeerCertSha256 = take("pcs")
        config.verifyPeerCertByName = take("vcn")
        config.realityPassword = take("pbk")
        config.realityShortID = take("sid")
        config.realityMldsa65Verify = take("pqv")
        config.realitySpiderX = take("spx")

        config.path = take("path")
        config.hostHeader = take("host")
        config.serviceName = take("serviceName")
        config.mode = take("mode")?.lowercased()
        config.authority = take("authority")
        config.extra = take("extra")

        if let unknown = params.keys.sorted().first {
            throw ConfigError("Unknown parameter “\(unknown)” in the link")
        }
        try config.validate()
        return config
    }

    func validate() throws {
        let tlsKeys: [(String, Any?)] = [("sni", serverName), ("fp", fingerprint), ("alpn", alpn.isEmpty ? nil : alpn),
                                         ("ech", echConfigList), ("pcs", pinnedPeerCertSha256),
                                         ("vcn", verifyPeerCertByName)]
        let realityKeys: [(String, Any?)] = [("pbk", realityPassword), ("sid", realityShortID),
                                             ("pqv", realityMldsa65Verify), ("spx", realitySpiderX)]
        switch security {
        case .none:
            if let key = (tlsKeys + realityKeys).first(where: { $0.1 != nil })?.0 {
                throw ConfigError("“\(key)” needs security=tls or security=reality")
            }
        case .tls:
            if let key = realityKeys.first(where: { $0.1 != nil })?.0 {
                throw ConfigError("“\(key)” is a REALITY setting, but the link uses security=tls")
            }
            if let pcs = pinnedPeerCertSha256 {
                for hash in pcs.split(separator: ",") {
                    let hex = hash.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: ":", with: "")
                    guard hex.count == 64, hex.allSatisfy(\.isHexDigit) else {
                        throw ConfigError("“pcs” must be SHA-256 hashes in hex")
                    }
                }
            }
        case .reality:
            guard let password = realityPassword else { throw ConfigError("REALITY needs the server key “pbk”") }
            guard Data(base64URLEncoded: password)?.count == 32 else {
                throw ConfigError("“pbk” is not a REALITY public key")
            }
            if let sid = realityShortID, sid.count > 16 || !sid.allSatisfy(\.isHexDigit) {
                throw ConfigError("“sid” must be up to 16 hex digits")
            }
            for key in ["alpn", "ech", "pcs", "vcn"] where tlsKeys.contains(where: { $0.0 == key && $0.1 != nil }) {
                throw ConfigError("“\(key)” is a TLS setting, but the link uses security=reality")
            }
        }

        if let flow {
            guard transport == .raw, security != .none else {
                throw ConfigError("flow=\(flow) works only with type=tcp and security=tls or reality")
            }
        }

        func onlyFor(_ name: String, _ value: String?, _ allowed: Set<Transport>) throws {
            guard value != nil, !allowed.contains(transport) else { return }
            throw ConfigError("“\(name)” is not used by type=\(transport.rawValue)")
        }
        try onlyFor("path", path, [.ws, .httpupgrade, .xhttp])
        try onlyFor("host", hostHeader, [.ws, .httpupgrade, .xhttp])
        try onlyFor("serviceName", serviceName, [.grpc])
        try onlyFor("authority", authority, [.grpc])
        try onlyFor("mode", mode, [.grpc, .xhttp])
        try onlyFor("extra", extra, [.xhttp])

        if let path, !path.hasPrefix("/") { throw ConfigError("“path” must start with “/”") }
        if let mode {
            let allowed = transport == .grpc ? Self.grpcModes : Self.xhttpModes
            guard allowed.contains(mode) else {
                throw ConfigError("“mode=\(mode)” is not valid for \(transport.rawValue) "
                    + "(use \(allowed.sorted().joined(separator: ", ")))")
            }
        }
        if let extra {
            guard let data = extra.data(using: .utf8),
                  (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else {
                throw ConfigError("“extra” must be a JSON object")
            }
        }
    }

    // MARK: Routing

    /// What the helper sets up around the tunnel, after Bridge settings are applied.
    public struct Routing: Equatable, Sendable {
        /// Networks sent into the tunnel. IPv6 ones are routed only once the
        /// server has proven it can reach IPv6 (see `ipv6Networks`).
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

    /// DNS used when the user hasn't chosen servers: a share link carries none.
    public static let defaultDNS = ["1.1.1.1", "1.0.0.1"]

    /// Applies routing and DNS overrides the same way as for WireGuard. Without
    /// overrides the tunnel takes all IPv4 and IPv6 traffic.
    public func routing(_ settings: TunnelSettings) throws -> Routing {
        let carrier = TunnelConfig(
            privateKey: "", addresses: [], dnsServers: Self.defaultDNS.compactMap(IPAddress.init),
            peers: [TunnelConfig.Peer(publicKey: "vless", endpoint: Endpoint(endpoint),
                                      allowedIPs: [IPNetwork("0.0.0.0/0")!, IPNetwork("::/0")!])])
        let (config, bypass) = try carrier.applying(settings)
        return Routing(networks: config.peers[0].allowedIPs, bypass: bypass, dnsServers: config.dnsServers,
                       dnsSearchDomains: config.dnsSearchDomains, dnsOnlyForDomains: config.dnsOnlyForDomains)
    }

    // MARK: Xray configuration

    /// Host name sent as SNI / HTTP Host when the link doesn't set one: the
    /// server name, unless the server is given as an IP address.
    var defaultHostName: String? { IPAddress(host) == nil ? host : nil }

    /// Builds the Xray JSON configuration.
    ///
    /// - Parameters:
    ///   - address: the server IP Bridge resolved (Xray must not resolve it through the tunnel).
    ///   - interface: the `utunN` name Xray creates.
    ///   - gateway: point-to-point prefix of the utun, e.g. `198.18.0.1/30` (local side is the next address).
    ///   - probePorts: localhost ports forwarded through the tunnel to `probeTargets` (IPv4, IPv6),
    ///     for health checks and to find out whether the server reaches IPv6.
    public func xrayConfiguration(address: String, interface: String, gateway: String, mtu: Int,
                                  probePorts: (ipv4: UInt16, ipv6: UInt16)) throws -> Data {
        var user: [String: Any] = ["id": id, "encryption": encryption]
        if let flow { user["flow"] = flow }

        var stream: [String: Any] = ["network": transport.rawValue, "security": security.rawValue]
        switch security {
        case .none: break
        case .tls:
            var tls: [String: Any] = [:]
            if let name = serverName ?? defaultHostName { tls["serverName"] = name }
            if let fingerprint { tls["fingerprint"] = fingerprint }
            if !alpn.isEmpty { tls["alpn"] = alpn }
            if let echConfigList { tls["echConfigList"] = echConfigList }
            if let pinnedPeerCertSha256 { tls["pinnedPeerCertSha256"] = pinnedPeerCertSha256 }
            if let verifyPeerCertByName { tls["verifyPeerCertByName"] = verifyPeerCertByName }
            stream["tlsSettings"] = tls
        case .reality:
            var reality: [String: Any] = ["password": realityPassword ?? "", "fingerprint": fingerprint ?? "chrome"]
            if let name = serverName ?? defaultHostName { reality["serverName"] = name }
            if let realityShortID { reality["shortId"] = realityShortID }
            if let realityMldsa65Verify { reality["mldsa65Verify"] = realityMldsa65Verify }
            if let realitySpiderX { reality["spiderX"] = realitySpiderX }
            stream["realitySettings"] = reality
        }

        let httpHost = hostHeader ?? serverName ?? defaultHostName
        switch transport {
        case .raw: break
        case .ws, .httpupgrade:
            var settings: [String: Any] = ["path": path ?? "/"]
            if let httpHost { settings["host"] = httpHost }
            stream[transport == .ws ? "wsSettings" : "httpupgradeSettings"] = settings
        case .grpc:
            var settings: [String: Any] = ["serviceName": serviceName ?? "", "multiMode": mode == "multi"]
            if let authority { settings["authority"] = authority }
            stream["grpcSettings"] = settings
        case .xhttp:
            var settings: [String: Any] = ["path": path ?? "/", "mode": mode ?? "auto"]
            if let httpHost { settings["host"] = httpHost }
            if let extra, let data = extra.data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) {
                settings["extra"] = object
            }
            stream["xhttpSettings"] = settings
        }

        func probe(_ tag: String, port: UInt16, target: IPAddress) -> [String: Any] {
            ["tag": tag, "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": Int(port),
             "settings": ["address": "\(target)", "port": Int(Self.probePort), "network": "tcp"]]
        }
        let root: [String: Any] = [
            "log": ["loglevel": "warning", "access": "none", "dnsLog": false],
            "inbounds": [
                ["tag": "tun", "protocol": "tun", "port": 0,
                 "settings": ["name": interface, "mtu": mtu, "gateway": [gateway]]],
                probe("probe4", port: probePorts.ipv4, target: Self.probeTargets.ipv4),
                probe("probe6", port: probePorts.ipv6, target: Self.probeTargets.ipv6),
            ],
            "outbounds": [
                ["tag": "proxy", "protocol": "vless",
                 "settings": ["vnext": [["address": address, "port": Int(port), "users": [user]]]],
                 "streamSettings": stream],
            ],
        ]
        return try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys,
                                                                           .withoutEscapingSlashes])
    }

    /// Reached through the tunnel to tell whether it works: any HTTP answer counts.
    /// (A TCP handshake alone proves nothing: the TUN stack accepts every connection.)
    public static let probeTargets = (ipv4: IPAddress("1.1.1.1")!, ipv6: IPAddress("2606:4700:4700::1111")!)
    public static let probePort: UInt16 = 80
}

extension Data {
    /// Base64url without padding, as used by REALITY keys.
    init?(base64URLEncoded string: String) {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s.append("=") }
        self.init(base64Encoded: s)
    }
}
