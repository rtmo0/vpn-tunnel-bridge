import Foundation

/// Transport and TLS/REALITY settings shared by VLESS and Trojan links
/// (the parameters of XTLS/Xray-core discussion #716).
public struct ProxyStream: Equatable, Sendable {
    public enum Security: String, Sendable { case none, tls, reality }
    public enum Transport: String, Sendable { case raw, ws, httpupgrade, grpc, xhttp }

    public var security: Security
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

    static let grpcModes: Set<String> = ["gun", "multi"]
    static let xhttpModes: Set<String> = ["auto", "packet-up", "stream-up", "stream-one"]

    // MARK: Parsing

    /// Takes the stream parameters out of `link`; the caller rejects whatever is left.
    static func take(from link: inout ShareLink, defaultSecurity: Security) throws -> ProxyStream {
        let type = link.take("type")?.lowercased() ?? "tcp"
        let transport: Transport
        switch type {
        case "tcp", "raw": transport = .raw
        case "ws": transport = .ws
        case "httpupgrade": transport = .httpupgrade
        case "grpc": transport = .grpc
        case "xhttp", "splithttp": transport = .xhttp
        case "kcp", "http", "h2", "quic":
            throw ConfigError("Transport “\(type)” is not supported yet (raw, ws, httpupgrade, grpc and xhttp are)")
        default: throw ConfigError("Unknown transport “type=\(type)”")
        }

        let securityName = link.take("security")?.lowercased() ?? defaultSecurity.rawValue
        guard let security = Security(rawValue: securityName) else {
            throw ConfigError("Unknown “security=\(securityName)” (use none, tls or reality)")
        }
        var stream = ProxyStream(security: security, transport: transport)

        // Clients commonly add these with a harmless value.
        for name in ["allowInsecure", "insecure"] {
            if let value = link.take(name), !["0", "false"].contains(value.lowercased()) {
                throw ConfigError("“\(name)=\(value)” turns off certificate checks, which Bridge does not do. "
                    + "Pin the server certificate with “pcs=<sha256>” instead")
            }
        }
        if let header = link.take("headerType"), header.lowercased() != "none" {
            throw ConfigError("“headerType=\(header)” (HTTP camouflage) is not supported yet")
        }

        stream.serverName = link.take("sni") ?? link.take("peer")
        if let fp = link.take("fp")?.lowercased() {
            guard fp.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }) else {
                throw ConfigError("“fp=\(fp)” is not a TLS fingerprint name")
            }
            stream.fingerprint = fp
        }
        if let alpn = link.take("alpn") {
            stream.alpn = alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        stream.echConfigList = link.take("ech")
        stream.pinnedPeerCertSha256 = link.take("pcs")
        stream.verifyPeerCertByName = link.take("vcn")
        stream.realityPassword = link.take("pbk")
        stream.realityShortID = link.take("sid")
        stream.realityMldsa65Verify = link.take("pqv")
        stream.realitySpiderX = link.take("spx")

        stream.path = link.take("path")
        stream.hostHeader = link.take("host")
        stream.serviceName = link.take("serviceName")
        stream.mode = link.take("mode")?.lowercased()
        stream.authority = link.take("authority")
        stream.extra = link.take("extra")
        try stream.validate()
        return stream
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
            if let pcs = pinnedPeerCertSha256 { try Self.validatePins(pcs, parameter: "pcs") }
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

    /// SHA-256 certificate pins: hex, optionally with colons, comma-separated.
    static func validatePins(_ pins: String, parameter: String) throws {
        for hash in pins.split(separator: ",") {
            let hex = hash.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: ":", with: "")
            guard hex.count == 64, hex.allSatisfy(\.isHexDigit) else {
                throw ConfigError("“\(parameter)” must be SHA-256 hashes in hex")
            }
        }
    }

    // MARK: Xray

    /// Xray `streamSettings`. `host` is the server as written in the link: Xray
    /// gets a resolved IP, so SNI and HTTP Host default to the original name.
    func xrayStreamSettings(host: String) -> [String: Any] {
        let defaultName = IPAddress(host) == nil ? host : nil
        var stream: [String: Any] = ["network": transport.rawValue, "security": security.rawValue]
        switch security {
        case .none: break
        case .tls:
            var tls: [String: Any] = [:]
            if let name = serverName ?? defaultName { tls["serverName"] = name }
            if let fingerprint { tls["fingerprint"] = fingerprint }
            if !alpn.isEmpty { tls["alpn"] = alpn }
            if let echConfigList { tls["echConfigList"] = echConfigList }
            if let pinnedPeerCertSha256 { tls["pinnedPeerCertSha256"] = pinnedPeerCertSha256 }
            if let verifyPeerCertByName { tls["verifyPeerCertByName"] = verifyPeerCertByName }
            stream["tlsSettings"] = tls
        case .reality:
            var reality: [String: Any] = ["password": realityPassword ?? "", "fingerprint": fingerprint ?? "chrome"]
            if let name = serverName ?? defaultName { reality["serverName"] = name }
            if let realityShortID { reality["shortId"] = realityShortID }
            if let realityMldsa65Verify { reality["mldsa65Verify"] = realityMldsa65Verify }
            if let realitySpiderX { reality["spiderX"] = realitySpiderX }
            stream["realitySettings"] = reality
        }

        let httpHost = hostHeader ?? serverName ?? defaultName
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
        return stream
    }

    /// Rows for the Manage window and `bridge check`.
    var summary: [(String, String)] {
        var p: [(String, String)] = [("Transport", transport.rawValue), ("Security", security.rawValue)]
        if let serverName { p.append(("SNI", serverName)) }
        if security != .none { p.append(("Fingerprint", fingerprint ?? "chrome")) }
        if !alpn.isEmpty { p.append(("ALPN", alpn.joined(separator: ","))) }
        if pinnedPeerCertSha256 != nil { p.append(("Pinned certificate", "yes")) }
        if let realityShortID { p.append(("Short ID", realityShortID)) }
        if let realitySpiderX { p.append(("SpiderX", realitySpiderX)) }
        if let hostHeader { p.append(("Host", hostHeader)) }
        if let path { p.append(("Path", path)) }
        if let serviceName { p.append(("Service name", serviceName)) }
        if let mode { p.append(("Mode", mode)) }
        if extra != nil { p.append(("Extra", "custom")) }
        return p
    }
}

extension Data {
    /// Base64url without padding, as used by REALITY keys.
    init?(base64URLEncoded string: String) {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s.append("=") }
        self.init(base64Encoded: s)
    }
}
