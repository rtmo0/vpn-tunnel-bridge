import Foundation

/// A VLESS server parsed from a share link (`vless://…`), as described in
/// XTLS/Xray-core discussion #716.
///
/// Like the other parsers, every query parameter is either applied or rejected:
/// a link is never connected with part of it silently ignored.
public struct VLESSConfig: Equatable, Sendable {
    /// User ID: a UUID, or a 1–30 byte string that Xray maps to one.
    public var id: String
    public var host: String
    public var port: UInt16
    /// The `#name` part of the link.
    public var remark: String?
    public var encryption = "none"
    public var flow: String?
    public var stream: ProxyStream

    public var endpoint: String { Endpoint.format(host: host, port: port) }

    static let flows: Set<String> = ["xtls-rprx-vision", "xtls-rprx-vision-udp443"]

    public static func parse(_ text: String) throws -> VLESSConfig {
        var link = try ShareLink.parse(text)
        guard link.scheme == "vless" else { throw ConfigError("Not a vless:// link") }
        guard let user = link.user, !user.isEmpty else {
            throw ConfigError("The link has no user ID (vless://<uuid>@host:port)")
        }
        guard !user.contains(":") else { throw ConfigError("The user ID must not contain “:”") }
        guard UUID(uuidString: user) != nil || (1...30).contains(user.utf8.count) else {
            throw ConfigError("“\(user.prefix(8))…” is not a valid VLESS user ID")
        }
        let port = try link.singlePort()

        var encryption = "none"
        if let value = link.take("encryption") {
            guard value.allSatisfy({ $0.isASCII && !$0.isWhitespace && $0 != "\"" && $0 != "\\" }) else {
                throw ConfigError("“encryption” contains invalid characters")
            }
            encryption = value
        }
        var flow: String?
        if let value = link.take("flow")?.lowercased() {
            guard flows.contains(value) else { throw ConfigError("Unknown flow “\(value)”") }
            flow = value
        }
        if let value = link.take("packetEncoding"), value.lowercased() != "xudp" {
            throw ConfigError("“packetEncoding=\(value)” is not supported (only xudp)")
        }
        let stream = try ProxyStream.take(from: &link, defaultSecurity: .none)
        try link.rejectLeftovers()

        if let flow, stream.transport != .raw || stream.security == .none {
            throw ConfigError("flow=\(flow) works only with type=tcp and security=tls or reality")
        }
        return VLESSConfig(id: user, host: link.host, port: port, remark: link.fragment, encryption: encryption,
                           flow: flow, stream: stream)
    }

    func xrayOutbound(address: String) -> [String: Any] {
        var user: [String: Any] = ["id": id, "encryption": encryption]
        if let flow { user["flow"] = flow }
        return ["protocol": "vless",
                "settings": ["vnext": [["address": address, "port": Int(port), "users": [user]]]],
                "streamSettings": stream.xrayStreamSettings(host: host)]
    }

    var summary: [(String, String)] {
        var rows = stream.summary
        if let flow { rows.insert(("Flow", flow), at: 2) }
        if encryption != "none" { rows.insert(("Encryption", "\(encryption.prefix(24))…"), at: 2) }
        return rows
    }
}

/// A Trojan server from a share link (`trojan://password@host:port?…`).
/// Uses the same transport and TLS/REALITY parameters as VLESS; TLS is the default.
public struct TrojanConfig: Equatable, Sendable {
    public var password: String
    public var host: String
    public var port: UInt16
    public var remark: String?
    public var stream: ProxyStream

    public var endpoint: String { Endpoint.format(host: host, port: port) }

    public static func parse(_ text: String) throws -> TrojanConfig {
        var link = try ShareLink.parse(text)
        guard link.scheme == "trojan" else { throw ConfigError("Not a trojan:// link") }
        guard let password = link.user, !password.isEmpty else {
            throw ConfigError("The link has no password (trojan://<password>@host:port)")
        }
        let port = try link.singlePort(default: 443)
        if let flow = link.take("flow") {
            throw ConfigError("Trojan “flow=\(flow)” is not supported; use VLESS for XTLS")
        }
        let stream = try ProxyStream.take(from: &link, defaultSecurity: .tls)
        try link.rejectLeftovers()
        return TrojanConfig(password: password, host: link.host, port: port, remark: link.fragment, stream: stream)
    }

    func xrayOutbound(address: String) -> [String: Any] {
        ["protocol": "trojan",
         "settings": ["servers": [["address": address, "port": Int(port), "password": password]]],
         "streamSettings": stream.xrayStreamSettings(host: host)]
    }
}

/// A Hysteria 2 server from a share link (`hysteria2://` or `hy2://`), as in
/// the official URI scheme: `hysteria2://[auth@]host[:ports]/?sni=…&obfs=salamander…`.
///
/// Several ports (`443,20000-30000`) mean port hopping.
public struct Hysteria2Config: Equatable, Sendable {
    /// Password, or `user:pass` for servers with userpass auth.
    public var auth: String
    public var host: String
    public var ports: PortList
    public var remark: String?
    public var serverName: String?
    public var pinnedPeerCertSha256: String?
    public var alpn: [String] = []
    public var obfsPassword: String?
    /// Seconds between port hops (only with several ports).
    public var hopInterval: Int?
    /// Bandwidth for Brutal congestion control, in Mbit/s; BBR when unset.
    public var upMbps: Int?
    public var downMbps: Int?

    public var port: UInt16 { ports.first }
    public var endpoint: String { Endpoint.format(host: host, port: port) }
    public var usesPortHopping: Bool { !ports.isSinglePort }

    public static func parse(_ text: String) throws -> Hysteria2Config {
        var link = try ShareLink.parse(text)
        guard ["hysteria2", "hy2"].contains(link.scheme) else { throw ConfigError("Not a hysteria2:// link") }
        guard let auth = link.user, !auth.isEmpty else {
            throw ConfigError("The link has no password (hysteria2://<password>@host:port)")
        }
        var portText = link.portSpec ?? ""
        if portText.isEmpty { portText = "443" }
        // Some clients put the hopping range in “mport” and keep the main port in the address.
        if let mport = link.take("mport") { portText += ",\(mport)" }
        guard let ports = PortList(portText) else { throw ConfigError("“\(portText)” is not a port or port range") }

        var config = Hysteria2Config(auth: auth, host: link.host, ports: ports, remark: link.fragment)
        config.serverName = link.take("sni") ?? link.take("peer")
        if let value = link.take("insecure"), !["0", "false"].contains(value.lowercased()) {
            throw ConfigError("“insecure=\(value)” turns off certificate checks, which Bridge does not do. "
                + "Pin the server certificate with “pinSHA256=<sha256>” instead")
        }
        if let pin = link.take("pinSHA256") {
            try ProxyStream.validatePins(pin, parameter: "pinSHA256")
            config.pinnedPeerCertSha256 = pin
        }
        if let alpn = link.take("alpn") {
            config.alpn = alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        switch link.take("obfs")?.lowercased() {
        case nil:
            if link.take("obfs-password") != nil { throw ConfigError("“obfs-password” needs “obfs=salamander”") }
        case "salamander":
            guard let password = link.take("obfs-password") else {
                throw ConfigError("obfs=salamander needs “obfs-password”")
            }
            config.obfsPassword = password
        case let other?:
            throw ConfigError("Unknown obfuscation “obfs=\(other)” (only salamander)")
        }
        if let interval = link.take("hopInterval") ?? link.take("hop-interval") {
            let digits = interval.lowercased().hasSuffix("s") ? String(interval.dropLast()) : interval
            guard let seconds = Int(digits), seconds >= 5 else {
                throw ConfigError("“hopInterval” must be at least 5 seconds")
            }
            config.hopInterval = seconds
        }
        for (names, keyPath) in [(["upmbps", "up"], \Hysteria2Config.upMbps), (["downmbps", "down"], \.downMbps)] {
            var found: String?
            for name in names where found == nil { found = link.take(name) }
            guard let value = found else { continue }
            let digits = value.lowercased().replacingOccurrences(of: "mbps", with: "").trimmingCharacters(in: .whitespaces)
            guard let mbps = Int(digits), mbps > 0 else { throw ConfigError("“\(names[0])” must be Mbit/s, e.g. 50") }
            config[keyPath: keyPath] = mbps
        }
        if config.upMbps != nil && (config.upMbps ?? 0) * 125_000 < 65_536 {
            throw ConfigError("“upmbps” is too low")
        }
        // Hysteria 2 is QUIC: TLS fingerprints don't apply. Accept the common empty/default value only.
        if let fp = link.take("fp"), !["chrome", "none"].contains(fp.lowercased()) {
            throw ConfigError("“fp” is not used by Hysteria 2")
        }
        try link.rejectLeftovers()
        return config
    }

    func xrayOutbound(address: String) -> [String: Any] {
        var tls: [String: Any] = ["alpn": alpn.isEmpty ? ["h3"] : alpn]
        if let name = serverName ?? (IPAddress(host) == nil ? host : nil) { tls["serverName"] = name }
        if let pinnedPeerCertSha256 { tls["pinnedPeerCertSha256"] = pinnedPeerCertSha256 }

        var masks: [[String: Any]] = []
        if let obfsPassword { masks.append(["type": "salamander", "settings": ["password": obfsPassword]]) }
        if usesPortHopping {
            let interval = hopInterval ?? 30
            masks.append(["type": "udphop", "settings": [
                "mode": "intervalRemote", "interval": "\(interval)-\(interval)", "remotePorts": ports.description,
            ]])
        }
        var finalMask: [String: Any] = [:]
        if !masks.isEmpty { finalMask["udp"] = masks }
        if let upMbps {
            var quic: [String: Any] = ["congestion": "brutal", "brutalUp": "\(upMbps) mbps"]
            if let downMbps { quic["brutalDown"] = "\(downMbps) mbps" }
            finalMask["quicParams"] = quic
        }

        var stream: [String: Any] = ["network": "hysteria", "security": "tls", "tlsSettings": tls,
                                     "hysteriaSettings": ["version": 2, "auth": auth]]
        if !finalMask.isEmpty { stream["finalmask"] = finalMask }
        return ["protocol": "hysteria",
                "settings": ["version": 2, "address": address, "port": Int(port)],
                "streamSettings": stream]
    }

    var summary: [(String, String)] {
        var rows: [(String, String)] = [("Transport", "QUIC")]
        if usesPortHopping { rows.append(("Ports", "\(ports) (hopping every \(hopInterval ?? 30) s)")) }
        if let serverName { rows.append(("SNI", serverName)) }
        if pinnedPeerCertSha256 != nil { rows.append(("Pinned certificate", "yes")) }
        rows.append(("Obfuscation", obfsPassword == nil ? "none" : "salamander"))
        if let upMbps {
            rows.append(("Congestion", "Brutal, ↑ \(upMbps)" + (downMbps.map { " ↓ \($0)" } ?? "") + " Mbit/s"))
        } else {
            rows.append(("Congestion", "BBR"))
        }
        return rows
    }
}

extension Endpoint {
    static func format(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}
