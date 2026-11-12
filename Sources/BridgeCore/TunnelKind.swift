import Foundation

public enum TunnelKind: String, Codable, Sendable {
    case amneziawg, wireguard, openvpn, vless, trojan, hysteria2

    public var displayName: String {
        switch self {
        case .amneziawg: "AmneziaWG"
        case .wireguard: "WireGuard"
        case .openvpn: "OpenVPN"
        case .vless: "VLESS"
        case .trojan: "Trojan"
        case .hysteria2: "Hysteria 2"
        }
    }

    /// File extension in the tunnel library.
    public var fileExtension: String {
        switch self {
        case .amneziawg, .wireguard: "conf"
        case .openvpn: "ovpn"
        case .vless: "vless"
        case .trojan: "trojan"
        case .hysteria2: "hy2"
        }
    }

    /// Protocols that run through the bundled Xray-core and come from share links.
    public var usesXray: Bool {
        switch self {
        case .vless, .trojan, .hysteria2: true
        case .amneziawg, .wireguard, .openvpn: false
        }
    }

    /// Guesses the protocol from config text: wg-quick files have an [Interface] section,
    /// Xray-based tunnels are a share link.
    public static func detect(_ text: String) -> TunnelKind {
        if let kind = ProxyLink.kind(of: text) { return kind }
        let lowered = text.lowercased()
        if lowered.range(of: #"(^|\n)\s*\[interface\]"#, options: .regularExpression) != nil {
            if let config = try? TunnelConfig.parse(text), !config.usesAmneziaObfuscation { return .wireguard }
            return .amneziawg
        }
        return .openvpn
    }
}
