import Foundation

public enum TunnelKind: String, Codable, Sendable {
    case amneziawg, wireguard, openvpn, vless

    public var displayName: String {
        switch self {
        case .amneziawg: "AmneziaWG"
        case .wireguard: "WireGuard"
        case .openvpn: "OpenVPN"
        case .vless: "VLESS"
        }
    }

    /// File extension in the tunnel library.
    public var fileExtension: String {
        switch self {
        case .amneziawg, .wireguard: "conf"
        case .openvpn: "ovpn"
        case .vless: "vless"
        }
    }

    /// Guesses the protocol from config text: wg-quick files have an [Interface] section,
    /// VLESS tunnels are a share link.
    public static func detect(_ text: String) -> TunnelKind {
        if VLESSConfig.isLink(text) { return .vless }
        let lowered = text.lowercased()
        if lowered.range(of: #"(^|\n)\s*\[interface\]"#, options: .regularExpression) != nil {
            if let config = try? TunnelConfig.parse(text), !config.usesAmneziaObfuscation { return .wireguard }
            return .amneziawg
        }
        return .openvpn
    }
}
