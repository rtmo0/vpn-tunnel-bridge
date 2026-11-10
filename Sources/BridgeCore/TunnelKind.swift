import Foundation

public enum TunnelKind: String, Codable, Sendable {
    case amneziawg, wireguard, openvpn

    public var displayName: String {
        switch self {
        case .amneziawg: "AmneziaWG"
        case .wireguard: "WireGuard"
        case .openvpn: "OpenVPN"
        }
    }

    /// Guesses the protocol from config text: wg-quick files have an [Interface] section.
    public static func detect(_ text: String) -> TunnelKind {
        let lowered = text.lowercased()
        if lowered.range(of: #"(^|\n)\s*\[interface\]"#, options: .regularExpression) != nil {
            if let config = try? TunnelConfig.parse(text), !config.usesAmneziaObfuscation { return .wireguard }
            return .amneziawg
        }
        return .openvpn
    }
}
