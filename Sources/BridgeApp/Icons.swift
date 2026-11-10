import AppKit
import BridgeCore

/// Menu bar glyph built on SF Symbols, so it matches the system's other menu bar
/// icons in weight and size. Template image: macOS tints it for light/dark bars.
///
/// - disconnected: `shield`
/// - connecting: `shield` with dots lighting up one by one (animated)
/// - one tunnel: `checkmark.shield.fill`
/// - several tunnels: `shield.fill` with the count knocked out
/// - problem: `exclamationmark.shield`
enum MenuBarIcon {
    enum State: Hashable {
        case disconnected
        case connecting
        case connected(count: Int)
        case error
    }

    static let frameCount = 4
    private static var cache: [String: NSImage] = [:]

    private static func symbol(_ name: String) -> NSImage? {
        let config = NSImage.SymbolConfiguration(pointSize: 15, weight: .regular)
        return NSImage(systemSymbolName: name, accessibilityDescription: nil)?.withSymbolConfiguration(config)
    }

    static func image(_ state: State, frame: Int = 0) -> NSImage {
        let step = frame % frameCount
        let key = "\(state)-\(state == .connecting ? step : 0)"
        if let cached = cache[key] { return cached }

        let name: String
        switch state {
        case .disconnected, .connecting: name = "shield"
        case let .connected(count): name = count <= 1 ? "checkmark.shield.fill" : "shield.fill"
        case .error: name = "exclamationmark.shield"
        }
        let base = symbol(name) ?? NSImage(size: NSSize(width: 16, height: 18))
        let image = NSImage(size: base.size, flipped: false) { rect in
            base.draw(in: rect)
            switch state {
            case .connecting:
                // Three dots in the optical centre of the shield (a little above the middle).
                let d = (rect.width * 0.14).rounded(.toNearestOrEven)
                let gap = rect.width * 0.08
                let total = 3 * d + 2 * gap
                let y = rect.midY + rect.height * 0.04 - d / 2
                for i in 0..<3 {
                    let x = rect.midX - total / 2 + CGFloat(i) * (d + gap)
                    NSColor.black.withAlphaComponent(i < step ? 1 : 0.28).setFill()
                    NSBezierPath(ovalIn: NSRect(x: x, y: y, width: d, height: d)).fill()
                }
            case let .connected(count) where count > 1:
                guard let cg = NSGraphicsContext.current?.cgContext else { break }
                cg.saveGState()
                cg.setBlendMode(.destinationOut)
                let label = count > 9 ? "9+" : "\(count)"
                let font = NSFont.systemFont(ofSize: count > 9 ? 7.5 : 10, weight: .bold)
                let text = NSAttributedString(string: label, attributes: [.font: font, .foregroundColor: NSColor.black])
                let size = text.size()
                text.draw(at: CGPoint(x: rect.midX - size.width / 2, y: rect.midY - size.height / 2 + rect.height * 0.04))
                cg.restoreGState()
            default:
                break
            }
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Bridge VPN"
        cache[key] = image
        return image
    }
}

/// Protocol tile for menu items: a rounded rectangle with the protocol name
/// knocked out. Template image, so it follows the menu's highlight colour.
enum ProtocolIcon {
    private static var cache: [TunnelKind: NSImage] = [:]
    private static var loadingCache: [Int: NSImage] = [:]

    /// Same size as the protocol tiles: an outlined tile with three dots that
    /// light up one after another. Used while a tunnel connects.
    static func loading(frame: Int) -> NSImage {
        let step = frame % 4
        if let cached = loadingCache[step] { return cached }
        let image = NSImage(size: NSSize(width: 26, height: 15), flipped: false) { rect in
            NSColor.black.setStroke()
            let outline = NSBezierPath(roundedRect: rect.insetBy(dx: 1, dy: 1.5), xRadius: 3.5, yRadius: 3.5)
            outline.lineWidth = 1.2
            outline.stroke()
            for i in 0..<3 {
                let dot = NSRect(x: 7.3 + CGFloat(i) * 4.4, y: 6, width: 2.6, height: 2.6)
                NSColor.black.withAlphaComponent(i < step ? 1 : 0.25).setFill()
                NSBezierPath(ovalIn: dot).fill()
            }
            return true
        }
        image.isTemplate = true
        loadingCache[step] = image
        return image
    }

    static func image(_ kind: TunnelKind) -> NSImage {
        if let cached = cache[kind] { return cached }
        let label: String
        switch kind {
        case .amneziawg: label = "AWG"
        case .wireguard: label = "WG"
        case .openvpn: label = "OVPN"
        }
        let size = NSSize(width: 26, height: 15)
        let image = NSImage(size: size, flipped: false) { rect in
            NSColor.black.setFill()
            NSBezierPath(roundedRect: rect.insetBy(dx: 0.5, dy: 1), xRadius: 3.5, yRadius: 3.5).fill()
            guard let cg = NSGraphicsContext.current?.cgContext else { return true }
            cg.setBlendMode(.destinationOut)
            let font = NSFont.systemFont(ofSize: label.count > 3 ? 7.2 : 8.5, weight: .heavy)
            let text = NSAttributedString(string: label, attributes: [.font: font, .foregroundColor: NSColor.black,
                                                                      .kern: label.count > 3 ? 0 : 0.3])
            let textSize = text.size()
            text.draw(at: CGPoint(x: (rect.width - textSize.width) / 2, y: (rect.height - textSize.height) / 2 + 0.3))
            return true
        }
        image.isTemplate = true
        cache[kind] = image
        return image
    }
}
