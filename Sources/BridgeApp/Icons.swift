import AppKit
import BridgeCore

/// Menu bar glyph: a shield, drawn as a template image so macOS tints it for
/// light and dark menu bars.
///
/// - disconnected: empty outline
/// - connecting: outline with dots appearing one by one (animated)
/// - connected: solid shield with a check mark, or the number of connected tunnels
/// - error: outline with an exclamation mark
enum MenuBarIcon {
    enum State: Hashable {
        case disconnected
        case connecting
        case connected(count: Int)
        case error
    }

    static let frameCount = 4
    private static var cache: [String: NSImage] = [:]

    static func image(_ state: State, frame: Int = 0) -> NSImage {
        let key = "\(state)-\(state == .connecting ? frame % frameCount : 0)"
        if let cached = cache[key] { return cached }
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { _ in
            draw(state, frame: frame % frameCount)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Bridge VPN"
        cache[key] = image
        return image
    }

    /// Same silhouette as the app icon.
    static func shield(center c: CGPoint, halfWidth w: CGFloat, halfHeight h: CGFloat) -> NSBezierPath {
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: c.x + x * w, y: c.y + y * h) }
        let path = NSBezierPath()
        path.move(to: p(0, 1))
        path.curve(to: p(1, 0.80), controlPoint1: p(0.30, 0.98), controlPoint2: p(0.70, 0.86))
        path.curve(to: p(0, -1), controlPoint1: p(1.02, 0.05), controlPoint2: p(0.62, -0.62))
        path.curve(to: p(-1, 0.80), controlPoint1: p(-0.62, -0.62), controlPoint2: p(-1.02, 0.05))
        path.curve(to: p(0, 1), controlPoint1: p(-0.70, 0.86), controlPoint2: p(-0.30, 0.98))
        path.close()
        return path
    }

    private static let outline = shield(center: CGPoint(x: 9, y: 9), halfWidth: 6.9, halfHeight: 7.9)

    private static func strokeOutline() {
        NSColor.black.setStroke()
        outline.lineWidth = 1.5
        outline.lineJoinStyle = .round
        outline.stroke()
    }

    /// Erases `body` out of what has been drawn so far (a knock-out).
    private static func knockOut(_ body: () -> Void) {
        guard let cg = NSGraphicsContext.current?.cgContext else { return }
        cg.saveGState()
        cg.setBlendMode(.destinationOut)
        body()
        cg.restoreGState()
    }

    private static func draw(_ state: State, frame: Int) {
        switch state {
        case .disconnected:
            strokeOutline()

        case .connecting:
            // Outline with three dots appearing one by one, like a loading indicator.
            strokeOutline()
            let visible = frame % frameCount  // 0…3 dots
            NSColor.black.setFill()
            for i in 0..<3 {
                let x = 5.2 + CGFloat(i) * 2.8
                let dot = NSBezierPath(ovalIn: NSRect(x: x, y: 8.3, width: 1.9, height: 1.9))
                if i < visible {
                    dot.fill()
                } else {
                    NSColor.black.withAlphaComponent(0.25).setFill()
                    dot.fill()
                    NSColor.black.setFill()
                }
            }

        case let .connected(count):
            NSColor.black.setFill()
            outline.fill()
            strokeOutline()
            knockOut {
                if count <= 1 {
                    let check = NSBezierPath()
                    check.move(to: CGPoint(x: 5.6, y: 9.3))
                    check.line(to: CGPoint(x: 8.0, y: 6.8))
                    check.line(to: CGPoint(x: 12.5, y: 11.6))
                    check.lineWidth = 2.1
                    check.lineCapStyle = .round
                    check.lineJoinStyle = .round
                    NSColor.black.setStroke()
                    check.stroke()
                } else {
                    let label = count > 9 ? "9+" : "\(count)"
                    let font = NSFont.systemFont(ofSize: count > 9 ? 8 : 10.5, weight: .heavy)
                    let text = NSAttributedString(string: label, attributes: [.font: font, .foregroundColor: NSColor.black])
                    let size = text.size()
                    text.draw(at: CGPoint(x: 9 - size.width / 2, y: 9.6 - size.height / 2))
                }
            }

        case .error:
            strokeOutline()
            NSColor.black.setFill()
            NSBezierPath(roundedRect: NSRect(x: 8.1, y: 7.4, width: 1.8, height: 5.6), xRadius: 0.9, yRadius: 0.9).fill()
            NSBezierPath(ovalIn: NSRect(x: 8.1, y: 4.4, width: 1.8, height: 1.8)).fill()
        }
    }
}

/// Protocol tile for menu items: a rounded rectangle with the protocol name
/// knocked out. Template image, so it follows the menu's highlight colour.
enum ProtocolIcon {
    private static var cache: [TunnelKind: NSImage] = [:]

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
