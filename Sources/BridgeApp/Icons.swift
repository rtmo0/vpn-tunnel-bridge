import AppKit
import BridgeCore
import SwiftUI

/// Menu bar glyph: a shield, drawn as a template image so macOS tints it for
/// light and dark menu bars.
///
/// - disconnected: empty outline
/// - connecting: the shield fills from the bottom (animated)
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
            strokeOutline()
            // Never completely full, so it can't be mistaken for "connected".
            let progress = CGFloat(frame + 1) / CGFloat(frameCount + 1)
            NSGraphicsContext.saveGraphicsState()
            NSBezierPath(rect: NSRect(x: 0, y: 0, width: 18, height: 1 + 16 * progress)).addClip()
            NSColor.black.setFill()
            outline.fill()
            NSGraphicsContext.restoreGraphicsState()

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

/// Monochrome protocol tile shown next to each tunnel, like account icons.
struct ProtocolBadge: View {
    let kind: TunnelKind
    var size: CGFloat = 28

    private var shades: [Color] {
        switch kind {
        case .amneziawg: [Color(white: 0.30), Color(white: 0.08)]
        case .wireguard: [Color(white: 0.48), Color(white: 0.22)]
        case .openvpn: [Color(white: 0.66), Color(white: 0.38)]
        }
    }

    private var label: String {
        switch kind {
        case .amneziawg: "AWG"
        case .wireguard: "WG"
        case .openvpn: "OVPN"
        }
    }

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
            .fill(LinearGradient(colors: shades, startPoint: .top, endPoint: .bottom))
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.25), lineWidth: 0.6)
            )
            .overlay(
                Text(label)
                    .font(.system(size: size * (label.count > 3 ? 0.27 : 0.36), weight: .heavy))
                    .foregroundStyle(.white)
                    .minimumScaleFactor(0.5)
                    .padding(.horizontal, 2)
            )
            .frame(width: size, height: size)
            .shadow(color: .black.opacity(0.2), radius: 1, y: 1)
    }
}

/// Small status light on the corner of a badge.
struct StatusDot: View {
    let color: Color

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 10, height: 10)
            .overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 2))
    }
}
