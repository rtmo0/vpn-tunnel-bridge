import AppKit

/// Menu bar glyph: "VPN" in a rounded frame, drawn as a template image so macOS
/// tints it for light and dark menu bars.
///
/// - disconnected: outlined frame with the letters
/// - connecting: outlined frame with dots appearing one by one (animated)
/// - connected: solid frame with the letters knocked out, or the number of
///   connected tunnels when there are several
/// - error: outlined frame with an exclamation mark
enum MenuBarIcon {
    enum State: Hashable {
        case disconnected
        case connecting
        case connected(count: Int)
        case error
    }

    static let size = NSSize(width: 22, height: 18)
    static let frameCount = 4
    private static var cache: [String: NSImage] = [:]

    static func image(_ state: State, frame: Int = 0) -> NSImage {
        let key = "\(state)-\(state == .connecting ? frame % frameCount : 0)"
        if let cached = cache[key] { return cached }
        let image = NSImage(size: size, flipped: false) { _ in
            draw(state, frame: frame % frameCount)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Bridge VPN"
        cache[key] = image
        return image
    }

    private static let box = NSRect(x: 1.25, y: 2.25, width: 19.5, height: 13.5)

    private static func frame() -> NSBezierPath {
        let path = NSBezierPath(roundedRect: box, xRadius: 3.8, yRadius: 3.8)
        path.lineWidth = 1.5
        return path
    }

    /// The letters V, P and N as round-capped strokes, 6.2 pt tall.
    private static func letters() -> NSBezierPath {
        let bottom: CGFloat = 5.9, top: CGFloat = 12.1, dx: CGFloat = 0.15
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x + dx, y: y) }
        let path = NSBezierPath()
        // V
        path.move(to: p(3.8, top))
        path.line(to: p(5.9, bottom))
        path.line(to: p(8.0, top))
        // P
        path.move(to: p(9.3, bottom))
        path.line(to: p(9.3, top))
        path.line(to: p(11.0, top))
        path.appendArc(withCenter: p(11.0, 10.5), radius: 1.6, startAngle: 90, endAngle: -90, clockwise: true)
        path.line(to: p(9.3, 8.9))
        // N
        path.move(to: p(13.9, bottom))
        path.line(to: p(13.9, top))
        path.line(to: p(17.9, bottom))
        path.line(to: p(17.9, top))
        path.lineWidth = 1.4
        path.lineCapStyle = .round
        path.lineJoinStyle = .round
        return path
    }

    /// Erases `body` out of what has been drawn so far (a knock-out).
    private static func knockOut(_ body: () -> Void) {
        guard let cg = NSGraphicsContext.current?.cgContext else { return }
        cg.saveGState()
        cg.setBlendMode(.destinationOut)
        body()
        cg.restoreGState()
    }

    private static func draw(_ state: State, frame step: Int) {
        NSColor.black.set()
        switch state {
        case .disconnected:
            frame().stroke()
            letters().stroke()

        case .connecting:
            frame().stroke()
            for i in 0..<3 {
                NSColor.black.withAlphaComponent(i < step ? 1 : 0.25).setFill()
                NSBezierPath(ovalIn: NSRect(x: 6.8 + CGFloat(i) * 3.3, y: 8.0, width: 2.0, height: 2.0)).fill()
            }

        case let .connected(count):
            let solid = frame()
            solid.fill()
            solid.stroke()
            knockOut {
                if count <= 1 {
                    letters().stroke()
                } else {
                    let label = count > 9 ? "9+" : "\(count)"
                    let font = NSFont.systemFont(ofSize: 10.5, weight: .heavy)
                    let text = NSAttributedString(string: label, attributes: [.font: font, .foregroundColor: NSColor.black])
                    let textSize = text.size()
                    text.draw(at: CGPoint(x: box.midX - textSize.width / 2, y: box.midY - textSize.height / 2 + 0.4))
                }
            }

        case .error:
            frame().stroke()
            NSBezierPath(roundedRect: NSRect(x: 10.2, y: 8.4, width: 1.6, height: 4.4), xRadius: 0.8, yRadius: 0.8).fill()
            NSBezierPath(ovalIn: NSRect(x: 10.2, y: 5.4, width: 1.6, height: 1.6)).fill()
        }
    }
}

/// Shown in place of a tunnel's tile (`KindTile.menuImage`) while it connects:
/// a tile outline of the same size with three dots that light up one after another.
/// Template image, so it follows the menu's highlight colour.
enum ProtocolIcon {
    private static var loadingCache: [Int: NSImage] = [:]

    static func loading(frame: Int) -> NSImage {
        let step = frame % 4
        if let cached = loadingCache[step] { return cached }
        let image = NSImage(size: NSSize(width: 16, height: 16), flipped: false) { rect in
            NSColor.black.setStroke()
            let outline = NSBezierPath(roundedRect: rect.insetBy(dx: 0.75, dy: 0.75), xRadius: 3.4, yRadius: 3.4)
            outline.lineWidth = 1.2
            outline.stroke()
            for i in 0..<3 {
                let dot = NSRect(x: 3.4 + CGFloat(i) * 3.6, y: 6.9, width: 2.2, height: 2.2)
                NSColor.black.withAlphaComponent(i < step ? 1 : 0.25).setFill()
                NSBezierPath(ovalIn: dot).fill()
            }
            return true
        }
        image.isTemplate = true
        loadingCache[step] = image
        return image
    }
}
