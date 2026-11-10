// Renders the Bridge app icon (1024×1024 PNG): a monochrome shield with
// "VPN" and a slatted padlock on a graphite squircle.
//
//   swift scripts/make-icon.swift build/icon/AppIcon-1024.png
//
// scripts/make-icon.sh turns it into Resources/AppIcon.icns.

import AppKit
import CoreGraphics

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon-1024.png"
let size: CGFloat = 1024

func gray(_ white: CGFloat, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: white, green: white, blue: white, alpha: alpha)
}

func gradient(_ stops: [(CGFloat, CGFloat, CGFloat)]) -> CGGradient {
    CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
               colors: stops.map { gray($0.0, $0.1) } as CFArray, locations: stops.map(\.2))!
}

/// Shield outline: pointed top centre, squared shoulders, curved sides to a point.
func shieldPath(center c: CGPoint, halfWidth w: CGFloat, halfHeight h: CGFloat) -> CGPath {
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: c.x + x * w, y: c.y + y * h) }
    let path = CGMutablePath()
    path.move(to: p(0, 1))
    path.addQuadCurve(to: p(1, 0.80), control: p(0.45, 0.97))
    path.addCurve(to: p(0, -1), control1: p(1.02, 0.05), control2: p(0.62, -0.62))
    path.addCurve(to: p(-1, 0.80), control1: p(-0.62, -0.62), control2: p(-1.02, 0.05))
    path.addQuadCurve(to: p(0, 1), control: p(-0.45, 0.97))
    path.closeSubpath()
    return path
}

let space = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
                    space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!

// macOS icon grid: 824×824 body, corner radius ≈ 185.
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let bodyPath = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -18), blur: 40, color: gray(0, 0.5))
ctx.addPath(bodyPath)
ctx.setFillColor(gray(0.08))
ctx.fillPath()
ctx.restoreGState()

// Background: graphite radial glow, like light behind the shield.
ctx.saveGState()
ctx.addPath(bodyPath)
ctx.clip()
ctx.drawRadialGradient(gradient([(0.42, 1, 0), (0.18, 1, 0.55), (0.04, 1, 1)]),
                       startCenter: CGPoint(x: 512, y: 520), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 520), endRadius: 600, options: [.drawsAfterEndLocation])

// Shield: white rim with a soft shadow, black face.
let center = CGPoint(x: 512, y: 505)
let outer = shieldPath(center: center, halfWidth: 250, halfHeight: 330)
let inner = shieldPath(center: CGPoint(x: 512, y: 512), halfWidth: 200, halfHeight: 275)

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 36, color: gray(0, 0.65))
ctx.addPath(outer)
ctx.setFillColor(gray(1))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(outer)
ctx.clip()
ctx.drawLinearGradient(gradient([(1, 1, 0), (0.86, 1, 1)]),
                       start: CGPoint(x: 512, y: 840), end: CGPoint(x: 512, y: 170), options: [])
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(inner)
ctx.clip()
ctx.drawLinearGradient(gradient([(0.16, 1, 0), (0.03, 1, 1)]),
                       start: CGPoint(x: 512, y: 790), end: CGPoint(x: 512, y: 240), options: [])
// Gloss on the upper half of the face.
ctx.drawRadialGradient(gradient([(1, 0.10, 0), (1, 0, 1)]),
                       startCenter: CGPoint(x: 512, y: 760), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 760), endRadius: 260, options: [])
ctx.restoreGState()

// "VPN"
NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: false)
let font = NSFont.systemFont(ofSize: 168, weight: .black)
let text = NSAttributedString(string: "VPN", attributes: [
    .font: font, .foregroundColor: NSColor.white, .kern: 4,
])
let textSize = text.size()
text.draw(at: CGPoint(x: 512 - textSize.width / 2, y: 575 - font.descender * -0.2))

// Padlock: shackle plus a body made of horizontal slats.
ctx.setStrokeColor(gray(1))
ctx.setLineWidth(26)
ctx.setLineCap(.butt)
let shackle = CGMutablePath()
shackle.move(to: CGPoint(x: 462, y: 432))
shackle.addLine(to: CGPoint(x: 462, y: 470))
shackle.addArc(center: CGPoint(x: 512, y: 470), radius: 50, startAngle: .pi, endAngle: 0, clockwise: true)
shackle.addLine(to: CGPoint(x: 562, y: 432))
ctx.addPath(shackle)
ctx.strokePath()

ctx.setFillColor(gray(1))
let slatHeight: CGFloat = 24, gap: CGFloat = 11
for i in 0..<4 {
    let y = 430 - CGFloat(i + 1) * slatHeight - CGFloat(i) * gap
    ctx.fill(CGRect(x: 432, y: y, width: 160, height: slatHeight))
}

ctx.restoreGState()  // body clip

// Rim: light on top, dark at the bottom.
ctx.saveGState()
ctx.addPath(bodyPath)
ctx.setLineWidth(4)
ctx.replacePathWithStrokedPath()
ctx.clip()
ctx.drawLinearGradient(gradient([(1, 0.25, 0), (1, 0.04, 0.5), (0, 0.35, 1)]),
                       start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
ctx.restoreGState()

let image = ctx.makeImage()!
let url = URL(fileURLWithPath: output)
try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
try NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])!.write(to: url)
print("wrote \(output)")
