// Renders the Bridge app icon (1024×1024 PNG) in a monochrome Liquid Glass
// style: a translucent glass shield with specular edges over a softly lit
// graphite background, carrying "VPN" and a slatted padlock.
//
//   swift scripts/make-icon.swift build/icon/AppIcon-1024.png
//
// scripts/make-icon.sh turns it into Resources/AppIcon.icns.

import AppKit
import CoreGraphics

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon-1024.png"
let size: CGFloat = 1024

func gray(_ white: CGFloat, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: white, green: white, blue: min(1, white * 1.03), alpha: alpha)
}

func gradient(_ stops: [(CGFloat, CGFloat, CGFloat)]) -> CGGradient {
    CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
               colors: stops.map { gray($0.0, $0.1) } as CFArray, locations: stops.map(\.2))!
}

/// Apple-style continuous-corner squircle (superellipse).
func squircle(_ rect: CGRect, exponent n: CGFloat = 5) -> CGPath {
    let path = CGMutablePath()
    let a = rect.width / 2, b = rect.height / 2
    for i in 0...720 {
        let t = CGFloat(i) / 720 * 2 * .pi
        let ct = cos(t), st = sin(t)
        let p = CGPoint(x: rect.midX + a * (ct < 0 ? -1 : 1) * pow(abs(ct), 2 / n),
                        y: rect.midY + b * (st < 0 ? -1 : 1) * pow(abs(st), 2 / n))
        if i == 0 { path.move(to: p) } else { path.addLine(to: p) }
    }
    path.closeSubpath()
    return path
}

func shield(_ c: CGPoint, _ w: CGFloat, _ h: CGFloat) -> CGPath {
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: c.x + x * w, y: c.y + y * h) }
    let path = CGMutablePath()
    path.move(to: p(0, 1))
    path.addCurve(to: p(1, 0.80), control1: p(0.30, 0.98), control2: p(0.70, 0.86))
    path.addCurve(to: p(0, -1), control1: p(1.02, 0.05), control2: p(0.62, -0.62))
    path.addCurve(to: p(-1, 0.80), control1: p(-0.62, -0.62), control2: p(-1.02, 0.05))
    path.addCurve(to: p(0, 1), control1: p(-0.70, 0.86), control2: p(-0.30, 0.98))
    path.closeSubpath()
    return path
}

let ctx = CGContext(data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: false)

/// Strokes `path` with a gradient running from `top` to `bottom`.
func gradientStroke(_ path: CGPath, width: CGFloat, top: CGFloat, bottom: CGFloat,
                    _ stops: [(CGFloat, CGFloat, CGFloat)], clipTo clip: CGPath? = nil) {
    ctx.saveGState()
    if let clip { ctx.addPath(clip); ctx.clip() }
    ctx.addPath(path)
    ctx.setLineWidth(width)
    ctx.setLineJoin(.round)
    ctx.replacePathWithStrokedPath()
    ctx.clip()
    ctx.drawLinearGradient(gradient(stops), start: CGPoint(x: 380, y: top), end: CGPoint(x: 644, y: bottom),
                           options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    ctx.restoreGState()
}

/// Soft light blob, used both behind the glass and (blurrier) through it.
func lightBlobs(blurScale: CGFloat, alpha: CGFloat) {
    for (x, y, r, a) in [(330.0, 760.0, 260.0, 0.55), (720.0, 300.0, 300.0, 0.40), (560.0, 620.0, 200.0, 0.30)] {
        let radius = CGFloat(r) * blurScale
        ctx.drawRadialGradient(gradient([(1, CGFloat(a) * alpha, 0), (1, 0, 1)]),
                               startCenter: CGPoint(x: x, y: y), startRadius: 0,
                               endCenter: CGPoint(x: x, y: y), endRadius: radius, options: [])
    }
}

// ---- Background ----------------------------------------------------------

let body = squircle(CGRect(x: 100, y: 100, width: 824, height: 824))

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -20), blur: 44, color: gray(0, 0.5))
ctx.addPath(body)
ctx.setFillColor(gray(0.08))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(body)
ctx.clip()
ctx.drawLinearGradient(gradient([(0.27, 1, 0), (0.12, 1, 0.55), (0.04, 1, 1)]),
                       start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
lightBlobs(blurScale: 1, alpha: 0.6)

// ---- Glass shield --------------------------------------------------------

let glass = shield(CGPoint(x: 512, y: 505), 268, 350)

// Shadow the glass casts on the background.
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -24), blur: 50, color: gray(0, 0.55))
ctx.addPath(glass)
ctx.setFillColor(gray(0.10, 0.6))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(glass)
ctx.clip()
// Frosted body: the background light shows through, blurred and brightened.
ctx.drawLinearGradient(gradient([(0.97, 0.40, 0), (0.85, 0.20, 0.5), (0.80, 0.16, 1)]),
                       start: CGPoint(x: 512, y: 855), end: CGPoint(x: 512, y: 155), options: [])
lightBlobs(blurScale: 1.6, alpha: 0.30)
// Darker core so the glyphs read well.
ctx.drawRadialGradient(gradient([(0, 0.40, 0), (0, 0.18, 0.7), (0, 0, 1)]),
                       startCenter: CGPoint(x: 512, y: 470), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 470), endRadius: 300, options: [])
// Top-left specular sheen.
ctx.drawRadialGradient(gradient([(1, 0.35, 0), (1, 0, 1)]),
                       startCenter: CGPoint(x: 360, y: 790), startRadius: 0,
                       endCenter: CGPoint(x: 360, y: 790), endRadius: 260, options: [])
// Inner glow along the edge (light refracted at the rim).
ctx.addPath(glass)
ctx.setLineWidth(60)
ctx.setStrokeColor(gray(1, 0.10))
ctx.strokePath()
ctx.restoreGState()

// Specular rim: bright at the top left, fading towards the bottom right.
gradientStroke(glass, width: 16, top: 860, bottom: 160,
               [(1, 1.0, 0), (1, 0.55, 0.30), (1, 0.12, 0.65), (1, 0.75, 1)], clipTo: glass)
// Second, inner edge: the far side of the glass, gives it thickness.
gradientStroke(shield(CGPoint(x: 512, y: 507), 252, 330), width: 2.5, top: 840, bottom: 180,
               [(1, 0.15, 0), (1, 0.45, 0.6), (1, 0.30, 1)])
// Thin outer edge for definition against the dark background.
gradientStroke(glass, width: 2.5, top: 860, bottom: 160, [(1, 0.6, 0), (1, 0.25, 1)])

// ---- Glyphs --------------------------------------------------------------

let glyphShadow = { ctx.setShadow(offset: CGSize(width: 0, height: -5), blur: 14, color: gray(0, 0.55)) }

let font = NSFont.systemFont(ofSize: 168, weight: .black)
let text = NSAttributedString(string: "VPN", attributes: [
    .font: font, .foregroundColor: NSColor(white: 1, alpha: 0.97), .kern: 6,
])
let textSize = text.size()
ctx.saveGState()
glyphShadow()
text.draw(at: CGPoint(x: 512 - textSize.width / 2 + 3, y: 560))
ctx.restoreGState()

ctx.saveGState()
glyphShadow()
ctx.beginTransparencyLayer(auxiliaryInfo: nil)
let shackle = CGMutablePath()
shackle.move(to: CGPoint(x: 467, y: 430))
shackle.addLine(to: CGPoint(x: 467, y: 470))
shackle.addArc(center: CGPoint(x: 512, y: 470), radius: 45, startAngle: .pi, endAngle: 0, clockwise: true)
shackle.addLine(to: CGPoint(x: 557, y: 430))
ctx.addPath(shackle)
ctx.setLineWidth(24)
ctx.setLineCap(.round)
ctx.setStrokeColor(gray(1, 0.97))
ctx.strokePath()
ctx.setFillColor(gray(1, 0.97))
let slat: CGFloat = 23, gap: CGFloat = 10
for i in 0..<4 {
    let y = 428 - CGFloat(i + 1) * slat - CGFloat(i) * gap
    ctx.addPath(CGPath(roundedRect: CGRect(x: 437, y: y, width: 150, height: slat),
                       cornerWidth: 8, cornerHeight: 8, transform: nil))
    ctx.fillPath()
}
ctx.endTransparencyLayer()
ctx.restoreGState()

ctx.restoreGState()  // body clip

// ---- Body edge -----------------------------------------------------------

gradientStroke(body, width: 5, top: 924, bottom: 100, [(1, 0.32, 0), (1, 0.05, 0.45), (0, 0.4, 1)], clipTo: body)

let image = ctx.makeImage()!
let url = URL(fileURLWithPath: output)
try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
try NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])!.write(to: url)
print("wrote \(output)")
