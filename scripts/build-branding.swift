// Deterministic format/size conversion of the supplied logo, not new artwork.
import AppKit
import Foundation

guard CommandLine.arguments.count == 3 else {
    fatalError("Usage: build-branding.swift COLOR_PNG OUTPUT.iconset")
}
let source = URL(fileURLWithPath: CommandLine.arguments[1])
let destination = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
guard let logo = NSImage(contentsOf: source), logo.isValid else {
    fatalError("Cannot decode the color logo")
}
guard logo.representations.contains(where: { $0.pixelsWide >= 1024 && $0.pixelsHigh >= 1024 }) else {
    fatalError("App icon source must have at least 1024 physical pixels per side")
}
try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = points * scale
        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
        ), let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
            fatalError("Cannot allocate app icon")
        }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        context.imageInterpolation = .high
        let canvas = NSRect(x: 0, y: 0, width: pixels, height: pixels)
        NSColor.clear.setFill()
        canvas.fill(using: .copy)
        // Preserve the transparent circular artwork, with consistent Dock padding.
        let inset = CGFloat(pixels) * 0.08
        logo.draw(in: canvas.insetBy(dx: inset, dy: inset))
        context.flushGraphics()
        NSGraphicsContext.restoreGraphicsState()
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            fatalError("Cannot encode app icon")
        }
        let suffix = scale == 2 ? "@2x" : ""
        try png.write(to: destination.appendingPathComponent("icon_\(points)x\(points)\(suffix).png"))
    }
}
