import AppKit

/// AppKit flattens ICNS representations when installing a Dock icon. Compare
/// rendered pixels, not TIFF containers or representation metadata.
@MainActor func matchingIconPixels(_ actual: NSImage, _ expected: NSImage) -> Bool {
    func pixels(_ image: NSImage) -> [Double]? {
        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: 64, pixelsHigh: 64,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
            isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
        ), let context = NSGraphicsContext(bitmapImageRep: bitmap) else { return nil }
        NSGraphicsContext.saveGraphicsState()
        defer { NSGraphicsContext.restoreGraphicsState() }
        NSGraphicsContext.current = context
        context.cgContext.clear(CGRect(x: 0, y: 0, width: 64, height: 64))
        image.draw(in: NSRect(x: 0, y: 0, width: 64, height: 64))
        var result = [Double]()
        for y in 0..<64 {
            for x in 0..<64 {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { return nil }
                let alpha = color.alphaComponent
                result += [color.redComponent * alpha, color.greenComponent * alpha,
                           color.blueComponent * alpha, alpha]
            }
        }
        return result
    }
    guard let a = pixels(actual), let b = pixels(expected) else { return false }
    // Allow minor resampling differences between native icon representations.
    return zip(a, b).reduce(0.0) { $0 + abs($1.0 - $1.1) } / Double(a.count) < 0.02
}
