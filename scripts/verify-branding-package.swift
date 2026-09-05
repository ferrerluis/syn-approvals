// Read-only verification; never launches the packaged app or its services.
import AppKit
import Foundation

guard CommandLine.arguments.count == 2 else { fatalError("Usage: verify-branding-package.swift Syn.app") }
let app = URL(fileURLWithPath: CommandLine.arguments[1])
let resources = app.appendingPathComponent("Contents/Resources")
let bundleURL = resources.appendingPathComponent("Syn_Syn.bundle")
let expected = Set(["syn-logo-color.png", "syn-logo-black.svg"])
guard let bundle = Bundle(url: bundleURL),
      Set(try FileManager.default.contentsOfDirectory(atPath: bundleURL.path)) == expected else {
    fatalError("Missing or unexpected packaged branding resources")
}
for name in expected {
    let path = name as NSString
    guard let url = bundle.url(forResource: path.deletingPathExtension, withExtension: path.pathExtension),
          let image = NSImage(contentsOf: url), image.isValid else {
        fatalError("Packaged branding resource cannot be decoded")
    }
}
let info = try PropertyListSerialization.propertyList(
    from: Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")), format: nil
) as? [String: Any]
guard info?["CFBundleIconFile"] as? String == "Syn",
      let icon = NSImage(contentsOf: resources.appendingPathComponent("Syn.icns")), icon.isValid else {
    fatalError("Packaged app icon is missing or not registered")
}
let sizes = Set(icon.representations.map(\.pixelsWide))
guard Set([16, 32, 64, 128, 256, 512, 1024]).isSubset(of: sizes) else {
    fatalError("Packaged app icon is missing native pixel sizes")
}
print("Branding package verified: two artwork resources and native 16–1024px app icons.")
