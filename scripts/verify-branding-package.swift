// Compiled with the real Branding.swift in a relocated probe app. No SynModel,
// authentication, transport, or application entry point is linked or launched.
import AppKit
import Foundation

@main
enum BrandingPackageProbe {
  @MainActor static func main() throws {
    let app = Bundle.main.bundleURL
    guard app.pathExtension == "app" else {
      fatalError("Probe must run inside a relocated app bundle")
    }
    let resources = app.appendingPathComponent("Contents/Resources")
    let bundleURL = resources.appendingPathComponent("Syn_Syn.bundle")
    let expected = Set(["syn-logo-color.png", "syn-logo-black.svg"])
    if CommandLine.arguments.dropFirst() == ["--expect-missing"] {
      for name in expected {
        let path = name as NSString
        guard
          SynBranding.resourceURL(path.deletingPathExtension, extension: path.pathExtension) == nil
        else {
          fatalError("Missing packaged artwork must not fall back to build-tree resources")
        }
      }
      guard SynBranding.colorLogo.isValid, SynBranding.blackLogo.isValid,
        SynBranding.idleMenuIcon.isTemplate, SynBranding.pendingMenuIcon.isTemplate
      else {
        fatalError("Missing artwork did not safely fall back")
      }
      print("Missing artwork verified: no trap or build-tree fallback.")
      return
    }
    guard CommandLine.arguments.count == 1 else { fatalError("Unexpected probe arguments") }
    guard Set(try FileManager.default.contentsOfDirectory(atPath: bundleURL.path)) == expected
    else {
      fatalError("Missing or unexpected packaged branding resources")
    }
    for name in expected {
      let path = name as NSString
      guard
        let url = SynBranding.resourceURL(
          path.deletingPathExtension, extension: path.pathExtension),
        url.standardizedFileURL == bundleURL.appendingPathComponent(name).standardizedFileURL,
        let image = NSImage(contentsOf: url), image.isValid
      else {
        fatalError("Packaged branding resource cannot be decoded")
      }
    }
    let info =
      try PropertyListSerialization.propertyList(
        from: Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")), format: nil
      ) as? [String: Any]
    guard info?["CFBundleIconFile"] as? String == "Syn",
      let icon = NSImage(contentsOf: resources.appendingPathComponent("Syn.icns")), icon.isValid
    else {
      fatalError("Packaged app icon is missing or not registered")
    }
    let sizes = Set(icon.representations.map(\.pixelsWide))
    guard Set([16, 32, 64, 128, 256, 512, 1024]).isSubset(of: sizes) else {
      fatalError("Packaged app icon is missing native pixel sizes")
    }
    print("Branding package verified: two artwork resources and native 16–1024px app icons.")
  }
}
