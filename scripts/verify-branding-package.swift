// Compiled with the real Branding.swift in a relocated probe app. No SynModel,
// authentication, transport, or application entry point is linked or launched.
import AppKit
import Foundation

@main
enum BrandingPackageProbe {
  static func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("Branding verification failed: \(message)\n".utf8))
    exit(EXIT_FAILURE)
  }

  @MainActor static func main() {
    do { try verify() } catch { fail(String(describing: error)) }
  }

  @MainActor static func verify() throws {
    let app = Bundle.main.bundleURL
    guard app.pathExtension == "app" else {
      fail("Probe must run inside a relocated app bundle")
    }
    let resources = app.appendingPathComponent("Contents/Resources")
    let bundleURL = resources.appendingPathComponent("Syn_Syn.bundle")
    let expected = Set([
      "syn-app-icon-light.png", "syn-app-icon-dark.png", "syn-menu-icon-idle.png",
      "syn-menu-icon.svg",
    ])
    if CommandLine.arguments.dropFirst() == ["--expect-missing"] {
      for name in expected {
        let path = name as NSString
        guard
          SynBranding.resourceURL(path.deletingPathExtension, extension: path.pathExtension) == nil
        else {
          fail("Missing packaged artwork must not fall back to build-tree resources")
        }
      }
      guard SynBranding.lightLogo.isValid, SynBranding.darkLogo.isValid,
        SynBranding.idleMenuLogo.isValid, SynBranding.pendingMenuLogo.isValid,
        SynBranding.idleMenuIcon.isTemplate, SynBranding.pendingMenuIcon.isTemplate
      else {
        fail("Missing artwork did not safely fall back")
      }
      print("Missing artwork verified: no trap or build-tree fallback.")
      return
    }
    guard CommandLine.arguments.count == 1 else { fail("Unexpected probe arguments") }
    guard Set(try FileManager.default.contentsOfDirectory(atPath: bundleURL.path)) == expected
    else {
      fail("Missing or unexpected packaged branding resources")
    }
    for name in expected {
      let path = name as NSString
      guard
        let url = SynBranding.resourceURL(
          path.deletingPathExtension, extension: path.pathExtension),
        url.standardizedFileURL == bundleURL.appendingPathComponent(name).standardizedFileURL,
        let image = NSImage(contentsOf: url), image.isValid
      else {
        fail("Packaged branding resource cannot be decoded")
      }
    }
    let info =
      try PropertyListSerialization.propertyList(
        from: Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")), format: nil
      ) as? [String: Any]
    guard info?["CFBundleIconFile"] as? String == "Syn",
      info?["CFBundleIconName"] as? String == "Syn",
      let icon = NSImage(contentsOf: resources.appendingPathComponent("Syn.icns")),
      icon.isValid,
      FileManager.default.fileExists(atPath: resources.appendingPathComponent("Assets.car").path)
    else {
      fail("Packaged app icon is missing or not registered")
    }
    let sizes = Set(icon.representations.map(\.pixelsWide))
    guard Set([16, 32, 128, 256]).isSubset(of: sizes) else {
      fail("Packaged compatibility icon is missing native pixel sizes")
    }
    print("Branding package verified: four artwork resources and compiled Icon Composer assets.")
  }
}
