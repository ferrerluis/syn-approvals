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
    let expected = Set(["syn-app-icon-light.png", "syn-app-icon-dark.png", "syn-menu-icon.svg"])
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
        SynBranding.menuBarLogo.isValid,
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
      let lightIcon = NSImage(contentsOf: resources.appendingPathComponent("Syn.icns")),
      lightIcon.isValid,
      let darkIcon = NSImage(contentsOf: resources.appendingPathComponent("Syn-dark.icns")),
      darkIcon.isValid
    else {
      fail("Packaged app icon is missing or not registered")
    }
    for icon in [lightIcon, darkIcon] {
      let sizes = Set(icon.representations.map(\.pixelsWide))
      guard Set([16, 32, 64, 128, 256, 512, 1024]).isSubset(of: sizes) else {
        fail("Packaged app icon is missing native pixel sizes")
      }
    }
    guard
      let aqua = NSAppearance(named: .aqua),
      let darkAqua = NSAppearance(named: .darkAqua),
      matchingIconPixels(SynBranding.applicationIcon(for: aqua), lightIcon),
      matchingIconPixels(SynBranding.applicationIcon(for: darkAqua), darkIcon),
      !matchingIconPixels(lightIcon, darkIcon)
    else {
      fail("Light and dark app-icon variants are missing or incorrectly mapped")
    }
    SynAppDelegate().applicationDidFinishLaunching(
      Notification(name: NSApplication.didFinishLaunchingNotification)
    )
    guard let installed = NSApplication.shared.applicationIconImage,
      installed.isValid, !installed.isTemplate,
      matchingIconPixels(installed, SynBranding.applicationIcon())
    else {
      fail("Launch delegate did not install the packaged color Dock icon")
    }
    print("Branding package verified: three artwork resources and light/dark 16–1024px app icons.")
  }
}
