import AppKit
import SwiftUI

/// Local, bundled artwork only. Never load an image supplied by a target.
@MainActor enum SynBranding {
  static let lightLogo = load("syn-app-icon-light", extension: "png")
  static let darkLogo = load("syn-app-icon-dark", extension: "png")
  static let menuBarLogo = load("syn-menu-icon", extension: "svg")
  static let idleMenuIcon = makeMenuIcon(hasPending: false)
  static let pendingMenuIcon = makeMenuIcon(hasPending: true)

  static func logo(for colorScheme: ColorScheme) -> NSImage {
    colorScheme == .dark ? darkLogo : lightLogo
  }

  static func applicationIcon(
    for appearance: NSAppearance = NSApplication.shared.effectiveAppearance
  ) -> NSImage {
    let usesDarkIcon = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
    let resource = usesDarkIcon ? "Syn-dark" : "Syn"
    if let url = Bundle.main.url(forResource: resource, withExtension: "icns"),
      let image = NSImage(contentsOf: url), image.isValid
    {
      return image
    }
    return usesDarkIcon ? darkLogo : lightLogo
  }

  static func installApplicationIcon(
    for appearance: NSAppearance = NSApplication.shared.effectiveAppearance
  ) {
    // Explicitly set the running Dock tile, even when Launch Services has
    // retained a generic icon from an earlier in-place installation.
    NSApplication.shared.applicationIconImage = applicationIcon(for: appearance)
  }

  static func resourceURL(_ name: String, extension fileExtension: String) -> URL? {
    if Bundle.main.bundleURL.pathExtension == "app" {
      // SwiftPM's accessor looks beside Contents, then in the build tree,
      // and traps if neither exists. Installed apps must use only their
      // own resources, returning nil so missing artwork can fall back.
      guard let resources = Bundle.main.resourceURL,
        let bundle = Bundle(url: resources.appendingPathComponent("Syn_Syn.bundle"))
      else {
        return nil
      }
      return bundle.url(forResource: name, withExtension: fileExtension)
    }
    // swift run / swift test use SwiftPM's unbundled executable layout.
    return Bundle.module.url(forResource: name, withExtension: fileExtension)
  }

  private static func load(_ name: String, extension fileExtension: String) -> NSImage {
    guard let url = resourceURL(name, extension: fileExtension),
      let image = NSImage(contentsOf: url)
    else {
      // A packaging error must not crash the approver or grant authority.
      return NSImage(systemSymbolName: "checkmark.shield", accessibilityDescription: "Syn")
        ?? NSImage()
    }
    return image
  }

  private static func makeMenuIcon(hasPending: Bool) -> NSImage {
    let logo = menuBarLogo
    let image = NSImage(size: NSSize(width: hasPending ? 24 : 18, height: 18), flipped: false) {
      _ in
      let scale = min(18 / logo.size.width, 18 / logo.size.height)
      let size = NSSize(width: logo.size.width * scale, height: logo.size.height * scale)
      let origin = NSPoint(x: (18 - size.width) / 2, y: (18 - size.height) / 2)
      logo.draw(in: NSRect(origin: origin, size: size))
      if hasPending {
        NSColor.black.setFill()
        NSBezierPath(ovalIn: NSRect(x: 20, y: 1, width: 3, height: 3)).fill()
      }
      return true
    }
    // AppKit supplies light/dark/highlight contrast from this black mask.
    image.isTemplate = true
    image.accessibilityDescription = hasPending ? "Syn, approval pending" : "Syn"
    return image
  }
}

@MainActor final class SynAppDelegate: NSObject, NSApplicationDelegate {
  private var appearanceObservation: NSKeyValueObservation?

  func applicationDidFinishLaunching(_ notification: Notification) {
    SynBranding.installApplicationIcon()
    appearanceObservation = NSApplication.shared.observe(\.effectiveAppearance, options: [.new]) {
      _, _ in
      Task { @MainActor in
        SynBranding.installApplicationIcon()
      }
    }
  }
}

struct SynLogo: View {
  var size: CGFloat = 32
  @Environment(\.colorScheme) private var colorScheme

  var body: some View {
    Image(nsImage: SynBranding.logo(for: colorScheme))
      .resizable()
      .interpolation(.high)
      .scaledToFit()
      .frame(width: size, height: size)
      .accessibilityHidden(true)
  }
}

struct SynBrandHeader: View {
  var body: some View {
    HStack(spacing: 10) {
      SynLogo(size: 32)
      VStack(alignment: .leading, spacing: 2) {
        Text("Syn").font(.title2.bold())
        Text("Remote approvals").font(.caption).foregroundStyle(.secondary)
      }
      Spacer(minLength: 0)
    }
    .padding(16)
    .accessibilityElement(children: .combine)
  }
}
