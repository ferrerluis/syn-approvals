import AppKit
import SwiftUI

/// Local, bundled artwork only. Never load an image supplied by a target.
@MainActor enum SynBranding {
  static let lightLogo = load("syn-app-icon-light", extension: "png")
  static let darkLogo = load("syn-app-icon-dark", extension: "png")
  static let idleMenuLogo = load("syn-menu-icon-idle", extension: "png")
  static let pendingMenuLogo = load("syn-menu-icon", extension: "svg")
  static let idleMenuIcon = makeIdleMenuIcon()
  static let pendingMenuIcon = makePendingMenuIcon()

  static func logo(for colorScheme: ColorScheme) -> NSImage {
    colorScheme == .dark ? darkLogo : lightLogo
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

  private static func makeIdleMenuIcon() -> NSImage {
    let canvas = CGFloat(18)
    let pendingScale = min(
      canvas / pendingMenuLogo.size.width,
      canvas / pendingMenuLogo.size.height
    )
    let pendingWidth = pendingMenuLogo.size.width * pendingScale
    let size = NSSize(
      width: idleMenuLogo.size.width * pendingScale,
      height: idleMenuLogo.size.height * pendingScale
    )
    let origin = NSPoint(x: (canvas - pendingWidth) / 2, y: 0)
    return templateMenuIcon(
      drawing: idleMenuLogo,
      in: NSRect(origin: origin, size: size),
      accessibilityDescription: "Syn"
    )
  }

  private static func makePendingMenuIcon() -> NSImage {
    let canvas = CGFloat(18)
    let scale = min(canvas / pendingMenuLogo.size.width, canvas / pendingMenuLogo.size.height)
    let size = NSSize(
      width: pendingMenuLogo.size.width * scale,
      height: pendingMenuLogo.size.height * scale
    )
    let origin = NSPoint(x: (canvas - size.width) / 2, y: (canvas - size.height) / 2)
    return templateMenuIcon(
      drawing: pendingMenuLogo,
      in: NSRect(origin: origin, size: size),
      accessibilityDescription: "Syn, approval pending"
    )
  }

  private static func templateMenuIcon(
    drawing logo: NSImage,
    in rect: NSRect,
    accessibilityDescription: String
  ) -> NSImage {
    let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { _ in
      logo.draw(in: rect)
      return true
    }
    // AppKit supplies light/dark/highlight contrast from this black mask.
    image.isTemplate = true
    image.accessibilityDescription = accessibilityDescription
    return image
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
