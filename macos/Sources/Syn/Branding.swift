import AppKit
import SwiftUI

/// Local, bundled artwork only. Never load an image supplied by a target.
@MainActor enum SynBranding {
    // AppKit misrenders the color SVG's embedded texture. The supplied 423px
    // PNG preserves it faithfully and exceeds the UI's 36pt @2x requirement.
    static let colorLogo = load("syn-logo-color", extension: "png")
    static let blackLogo = load("syn-logo-black", extension: "svg")
    static let idleMenuIcon = makeMenuIcon(hasPending: false)
    static let pendingMenuIcon = makeMenuIcon(hasPending: true)

    static func resourceURL(_ name: String, extension fileExtension: String) -> URL? {
        if Bundle.main.bundleURL.pathExtension == "app" {
            // SwiftPM's accessor looks beside Contents, then in the build tree,
            // and traps if neither exists. Installed apps must use only their
            // own resources, returning nil so missing artwork can fall back.
            guard let resources = Bundle.main.resourceURL,
                  let bundle = Bundle(url: resources.appendingPathComponent("Syn_Syn.bundle")) else {
                return nil
            }
            return bundle.url(forResource: name, withExtension: fileExtension)
        }
        // swift run / swift test use SwiftPM's unbundled executable layout.
        return Bundle.module.url(forResource: name, withExtension: fileExtension)
    }

    private static func load(_ name: String, extension fileExtension: String) -> NSImage {
        guard let url = resourceURL(name, extension: fileExtension), let image = NSImage(contentsOf: url) else {
            // A packaging error must not crash the approver or grant authority.
            return NSImage(systemSymbolName: "checkmark.shield", accessibilityDescription: "Syn") ?? NSImage()
        }
        return image
    }

    private static func makeMenuIcon(hasPending: Bool) -> NSImage {
        let logo = blackLogo
        let image = NSImage(size: NSSize(width: hasPending ? 24 : 18, height: 18), flipped: false) { _ in
            logo.draw(in: NSRect(x: 0, y: 0, width: 18, height: 18))
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

struct SynLogo: View {
    var size: CGFloat = 32

    var body: some View {
        Image(nsImage: SynBranding.colorLogo)
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
