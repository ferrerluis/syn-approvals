import AppKit
import SwiftUI
import Testing
@testable import Syn

@MainActor @Test func bundledLogosMatchCanonicalOriginalsAndDecode() throws {
    let repo = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    for (name, directory, fileExtension) in [("syn-logo-color", "color", "png"), ("syn-logo-black", "monochrome", "svg")] {
        let bundled = try #require(SynBranding.resourceURL(name, extension: fileExtension))
        let original = repo.appendingPathComponent("assets/branding/\(directory)/\(name).\(fileExtension)")
        #expect(try Data(contentsOf: bundled) == Data(contentsOf: original))
        let image = try #require(NSImage(contentsOf: bundled))
        #expect(image.isValid)
        #expect(image.size.width > 0 && image.size.width == image.size.height)
    }
}

@MainActor @Test func menuBrandingKeepsTemplateContrastAndPendingIndicator() {
    #expect(SynBranding.idleMenuIcon.isTemplate)
    #expect(SynBranding.pendingMenuIcon.isTemplate)
    #expect(SynBranding.idleMenuIcon.size == NSSize(width: 18, height: 18))
    #expect(SynBranding.pendingMenuIcon.size == NSSize(width: 24, height: 18))
    #expect(SynBranding.pendingMenuIcon.accessibilityDescription?.contains("pending") == true)
}

@MainActor @Test func launchDelegateInstallsColorDockIcon() throws {
    let app = NSApplication.shared
    let previous = app.applicationIconImage
    defer { app.applicationIconImage = previous }
    SynAppDelegate().applicationDidFinishLaunching(
        Notification(name: NSApplication.didFinishLaunchingNotification)
    )
    let installed = try #require(app.applicationIconImage)
    #expect(installed.isValid)
    #expect(!installed.isTemplate)
    #expect(matchingIconPixels(installed, SynBranding.applicationIcon))
    // A generic placeholder, blank icon, or monochrome mark must not pass.
    #expect(!matchingIconPixels(NSImage(size: NSSize(width: 64, height: 64)), SynBranding.applicationIcon))
    #expect(!matchingIconPixels(SynBranding.blackLogo, SynBranding.applicationIcon))
    let placeholder = try #require(NSImage(systemSymbolName: "app", accessibilityDescription: nil))
    #expect(!matchingIconPixels(placeholder, SynBranding.applicationIcon))
}

@MainActor @Test func logosRenderWithTransparencyAndColor() throws {
    for (image, expectColor) in [(SynBranding.colorLogo, true), (SynBranding.blackLogo, false)] {
        let renderer = ImageRenderer(content: Image(nsImage: image).resizable().frame(width: 64, height: 64))
        let rendered = try #require(renderer.cgImage)
        let bitmap = NSBitmapImageRep(cgImage: rendered)
        #expect(try #require(bitmap.colorAt(x: 0, y: 0)).alphaComponent == 0)
        var opaquePixels = 0
        var coloredPixels = 0
        for y in 0..<bitmap.pixelsHigh {
            for x in 0..<bitmap.pixelsWide {
                let pixel = try #require(bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB))
                if pixel.alphaComponent > 0.9 {
                    opaquePixels += 1
                    if abs(pixel.redComponent - pixel.blueComponent) > 0.02 { coloredPixels += 1 }
                }
            }
        }
        #expect(opaquePixels > 500)
        #expect(expectColor ? coloredPixels > 500 : coloredPixels == 0)
    }
}

/// Optional visual proof of actual branding views, with no model, key or network access.
@MainActor @Test func brandingPreviewInBothAppearances() throws {
    for appearance in [ColorScheme.light, .dark] {
        let content = VStack(alignment: .leading, spacing: 20) {
            SynBrandHeader()
            HStack(spacing: 24) {
                SynLogo(size: 128)
                VStack(alignment: .leading, spacing: 16) {
                    Text("Menu bar").font(.headline)
                    HStack(spacing: 24) {
                        Image(nsImage: SynBranding.idleMenuIcon)
                        Image(nsImage: SynBranding.pendingMenuIcon)
                    }
                    Text("Idle / approval pending").font(.caption).foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 16)
        }
        .padding(20)
        .frame(width: 420)
        .background(appearance == .dark ? Color(white: 0.12) : .white)
        .environment(\.colorScheme, appearance)
        let renderer = ImageRenderer(content: content)
        renderer.scale = 2
        let image = try #require(renderer.cgImage)
        if let directory = ProcessInfo.processInfo.environment["SYN_BRANDING_PREVIEW_DIR"] {
            let bitmap = NSBitmapImageRep(cgImage: image)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            let name = appearance == .dark ? "branding-dark.png" : "branding-light.png"
            try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent(name))
        }
    }
}
