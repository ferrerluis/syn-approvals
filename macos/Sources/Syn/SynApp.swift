import SwiftUI

@main
struct SynApp: App {
    @NSApplicationDelegateAdaptor(SynAppDelegate.self) private var appDelegate
    @StateObject private var model = SynModel()

    var body: some Scene {
        Window("Syn", id: "main") {
            SynContentView(model: model)
        }
        .defaultSize(width: 960, height: 680)
        .defaultLaunchBehavior(.presented)

        MenuBarExtra {
            SynMenuView(model: model)
        } label: {
            Image(nsImage: model.pending.isEmpty ? SynBranding.idleMenuIcon : SynBranding.pendingMenuIcon)
                .accessibilityLabel(model.pending.isEmpty ? "Syn" : "Syn, \(model.pending.count) approvals pending")
        }
        .menuBarExtraStyle(.menu)
    }
}
