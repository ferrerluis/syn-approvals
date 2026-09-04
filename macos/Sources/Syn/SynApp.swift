import SwiftUI

@main
struct SynApp: App {
    @StateObject private var model = SynModel()

    var body: some Scene {
        MenuBarExtra("Syn", systemImage: model.pending.isEmpty ? "checkmark.shield" : "exclamationmark.shield") {
            SynMenuView(model: model)
        }
        .menuBarExtraStyle(.menu)

        WindowGroup("Syn", id: "main") {
            SynContentView(model: model)
        }
        .defaultSize(width: 960, height: 680)
    }
}
