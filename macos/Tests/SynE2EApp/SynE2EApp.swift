import Darwin
import SwiftUI

private final class E2ENotifications: SynNotifying, @unchecked Sendable {
    var onReview: (@Sendable (String) -> Void)?
    var onDeny: (@Sendable (String) -> Void)?
    func configure() async throws {}
    func post(request: VerifiedApprovalRequest, targetName: String) async throws {}
    func remove(requestID: String) {}
}

@MainActor
private final class E2ELoginItem: LoginItemManaging {
    var enabled = false
    func setEnabled(_ enabled: Bool) throws { self.enabled = enabled }
}

@MainActor
private final class E2EPreferences: StartupPreferenceStoring {
    private var values: [String: Any] = [:]
    func string(forKey defaultName: String) -> String? { values[defaultName] as? String }
    func set(_ value: Any?, forKey defaultName: String) { values[defaultName] = value }
}

final class SynE2EAppDelegate: NSObject, NSApplicationDelegate {
    private var keys: E2EDisposableKeyStore?
    private var inbox: E2EGrantInbox?
    private var stateDirectory: URL?

    func own(
        _ keys: E2EDisposableKeyStore, inbox: E2EGrantInbox,
        stateDirectory: URL
    ) {
        self.keys = keys; self.inbox = inbox
        self.stateDirectory = stateDirectory
    }

    func applicationWillTerminate(_ notification: Notification) {
        try? keys?.cleanup()
        inbox?.cleanupOwnedFiles()
        if let stateDirectory { _ = rmdir(stateDirectory.path) }
        keys = nil
        inbox = nil
        stateDirectory = nil
    }
}

@main
struct SynE2EApp: App {
    @NSApplicationDelegateAdaptor(SynE2EAppDelegate.self) private var appDelegate
    @StateObject private var model: SynModel

    init() {
        let environment = ProcessInfo.processInfo.environment
        guard let rootPath = environment["SYN_E2E_PROFILE_ROOT"],
              let profileID = environment["SYN_E2E_PROFILE_ID"] else {
            fatalError("SynE2E requires an explicit disposable profile root and profile identifier")
        }
        var createdKeys: E2EDisposableKeyStore?
        do {
            let root = URL(fileURLWithPath: rootPath, isDirectory: true)
            let keys = try E2EDisposableKeyStore(
                rootDirectory: root, profileID: profileID
            )
            createdKeys = keys
            let inbox = try E2EGrantInbox(directory: root, profileID: profileID)
            let state = root.appendingPathComponent(profileID + ".state", isDirectory: true)
            try FileManager.default.createDirectory(at: state, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: state.path)
            let defaults = E2EPreferences()
            let provider = E2EScenarioSigningProvider(inbox: inbox, keys: keys)
            let knownHosts = try SynKnownHostsStore(fileURL: state.appendingPathComponent("known_hosts"))
            let targets = try TargetStore(fileURL: state.appendingPathComponent("targets.json"))
            _model = StateObject(wrappedValue: SynModel(
                startServices: true,
                signingProvider: provider,
                knownHostsStore: knownHosts,
                targetStore: targets,
                startupPreference: StartupPreference(defaults: defaults, service: E2ELoginItem()),
                notifications: E2ENotifications(),
                transportIdentityStore: TransportIdentityStore(labelPrefix: "SynE2E \(profileID)"),
                verifiedRequestObserver: { try inbox.publish($0) }
            ))
            appDelegate.own(
                keys, inbox: inbox, stateDirectory: state
            )
        } catch {
            try? createdKeys?.cleanup()
            fatalError("SynE2E could not open its isolated test profile")
        }
    }

    var body: some Scene {
        Window("Syn E2E", id: "main") { SynContentView(model: model) }
            .defaultSize(width: 960, height: 680)
    }
}
