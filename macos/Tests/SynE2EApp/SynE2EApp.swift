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
    private var state: E2EProfileState?
    private var finalCleanup = false

    func own(
        _ keys: E2EDisposableKeyStore, inbox: E2EGrantInbox,
        state: E2EProfileState, finalCleanup: Bool
    ) {
        self.keys = keys; self.inbox = inbox
        self.state = state; self.finalCleanup = finalCleanup
    }

    func applicationWillTerminate(_ notification: Notification) {
        if finalCleanup {
            do { try state?.cleanup(); try inbox?.cleanupOwnedFiles(requireRemoval: true); try keys?.cleanup() }
            catch { fatalError("SynE2E could not clean its exact isolated test profile") }
        }
        keys = nil
        inbox = nil
        state = nil
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
        do {
            let root = URL(fileURLWithPath: rootPath, isDirectory: true)
            let keys = try E2EDisposableKeyStore(
                rootDirectory: root, profileID: profileID
            )
            let inbox = try E2EGrantInbox(directory: root, profileID: profileID)
            let state = try E2EProfileState(rootDirectory: root, profileID: profileID)
            let defaults = E2EPreferences()
            let provider = E2EScenarioSigningProvider(inbox: inbox, keys: keys)
            let knownHosts = try SynKnownHostsStore(fileURL: state.directory.appendingPathComponent("known_hosts"))
            let targets = try TargetStore(fileURL: state.directory.appendingPathComponent("targets.json"))
            _model = StateObject(wrappedValue: SynModel(
                startServices: true,
                signingProvider: provider,
                knownHostsStore: knownHosts,
                targetStore: targets,
                startupPreference: StartupPreference(defaults: defaults, service: E2ELoginItem()),
                notifications: E2ENotifications(),
                transportIdentityStore: TransportIdentityStore(),
                verifiedRequestObserver: { try inbox.publish($0) }
            ))
            appDelegate.own(
                keys, inbox: inbox, state: state,
                finalCleanup: environment["SYN_E2E_FINAL_CLEANUP"] == "1"
            )
        } catch {
            fatalError("SynE2E could not open its isolated test profile")
        }
    }

    var body: some Scene {
        Window("Syn E2E", id: "main") { SynContentView(model: model) }
            .defaultSize(width: 960, height: 680)
    }
}
