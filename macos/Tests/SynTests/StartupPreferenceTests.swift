import Foundation
import Testing
@testable import Syn

@MainActor private final class FakeLoginItem: LoginItemManaging {
    var status: LoginItemRegistrationStatus = .notRegistered
    var reject = false
    var calls = 0
    func setEnabled(_ value: Bool) throws {
        calls += 1
        if reject { throw SynProtocolError.invalid("test registration failure") }
        status = value ? .enabled : .notRegistered
    }
}

private final class SilentNotifications: SynNotifying, @unchecked Sendable {
    var onReview: (@Sendable (String) -> Void)?
    var onDeny: (@Sendable (String) -> Void)?

    func configure() async throws {}
    func post(request: VerifiedApprovalRequest, targetName: String) async throws {}
    func remove(requestID: String) {}
}

@Test @MainActor func shippingModelWiresItsDefaultStartupPreference() throws {
    let defaults = UserDefaults.standard
    let choiceKey = "syn.startupChoice.v1"
    let previousChoice = defaults.object(forKey: choiceKey)
    defer {
        if let previousChoice { defaults.set(previousChoice, forKey: choiceKey) }
        else { defaults.removeObject(forKey: choiceKey) }
    }
    defaults.removeObject(forKey: choiceKey)

    // The SwiftPM test executable is not a registered login item, matching a
    // clean installation without touching the user's real Syn registration.
    #expect(!SystemLoginItem().status.isEnabled)
    let targetFile = FileManager.default.temporaryDirectory
        .appendingPathComponent("syn-startup-targets-\(UUID().uuidString).json")
    defer { try? FileManager.default.removeItem(at: targetFile) }

    let model = SynModel(
        targetStore: try TargetStore(fileURL: targetFile),
        notifications: SilentNotifications()
    )

    #expect(model.showStartupPrompt)
}

@Test @MainActor func startupChoicesPersistWithoutSystemChangesInTests() throws {
    for choice in ["yes", "no", "dismissed"] {
        let suite = "org.syn-approvals.tests.startup.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let service = FakeLoginItem()
        let settings = StartupPreference(defaults: defaults, service: service)
        #expect(settings.shouldAsk(existingTargets: false))
        if choice == "dismissed" { settings.dismiss() }
        else { try settings.choose(choice == "yes") }
        #expect(service.status.isEnabled == (choice == "yes"))
        let relaunched = StartupPreference(defaults: defaults, service: service)
        #expect(!relaunched.shouldAsk(existingTargets: false))
        #expect(service.calls == (choice == "yes" ? 1 : 0))
    }
}

@Test @MainActor func startupFailureDoesNotRecordConsentAndExistingSetupIsPreserved() throws {
    let suite = "org.syn-approvals.tests.startup.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let service = FakeLoginItem()
    let settings = StartupPreference(defaults: defaults, service: service)
    #expect(!settings.shouldAsk(existingTargets: true))
    service.reject = true
    #expect(throws: SynProtocolError.self) { try settings.choose(true) }
    #expect(settings.shouldAsk(existingTargets: false))
    service.status = .enabled
    #expect(!settings.shouldAsk(existingTargets: false))
}

@Test @MainActor func startupNoUnregistersAnApprovalPendingLoginItem() throws {
    let suite = "org.syn-approvals.tests.startup.pending.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let service = FakeLoginItem()
    service.status = .requiresApproval
    let settings = StartupPreference(defaults: defaults, service: service)

    #expect(settings.shouldAsk(existingTargets: false))
    try settings.choose(false)

    #expect(service.calls == 1)
    #expect(service.status == .notRegistered)
    #expect(defaults.string(forKey: "syn.startupChoice.v1") == "no")
}

@Test @MainActor func systemLoginItemPreservesMacOSRegistrationStatuses() {
    #expect(SystemLoginItem.registrationStatus(for: .notRegistered) == .notRegistered)
    #expect(SystemLoginItem.registrationStatus(for: .enabled) == .enabled)
    #expect(SystemLoginItem.registrationStatus(for: .requiresApproval) == .requiresApproval)
    #expect(SystemLoginItem.registrationStatus(for: .notFound) == .notFound)
}
