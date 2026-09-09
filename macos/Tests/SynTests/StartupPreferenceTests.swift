import Foundation
import Testing
@testable import Syn

@MainActor private final class FakeLoginItem: LoginItemManaging {
    var enabled = false
    var reject = false
    var calls = 0
    func setEnabled(_ value: Bool) throws {
        calls += 1
        if reject { throw SynProtocolError.invalid("test registration failure") }
        enabled = value
    }
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
        #expect(service.enabled == (choice == "yes"))
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
    service.enabled = true
    #expect(!settings.shouldAsk(existingTargets: false))
}
