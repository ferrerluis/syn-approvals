import Foundation
import ServiceManagement

@MainActor
protocol LoginItemManaging {
    var enabled: Bool { get }
    func setEnabled(_ enabled: Bool) throws
}

@MainActor
struct SystemLoginItem: LoginItemManaging {
    var enabled: Bool { SMAppService.mainApp.status == .enabled }

    func setEnabled(_ enabled: Bool) throws {
        if enabled { try SMAppService.mainApp.register() }
        else { try SMAppService.mainApp.unregister() }
        guard self.enabled == enabled else {
            throw SynProtocolError.invalid("macOS has not enabled this login item. Check Login Items in System Settings.")
        }
    }
}

@MainActor
final class StartupPreference {
    private static let choiceKey = "syn.startupChoice.v1"
    private let defaults: UserDefaults
    private let service: any LoginItemManaging

    init(defaults: UserDefaults = .standard, service: any LoginItemManaging = SystemLoginItem()) {
        self.defaults = defaults
        self.service = service
    }

    var enabled: Bool { service.enabled }

    func shouldAsk(existingTargets: Bool) -> Bool {
        defaults.string(forKey: Self.choiceKey) == nil && !existingTargets && !service.enabled
    }

    func choose(_ enabled: Bool) throws {
        // Record consent only after the OS confirms the requested state.
        if service.enabled != enabled { try service.setEnabled(enabled) }
        defaults.set(enabled ? "yes" : "no", forKey: Self.choiceKey)
    }

    func dismiss() {
        // Dismissal remembers that the question was shown, never grants consent.
        if defaults.string(forKey: Self.choiceKey) == nil {
            defaults.set("dismissed", forKey: Self.choiceKey)
        }
    }
}
