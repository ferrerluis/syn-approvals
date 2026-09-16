import Foundation
import ServiceManagement

enum LoginItemRegistrationStatus: Equatable {
    case notRegistered
    case enabled
    case requiresApproval
    case notFound
    case unknown

    var isEnabled: Bool { self == .enabled }

    var registrationExists: Bool? {
        switch self {
        case .enabled, .requiresApproval: true
        case .notRegistered, .notFound: false
        case .unknown: nil
        }
    }
}

@MainActor
protocol LoginItemManaging {
    var status: LoginItemRegistrationStatus { get }
    func setEnabled(_ enabled: Bool) throws
}

@MainActor
protocol StartupPreferenceStoring {
    func string(forKey defaultName: String) -> String?
    func set(_ value: Any?, forKey defaultName: String)
}

extension UserDefaults: StartupPreferenceStoring {}

@MainActor
struct SystemLoginItem: LoginItemManaging {
    var status: LoginItemRegistrationStatus {
        Self.registrationStatus(for: SMAppService.mainApp.status)
    }

    static func registrationStatus(for status: SMAppService.Status) -> LoginItemRegistrationStatus {
        switch status {
        case .notRegistered: .notRegistered
        case .enabled: .enabled
        case .requiresApproval: .requiresApproval
        case .notFound: .notFound
        @unknown default: .unknown
        }
    }

    func setEnabled(_ enabled: Bool) throws {
        if enabled { try SMAppService.mainApp.register() }
        else { try SMAppService.mainApp.unregister() }
        if enabled {
            guard status == .enabled else {
                throw SynProtocolError.invalid("macOS has not enabled this login item. Check Login Items in System Settings.")
            }
        } else {
            guard status.registrationExists == false else {
                throw SynProtocolError.invalid("macOS has not disabled this login item. Check Login Items in System Settings.")
            }
        }
    }
}

@MainActor
final class StartupPreference {
    private static let choiceKey = "syn.startupChoice.v1"
    private let defaults: any StartupPreferenceStoring
    private let service: any LoginItemManaging

    init(defaults: any StartupPreferenceStoring = UserDefaults.standard, service: any LoginItemManaging = SystemLoginItem()) {
        self.defaults = defaults
        self.service = service
    }

    var enabled: Bool { service.status.isEnabled }

    func shouldAsk(existingTargets: Bool) -> Bool {
        defaults.string(forKey: Self.choiceKey) == nil && !existingTargets && !service.status.isEnabled
    }

    func choose(_ enabled: Bool) throws {
        // Record consent only after the OS confirms the requested state.
        if enabled {
            if !service.status.isEnabled { try service.setEnabled(true) }
        } else {
            switch service.status.registrationExists {
            case true: try service.setEnabled(false)
            case false: break
            case nil:
                throw SynProtocolError.invalid("macOS returned an unknown login item status.")
            }
        }
        defaults.set(enabled ? "yes" : "no", forKey: Self.choiceKey)
    }

    func dismiss() {
        // Dismissal remembers that the question was shown, never grants consent.
        if defaults.string(forKey: Self.choiceKey) == nil {
            defaults.set("dismissed", forKey: Self.choiceKey)
        }
    }
}
