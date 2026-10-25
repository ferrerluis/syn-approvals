import Foundation

/// Only these fixed messages may cross from SSH diagnostics into the update UI.
/// Progress is informational; the coordinator still verifies the final reply.
enum SetupDiagnosticEvent: String, CaseIterable, Sendable {
    case checkingDependencies = "checking_dependencies"
    case installingDependencies = "installing_dependencies"
    case extractingSource = "extracting_source"
    case compilingPackage = "compiling_package"
    case verifyingPackage = "verifying_package"
    case packageReady = "package_ready"

    var message: String {
        switch self {
        case .checkingDependencies: "Checking build tools on the machine"
        case .installingDependencies: "Installing required build tools"
        case .extractingSource: "Unpacking verified source"
        case .compilingPackage: "Compiling and packaging Syn on the machine"
        case .verifyingPackage: "Checking the built package"
        case .packageReady: "Verified package ready to install"
        }
    }
}

/// Bounded, byte-exact line parsing. Unknown text is never rendered or retained.
struct SetupDiagnosticParser {
    private var line = Data()
    private var droppingLine = false

    mutating func consume(_ bytes: Data) -> [SetupDiagnosticEvent] {
        var events: [SetupDiagnosticEvent] = []
        for byte in bytes {
            if byte == 10 {
                if !droppingLine,
                   let event = SetupDiagnosticEvent.allCases.first(where: {
                       line == Data("SYN_SETUP_EVENT_V1 \($0.rawValue)".utf8)
                   }) { events.append(event) }
                line.removeAll(keepingCapacity: true)
                droppingLine = false
            } else if line.count < 96, !droppingLine {
                line.append(byte)
            } else {
                line.removeAll(keepingCapacity: true)
                droppingLine = true
            }
        }
        return events
    }
}

struct SetupActivity: Equatable {
    struct Entry: Identifiable, Equatable {
        let id: Int
        let elapsed: String
        let message: String
    }
    enum Outcome { case completed, failed, cancelled, needsMaintenance }

    let startedAt: Date
    private(set) var finishedAt: Date?
    private(set) var entries: [Entry] = []
    private var nextID = 0

    init(now: Date = .now) { startedAt = now }

    func elapsed(at now: Date) -> String {
        let seconds = max(0, Int((finishedAt ?? now).timeIntervalSince(startedAt)))
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    mutating func record(_ phase: RemoteOnboardingProgress, now: Date = .now) {
        append(phase.rawValue, now: now)
    }

    mutating func record(_ event: SetupDiagnosticEvent, now: Date = .now) {
        append(event.message, now: now)
    }

    mutating func finish(_ outcome: Outcome, now: Date = .now) {
        guard finishedAt == nil else { return }
        let message: String
        switch outcome {
        case .completed: message = "Update completed and verified"
        case .failed: message = "Setup stopped; review the error above"
        case .cancelled: message = "Setup cancelled"
        case .needsMaintenance: message = "Waiting for maintenance access"
        }
        append(message, now: now)
        finishedAt = now
    }

    private mutating func append(_ message: String, now: Date) {
        guard finishedAt == nil, entries.last?.message != message else { return }
        entries.append(Entry(id: nextID, elapsed: elapsed(at: now), message: message))
        nextID += 1
        if entries.count > 64 { entries.removeFirst(entries.count - 64) }
    }
}
