import Foundation

enum SSHProbeFailure: Error, Equatable, LocalizedError {
    case unavailable, authenticationNeeded, unknownHost, changedHostKey
    case timedOut, tooMuchOutput, invalidOutput, unsupportedPlatform

    var errorDescription: String? {
        switch self {
        case .unavailable: "SSH access could not be verified. Check the address, host identity and SSH credentials."
        case .authenticationNeeded: "SSH sign-in is required for this machine."
        case .unknownHost: "Confirm this machine's SSH identity before signing in."
        case .changedHostKey: "This machine's saved SSH identity has changed. Setup stopped before sign-in."
        case .timedOut: "The SSH check timed out. Check the connection and try again."
        case .tooMuchOutput: "The remote machine returned more data than this check accepts."
        case .invalidOutput: "The remote machine returned an unexpected setup response."
        case .unsupportedPlatform: "This version of Syn requires Ubuntu 26.04 on ARM64."
        }
    }

    static func classify(_ output: SSHProbeOutput) -> SSHProbeFailure {
        let diagnostic = String(decoding: output.diagnostics, as: UTF8.self).lowercased()
        if diagnostic.contains("remote host identification has changed")
            || diagnostic.contains("offending ") && diagnostic.contains("key in") {
            return .changedHostKey
        }
        if diagnostic.contains("no ") && diagnostic.contains("host key is known")
            || diagnostic.contains("host key verification failed") {
            return .unknownHost
        }
        if diagnostic.contains("permission denied")
            || diagnostic.contains("no supported authentication methods available") {
            return .authenticationNeeded
        }
        return .unavailable
    }
}

struct SSHProbeOutput: Sendable {
    let status: Int32
    let stdout: Data
    let diagnostics: Data

    init(status: Int32, stdout: Data, diagnostics: Data = Data()) {
        self.status = status
        self.stdout = stdout
        self.diagnostics = diagnostics
    }
}

protocol SSHProbeRunning: Sendable {
    func run(settings: SSHConnectionSettings, operation: SSHReadOnlyOperation) async throws -> SSHProbeOutput
}

/// Only fixed read-only operations are available here. Syn supplies no credential
/// prompt or input; a configured identity agent may still request user presence.
struct SystemSSHProbeRunner: SSHProbeRunning {
    func run(settings: SSHConnectionSettings, operation: SSHReadOnlyOperation) async throws -> SSHProbeOutput {
        let arguments = try settings.arguments(
            for: operation, synKnownHosts: try settings.preparedSynKnownHostsURL()
        )
        return try await SSHProbeProcess().run(arguments: arguments)
    }
}

struct SSHSetupProbe: Sendable {
    let runner: any SSHProbeRunning

    init(runner: any SSHProbeRunning = SystemSSHProbeRunner()) { self.runner = runner }

    func checkPlatform(_ settings: SSHConnectionSettings) async throws {
        try Task.checkCancellation()
        try settings.validate()
        let platform = try await runner.run(settings: settings, operation: .platform)
        guard platform.status == 0 else { throw SSHProbeFailure.classify(platform) }
        guard platform.stdout == Data("Linux aarch64\n".utf8) else {
            throw SSHProbeFailure.unsupportedPlatform
        }
        try Task.checkCancellation()
        let release = try await runner.run(settings: settings, operation: .operatingSystem)
        guard release.status == 0 else { throw SSHProbeFailure.classify(release) }
        try Self.validateOperatingSystem(release.stdout)
    }

    static func validateOperatingSystem(_ data: Data) throws {
        guard data.count <= 16_384, let text = String(data: data, encoding: .utf8),
              !text.utf8.contains(0) else { throw SSHProbeFailure.invalidOutput }
        var fields: [String: String] = [:]
        for line in text.split(separator: "\n") {
            guard !line.hasPrefix("#"), let separator = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<separator])
            guard key == "ID" || key == "VERSION_ID" else { continue }
            guard fields[key] == nil else { throw SSHProbeFailure.invalidOutput }
            var value = String(line[line.index(after: separator)...])
            if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 {
                value.removeFirst(); value.removeLast()
            }
            fields[key] = value
        }
        guard fields["ID"] == "ubuntu", fields["VERSION_ID"] == "26.04" else {
            throw SSHProbeFailure.unsupportedPlatform
        }
    }
}
