import Darwin
import Foundation

/// Read-only setup information, not proof that sudo or recovery is healthy.
/// A failed SSH command is never interpreted as an uninstalled machine.
struct RemoteInstallationStatus: Equatable, Sendable {
    enum Configuration: String, Decodable, Sendable {
        case configured, absent, incomplete, invalid, unreadable
    }

    let configuration: Configuration
    let release: ReleaseIdentity
    let targetID: String?
    let managedUID: UInt32?

    private struct Envelope: Decodable {
        let ok: Bool
        let data: Report
    }

    private struct Report: Decodable {
        let schema_version: Int
        let configured: Bool?
        let configuration_state: Configuration
        let release_id: String
        let release_commit: String
        let target_id: String?
        let managed_uid: UInt32?
    }

    static func parse(_ output: SSHProbeOutput) throws -> Self {
        guard output.status == 0 else { throw SSHProbeFailure.classify(output) }
        guard !output.stdout.isEmpty, output.stdout.count <= 16_384 else {
            throw SSHProbeFailure.invalidOutput
        }
        do {
            let envelope = try JSONDecoder().decode(Envelope.self, from: output.stdout)
            let report = envelope.data
            guard envelope.ok, report.schema_version == 1,
                  ReleaseIdentity.validID(report.release_id),
                  report.release_commit.utf8.count == 40,
                  report.release_commit.utf8.allSatisfy({
                      (48...57).contains($0) || (97...102).contains($0)
                  }) else { throw SSHProbeFailure.invalidOutput }

            switch report.configuration_state {
            case .configured:
                guard report.configured == true, report.managed_uid != nil,
                      let target = report.target_id, !target.isEmpty,
                      target.utf8.count <= 256 else { throw SSHProbeFailure.invalidOutput }
            case .unreadable:
                guard report.configured == nil else { throw SSHProbeFailure.invalidOutput }
            case .absent:
                guard report.configured == false, report.target_id == nil,
                      report.managed_uid == nil else { throw SSHProbeFailure.invalidOutput }
            case .incomplete, .invalid:
                guard report.configured == false else { throw SSHProbeFailure.invalidOutput }
            }

            return Self(
                configuration: report.configuration_state,
                release: ReleaseIdentity(schemaVersion: 1, releaseID: report.release_id,
                                         commit: report.release_commit),
                targetID: report.target_id, managedUID: report.managed_uid
            )
        } catch {
            // Do not attach raw SSH output to errors or diagnostics.
            throw SSHProbeFailure.invalidOutput
        }
    }
}

extension SSHSetupProbe {
    func readInstallation(_ settings: SSHConnectionSettings) async throws -> RemoteInstallationStatus {
        try Task.checkCancellation()
        try settings.validate()
        let output = try await runner.run(settings: settings, operation: .status)
        try Task.checkCancellation()
        return try RemoteInstallationStatus.parse(output)
    }
}

enum RemoteMachineInstallation: Equatable, Sendable {
    case notInstalled
    case updateRequired(RemoteInstallationStatus?)
    case installed(RemoteInstallationStatus)
}

struct RemoteMachinePreflight: Equatable, Sendable {
    let settings: SSHConnectionSettings
    let serverAddress: String
    let installation: RemoteMachineInstallation
}

protocol MachineSetupChecking: Sendable {
    func check(_ settings: SSHConnectionSettings) async throws -> RemoteMachinePreflight
}

struct SSHMachineSetupChecker: MachineSetupChecking {
    let probe: SSHSetupProbe
    let expectedRelease: ReleaseIdentity

    init(
        probe: SSHSetupProbe = SSHSetupProbe(),
        expectedRelease: ReleaseIdentity = .current
    ) {
        self.probe = probe
        self.expectedRelease = expectedRelease
    }

    func check(_ settings: SSHConnectionSettings) async throws -> RemoteMachinePreflight {
        try await probe.checkPlatform(settings)
        try Task.checkCancellation()
        let connection = try await probe.runner.run(settings: settings, operation: .connection)
        let serverAddress = try Self.parseServerAddress(connection)
        try Task.checkCancellation()
        let output = try await probe.runner.run(settings: settings, operation: .status)
        try Task.checkCancellation()
        if output.status == 127, output.stdout.isEmpty {
            return RemoteMachinePreflight(
                settings: settings, serverAddress: serverAddress, installation: .notInstalled
            )
        }
        if RemoteInstallationStatus.isLegacyStatus(output) {
            return RemoteMachinePreflight(
                settings: settings, serverAddress: serverAddress,
                installation: .updateRequired(nil)
            )
        }
        let status = try RemoteInstallationStatus.parse(output)
        let installation: RemoteMachineInstallation = status.configuration == .configured
            && status.release == expectedRelease ? .installed(status) : .updateRequired(status)
        return RemoteMachinePreflight(
            settings: settings, serverAddress: serverAddress, installation: installation
        )
    }

    static func parseServerAddress(_ output: SSHProbeOutput) throws -> String {
        guard output.status == 0, !output.stdout.isEmpty, output.stdout.count <= 1_024,
              let text = String(data: output.stdout, encoding: .utf8),
              !text.utf8.contains(0) else { throw SSHProbeFailure.invalidOutput }
        let fields = text.split(whereSeparator: \.isWhitespace)
        guard fields.count == 4,
              UInt16(fields[1]) != nil, UInt16(fields[1]) != 0,
              UInt16(fields[3]) != nil, UInt16(fields[3]) != 0 else {
            throw SSHProbeFailure.invalidOutput
        }
        let client = String(fields[0])
        let server = String(fields[2])
        guard validIPAddress(client), validUsableServerAddress(server) else {
            throw SSHProbeFailure.invalidOutput
        }
        return server
    }

    private static func validIPAddress(_ value: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return value.withCString {
            inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1
        }
    }

    private static func validUsableServerAddress(_ value: String) -> Bool {
        var v4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            let address = UInt32(bigEndian: v4.s_addr)
            return address != 0 && address != UInt32.max
                && address & 0xff00_0000 != 0x7f00_0000
                && address & 0xf000_0000 != 0xe000_0000
        }
        var v6 = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &v6) { Array($0) }
        return bytes != Array(repeating: 0, count: 16)
            && bytes != Array(repeating: 0, count: 15) + [1]
            && bytes.first != 0xff
    }
}

private extension RemoteInstallationStatus {
    static func isLegacyStatus(_ output: SSHProbeOutput) -> Bool {
        guard output.status == 0, !output.stdout.isEmpty, output.stdout.count <= 16_384,
              let object = try? JSONSerialization.jsonObject(with: output.stdout),
              let envelope = object as? [String: Any], Set(envelope.keys) == ["ok", "data"],
              envelope["ok"] as? Bool == true,
              let report = envelope["data"] as? [String: Any] else { return false }
        let legacyKeys: Set<String> = [
            "configured", "target_id", "managed_user", "managed_uid", "listen", "overlay",
            "approver_ip", "timeout_seconds", "agent_socket", "target_key_id",
        ]
        guard Set(report.keys) == legacyKeys, report["configured"] is Bool else { return false }
        return true
    }
}
