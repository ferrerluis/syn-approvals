import CryptoKit
import Foundation

struct SSHHostKeyRecord: Equatable, Sendable {
    let hostField: String
    let algorithm: String
    let keyBase64: String

    var line: String { "\(hostField) \(algorithm) \(keyBase64)" }
    var fingerprint: String {
        let bytes = Data(base64Encoded: keyBase64) ?? Data()
        return "SHA256:" + Data(SHA256.hash(data: bytes)).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
    }
}

struct SSHHostTrustCandidate: Equatable, Sendable {
    let settings: SSHConnectionSettings
    let records: [SSHHostKeyRecord]
    var port: UInt16 { settings.port ?? 22 }
}

protocol SSHHostKeyScanning: Sendable {
    func scan(_ settings: SSHConnectionSettings) async throws -> SSHHostTrustCandidate
}

struct SystemSSHHostKeyScanner: SSHHostKeyScanning {
    func scan(_ settings: SSHConnectionSettings) async throws -> SSHHostTrustCandidate {
        let port = settings.port ?? 22
        let arguments = try Self.arguments(for: settings)
        let output = try await SSHProbeProcess(keyScanTimeout: .seconds(8)).run(arguments: arguments)
        guard output.status == 0 else { throw SSHProbeFailure.unavailable }
        return SSHHostTrustCandidate(
            settings: settings,
            records: try Self.parse(output.stdout, hostname: settings.hostname, port: port)
        )
    }

    static func arguments(for settings: SSHConnectionSettings) throws -> [String] {
        try settings.validate()
        return [
            "-T", "5", "-t", "ecdsa,ed25519", "-p",
            String(settings.port ?? 22), settings.hostname,
        ]
    }

    static func parse(_ data: Data, hostname: String, port: UInt16) throws -> [SSHHostKeyRecord] {
        guard !data.isEmpty, data.count <= 16_384,
              let text = String(data: data, encoding: .utf8), !text.utf8.contains(0) else {
            throw SSHProbeFailure.invalidOutput
        }
        let hostField = port == 22 ? hostname : "[\(hostname)]:\(port)"
        var records: [SSHHostKeyRecord] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if rawLine.first == "#" { continue }
            let fields = rawLine.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count == 3, fields[0] == Substring(hostField) else {
                throw SSHProbeFailure.invalidOutput
            }
            let algorithm = String(fields[1])
            guard algorithm == "ssh-ed25519" || algorithm == "ecdsa-sha2-nistp256",
                  let key = Data(base64Encoded: String(fields[2])),
                  !key.isEmpty, key.count <= 8_192 else {
                throw SSHProbeFailure.invalidOutput
            }
            let record = SSHHostKeyRecord(
                hostField: hostField, algorithm: algorithm, keyBase64: String(fields[2])
            )
            if !records.contains(record) { records.append(record) }
        }
        guard !records.isEmpty, records.count <= 4 else { throw SSHProbeFailure.invalidOutput }
        return records.sorted { ($0.algorithm, $0.keyBase64) < ($1.algorithm, $1.keyBase64) }
    }
}
