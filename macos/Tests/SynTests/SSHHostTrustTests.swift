import Darwin
import Foundation
import Testing
@testable import Syn

@Test func synKnownHostsIsPrivateAndRejectsUnsafeExistingObjects() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("syn-known-hosts-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let file = root.appendingPathComponent("SSH/known_hosts")
    let store = try SynKnownHostsStore(fileURL: file)
    #expect(try store.prepare() == file)
    let directoryMode = try #require((try FileManager.default.attributesOfItem(atPath: file.deletingLastPathComponent().path)[.posixPermissions]) as? NSNumber)
    let fileMode = try #require((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions]) as? NSNumber)
    #expect(directoryMode.uint16Value == 0o700)
    #expect(fileMode.uint16Value == 0o600)
    #expect(try store.prepare() == file)

    try FileManager.default.removeItem(at: file)
    try FileManager.default.createSymbolicLink(at: file, withDestinationURL: URL(fileURLWithPath: "/dev/null"))
    #expect(throws: SSHProbeFailure.unavailable) { try store.prepare() }
}

@Test func sshTrustSourcePersistsAndSynStoreMustBeExplicit() throws {
    let legacy = Data(#"{"hostname":"pi","username":"user"}"#.utf8)
    #expect(try JSONDecoder().decode(SSHConnectionSettings.self, from: legacy).hostTrustSource == .existingOpenSSH)
    let settings = SSHConnectionSettings(hostname: "pi", username: "user", port: 22,
                                         hostTrustSource: .synKnownHosts)
    #expect(throws: SynProtocolError.self) { try settings.arguments(for: .platform) }
    let path = URL(fileURLWithPath: "/Users/test/Library/Application Support/Syn/SSH/known_hosts")
    let arguments = try settings.arguments(for: .platform, synKnownHosts: path)
    #expect(arguments.contains("UserKnownHostsFile=\"\(path.path)\""))
    #expect(!arguments.contains("StrictHostKeyChecking=no"))
    #expect(try JSONDecoder().decode(SSHConnectionSettings.self, from: JSONEncoder().encode(settings)) == settings)
}

@Test func keyScanParsesOnlyExactSupportedHostRecordsAndFingerprints() throws {
    let edKey = Data([1, 2, 3, 4]).base64EncodedString()
    let ecKey = Data([5, 6, 7, 8]).base64EncodedString()
    let output = Data("# banner\n[pi.example]:2222 ssh-ed25519 \(edKey)\n[pi.example]:2222 ecdsa-sha2-nistp256 \(ecKey)\n".utf8)
    let records = try SystemSSHHostKeyScanner.parse(output, hostname: "pi.example", port: 2222)
    #expect(records.count == 2)
    #expect(records.allSatisfy { $0.hostField == "[pi.example]:2222" })
    #expect(records.allSatisfy { $0.fingerprint.hasPrefix("SHA256:") })

    for invalid in [
        "other ssh-ed25519 \(edKey)\n",
        "pi.example ssh-rsa \(edKey)\n",
        "pi.example ssh-ed25519 not-base64!\n",
        "pi.example ssh-ed25519 \(edKey) trailing\n",
    ] {
        #expect(throws: SSHProbeFailure.self) {
            try SystemSSHHostKeyScanner.parse(Data(invalid.utf8), hostname: "pi.example", port: 22)
        }
    }
}

@Test func keyScanArgumentsAreFixedAfterDestinationValidation() throws {
    let settings = SSHConnectionSettings(hostname: "pi.example", username: "user", port: 2222)
    #expect(try SystemSSHHostKeyScanner.arguments(for: settings)
        == ["-T", "5", "-t", "ecdsa,ed25519", "-p", "2222", "pi.example"])
    #expect(throws: SynProtocolError.self) {
        try SystemSSHHostKeyScanner.arguments(for: .init(
            hostname: "-f", username: "user", port: nil
        ))
    }
}

@Test func confirmedHostRecordsArePrivateDurableAndNeverOverwritten() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("syn-confirmed-host-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let store = try SynKnownHostsStore(fileURL: root.appendingPathComponent("SSH/known_hosts"))
    let settings = SSHConnectionSettings(hostname: "pi.example", username: "user", port: 2222)
    let original = SSHHostTrustCandidate(settings: settings, records: [
        .init(hostField: "[pi.example]:2222", algorithm: "ssh-ed25519",
              keyBase64: Data([1, 2, 3]).base64EncodedString()),
    ])
    let file = try store.trust(original)
    let first = try Data(contentsOf: file)
    #expect(first == Data((original.records[0].line + "\n").utf8))
    #expect(try store.trust(original) == file)
    #expect(try Data(contentsOf: file) == first)

    let changed = SSHHostTrustCandidate(settings: settings, records: [
        .init(hostField: "[pi.example]:2222", algorithm: "ssh-ed25519",
              keyBase64: Data([9, 9, 9]).base64EncodedString()),
    ])
    #expect(throws: SSHProbeFailure.changedHostKey) { try store.trust(changed) }
    #expect(try Data(contentsOf: file) == first)
}
