import Foundation
import Testing
@testable import Syn

@Test func maintenanceIdentityPersistsPerMachineWithoutSharingKeys() throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: base) }
    let settings = SSHConnectionSettings(hostname: "remote.example", username: "developer", port: nil)
    let first = try SSHMaintenanceIdentity.prepare(for: settings, directory: base)
    let second = try SSHMaintenanceIdentity.prepare(for: settings, directory: base)
    #expect(first.publicKey == second.publicKey)
    #expect(first.privateKeyURL == second.privateKeyURL)
    let other = try SSHMaintenanceIdentity.prepare(
        for: .init(hostname: "other.example", username: "developer", port: nil), directory: base
    )
    #expect(first.publicKey != other.publicKey)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: first.privateKeyURL.path)
    #expect(throws: SynProtocolError.self) {
        try SSHMaintenanceIdentity.prepare(for: settings, directory: base)
    }
}

@Test func bootstrapCommandPinsRootCopyBeforeExecutionAndContainsNoPassword() throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: base) }
    let settings = SSHConnectionSettings(hostname: "remote.example", username: "developer", port: nil)
    let identity = try SSHMaintenanceIdentity.prepare(for: settings, directory: base)
    let helper = RemoteHelperArtifactDescriptor(
        releaseID: "20260909000000", commit: String(repeating: "a", count: 40),
        artifact: .init(name: "synctl", sha256: String(repeating: "b", count: 64), sizeBytes: 1024)
    )
    let command = try SSHMaintenanceBootstrap.command(settings: settings, identity: identity, helper: helper)
    #expect(command.hasPrefix("sudo /bin/sh -c '"))
    #expect(command.contains(helper.artifact.sha256))
    #expect(command.contains(identity.publicKey))
    #expect(!command.contains(identity.privateKeyURL.path))
    #expect(!command.contains("sudo -S"))
    let verification = try #require(command.range(of: "sha256sum --check --status"))
    let execution = try #require(command.range(of: "--json maintenance install"))
    #expect(verification.upperBound < execution.lowerBound)
    // Parse the generated shell without executing sudo or touching a device.
    let script = base.appendingPathComponent("syntax.sh")
    try Data(command.utf8).write(to: script)
    let parser = Process()
    parser.executableURL = URL(fileURLWithPath: "/bin/sh")
    parser.arguments = ["-n", script.path]
    try parser.run()
    parser.waitUntilExit()
    #expect(parser.terminationStatus == 0)
}

@Test func maintenanceIdentityRejectsSymlinkStorage() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let real = root.appendingPathComponent("real")
    try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false,
                                           attributes: [.posixPermissions: 0o700])
    let link = root.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
    #expect(throws: SynProtocolError.self) {
        try SSHMaintenanceIdentity.prepare(
            for: .init(hostname: "remote", username: "developer", port: nil), directory: link
        )
    }
}

@Test func resolvedRouteDropsOtherCredentialsAndOpenSSHUsesExactlyOneKey() async throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: base) }
    let settings = SSHConnectionSettings(hostname: "saved-alias", username: "developer", port: nil)
    let identity = try SSHMaintenanceIdentity.prepare(for: settings, directory: base)
    let route = try SSHMaintenanceRoute.parse(Data("""
    hostname remote.example
    port 2222
    proxyjump none
    hostkeyalias saved-host-identity
    identityfile /tmp/unrestricted-root-key
    certificatefile /tmp/unrestricted-certificate
    identityagent /tmp/agent.sock
    localcommand unexpected-command
    remotecommand unexpected-command
    forwardagent yes
    """.utf8))
    let args = try settings.maintenanceArguments(for: .probe, identityFile: identity.privateKeyURL, route: route)
    #expect(args.prefix(2) == ["-F", "/dev/null"])
    #expect(!args.joined(separator: " ").contains("unrestricted"))
    let output = try await SSHProbeProcess().run(arguments: ["-G"] + args)
    #expect(output.status == 0)
    let lines = String(decoding: output.stdout, as: UTF8.self).split(separator: "\n").map(String.init)
    #expect(lines.filter { $0.hasPrefix("identityfile ") } == ["identityfile \(identity.privateKeyURL.path)"])
    #expect(lines.contains("hostname remote.example"))
    #expect(lines.contains("port 2222"))
    #expect(lines.contains("hostkeyalias saved-host-identity"))
    #expect(lines.contains("identityagent none"))
    #expect(lines.contains("certificatefile none"))
    #expect(lines.contains("user root"))
    #expect(lines.contains("stricthostkeychecking true") || lines.contains("stricthostkeychecking yes"))
}

@Test func maintenanceRouteRejectsMissingOrDuplicateDestinations() {
    for value in ["hostname remote", "hostname remote\nport 0", "hostname remote\nport 22\nport 23",
                  "hostname remote;command\nport 22", "hostname remote\nport 22\u{0}"] {
        #expect(throws: (any Error).self) { try SSHMaintenanceRoute.parse(Data(value.utf8)) }
    }
}
