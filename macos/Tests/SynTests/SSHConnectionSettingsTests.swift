import Foundation
import Testing
@testable import Syn

@Test func sshSettingsRejectOptionAndShellInjection() {
    for host in ["-oProxyCommand=bad", "pi;command", "pi\ncommand", "user@pi", "$(command)", "pi host", ""] {
        #expect(throws: SynProtocolError.self) {
            _ = try SSHConnectionSettings(hostname: host, username: "user", port: nil).arguments(for: .platform)
        }
    }
    for user in ["root", "-option", "user;command", "", "user\npassword"] {
        #expect(throws: SynProtocolError.self) {
            try SSHConnectionSettings(hostname: "pi", username: user, port: nil).validate()
        }
    }
    #expect(throws: SynProtocolError.self) {
        try SSHConnectionSettings(hostname: "pi", username: "user", port: 0).validate()
    }
}

@Test func scpUsesFixedDestinationAndPreservesSecurityOptions() throws {
    let local = URL(fileURLWithPath: "/private/tmp/source archive.tar.gz")
    for (host, expected) in [("pi", "user@pi:.cache/syn-setup/source.incoming"),
                             ("fd00::10", "user@[fd00::10]:.cache/syn-setup/source.incoming")] {
        let arguments = try SSHConnectionSettings(hostname: host, username: "user", port: 2222)
            .scpArguments(localFile: local, destination: .source)
        #expect(arguments.suffix(3) == ["--", local.path, expected])
        #expect(arguments.contains("ForwardAgent=no"))
        #expect(arguments.contains("StrictHostKeyChecking=yes"))
        #expect(arguments.contains("2222"))
        #expect(arguments.first == "-O")
        #expect(!arguments.contains("-T"))
        #expect(!arguments.contains("-a"))
        #expect(!arguments.contains("-l"))
    }
}

@Test func sshReadOnlyCommandsPreserveHostnamesAndRestrictSideEffects() throws {
    for host in ["pi", "pi.home.example", "192.168.1.10", "fd00::10"] {
        let args = try SSHConnectionSettings(hostname: host, username: "user", port: 2222).arguments(for: .status)
        #expect(args.suffix(3) == ["--", host, "/usr/bin/synctl --json status"])
        #expect(args.contains("StrictHostKeyChecking=yes"))
        #expect(args.contains("ForwardAgent=no"))
        #expect(args.contains("PermitLocalCommand=no"))
        #expect(args.contains("UpdateHostKeys=no"))
        #expect(args.contains("AddKeysToAgent=no"))
        #expect(args.contains("2222"))
    }
}

@Test func sshTargetMetadataContainsNoCredentials() throws {
    let settings = SSHConnectionSettings(hostname: "pi", username: "user", port: nil)
    let encoded = try JSONEncoder().encode(settings)
    let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    #expect(Set(object.keys) == ["hostname", "username", "hostTrustSource"])
    #expect(try JSONDecoder().decode(SSHConnectionSettings.self, from: encoded) == settings)
}

@Test func privilegedOnboardingCommandsUseOnlyRestrictedKeyAndValidateIdentifiers() throws {
    let settings = SSHConnectionSettings(hostname: "pi", username: "user", port: 2222)
    let operationID = String(repeating: "a", count: 32)
    let digest = String(repeating: "b", count: 64)
    let identity = URL(fileURLWithPath: "/tmp/syn-test-key")
    func arguments(_ operation: SSHPrivilegedOperation) throws -> [String] {
        try settings.maintenanceArguments(for: operation, identityFile: identity)
    }
    #expect(try arguments(.prepare(operationID: operationID, requestSHA256: digest, sourceSHA256: digest)).last
        == "syn-maintenance-v1 prepare \(operationID) \(digest) \(digest)")
    #expect(try arguments(.retainHelper(operationID: operationID, sha256: digest, size: 123)).last
        == "syn-maintenance-v1 retain \(operationID) \(digest) 123")
    #expect(try arguments(.recover).last == "syn-maintenance-v1 recover")
    #expect(try arguments(.probe).last == "syn-maintenance-v1 probe")
    let phases: [(SSHPrivilegedOperation, String)] = [
        (.build(operationID: operationID), "build"),
        (.configure(operationID: operationID), "configure"),
        (.activate(operationID: operationID), "activate"),
        (.complete(operationID: operationID), "complete"),
        (.cleanup(operationID: operationID), "cleanup"),
    ]
    for (operation, phase) in phases {
        let args = try arguments(operation)
        #expect(args.last == "syn-maintenance-v1 \(phase) \(operationID)")
        for option in ["StrictHostKeyChecking=yes", "BatchMode=yes", "IdentityAgent=none",
                       "IdentitiesOnly=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                       "ForwardAgent=no", "ClearAllForwardings=yes"] {
            #expect(args.contains(option))
        }
        #expect(args.contains(identity.path))
        #expect(args.contains("root"))
        #expect(!args.last!.contains("sudo"))
        #expect(!args.contains("user"))
    }
    #expect(throws: SynProtocolError.self) { try arguments(.build(operationID: "../../bin/sh")) }
    #expect(throws: SynProtocolError.self) {
        try arguments(.prepare(operationID: operationID, requestSHA256: "A" + digest.dropFirst(), sourceSHA256: digest))
    }
    #expect(throws: SynProtocolError.self) {
        try arguments(.retainHelper(operationID: operationID, sha256: digest, size: 0))
    }
    #expect(SSHPrivilegedOperation.build(operationID: operationID).timeout == .seconds(1_800))
    #expect(SSHPrivilegedOperation.complete(operationID: operationID).timeout == .seconds(150))
}
