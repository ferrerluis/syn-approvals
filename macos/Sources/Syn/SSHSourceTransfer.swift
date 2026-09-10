import Foundation

protocol SCPProcessRunning: Sendable {
    func copy(arguments: [String]) async throws -> SSHProbeOutput
}

protocol SSHSetupRunning: Sendable {
    func run(settings: SSHConnectionSettings, operation: SSHSetupOperation) async throws -> SSHProbeOutput
}

struct SystemSSHSetupRunner: SSHSetupRunning {
    func run(settings: SSHConnectionSettings, operation: SSHSetupOperation) async throws -> SSHProbeOutput {
        try await SSHProbeProcess().run(arguments: settings.arguments(
            for: operation, synKnownHosts: try settings.preparedSynKnownHostsURL()
        ))
    }
}

struct SystemSCPProcessRunner: SCPProcessRunning {
    func copy(arguments: [String]) async throws -> SSHProbeOutput {
        try await SSHProbeProcess(scpTimeout: .seconds(300)).run(arguments: arguments)
    }
}

struct SSHSourceTransfer: Sendable {
    let ssh: any SSHSetupRunning
    let scp: any SCPProcessRunning

    init(ssh: any SSHSetupRunning = SystemSSHSetupRunner(),
         scp: any SCPProcessRunning = SystemSCPProcessRunner()) {
        self.ssh = ssh
        self.scp = scp
    }

    func transferBootstrapHelper(_ helper: StagedRemoteHelperArtifact,
                                 to settings: SSHConnectionSettings) async throws {
        let prepared = try await ssh.run(settings: settings, operation: .prepareSourceTransfer)
        guard prepared.status == 0, prepared.stdout.isEmpty else {
            throw SSHProbeFailure.classify(prepared)
        }
        let output = try await scp.copy(arguments: settings.scpArguments(
            localFile: helper.url, destination: .helper,
            synKnownHosts: try settings.preparedSynKnownHostsURL()
        ))
        guard output.status == 0, output.stdout.isEmpty else { throw SSHProbeFailure.classify(output) }
        // The trusted bootstrap command checks the root-owned copy against the
        // Mac's bundled hash. Ordinary-user SSH output cannot authorize it.
    }

    func transfer(
        _ source: StagedRemoteSourceArtifact,
        helper: StagedRemoteHelperArtifact,
        request: StagedOnboardingRequest,
        to settings: SSHConnectionSettings,
        synKnownHosts: URL? = nil
    ) async throws {
        try Task.checkCancellation()
        let prepared = try await ssh.run(settings: settings, operation: .prepareSourceTransfer)
        guard prepared.status == 0, prepared.stdout.isEmpty else {
            throw SSHProbeFailure.classify(prepared)
        }
        let copied = try await scp.copy(arguments: settings.scpArguments(
            localFile: source.url, destination: .source, synKnownHosts: synKnownHosts
        ))
        guard copied.status == 0, copied.stdout.isEmpty else {
            throw SSHProbeFailure.classify(copied)
        }
        try Task.checkCancellation()
        let digest = try await ssh.run(settings: settings, operation: .sourceDigest)
        guard digest.status == 0 else { throw SSHProbeFailure.classify(digest) }
        let expected = source.descriptor.artifact.sha256
        let line = String(decoding: digest.stdout, as: UTF8.self)
        guard line == "\(expected)  .cache/syn-setup/source.incoming\n" else {
            throw RemoteSourceArtifactError.artifactHashMismatch
        }
        let helperCopied = try await scp.copy(arguments: settings.scpArguments(
            localFile: helper.url, destination: .helper, synKnownHosts: synKnownHosts
        ))
        guard helperCopied.status == 0, helperCopied.stdout.isEmpty else {
            throw SSHProbeFailure.classify(helperCopied)
        }
        let helperDigest = try await ssh.run(settings: settings, operation: .helperDigest)
        guard helperDigest.status == 0 else { throw SSHProbeFailure.classify(helperDigest) }
        guard String(decoding: helperDigest.stdout, as: UTF8.self)
            == "\(helper.descriptor.artifact.sha256)  .cache/syn-setup/synctl-bootstrap.incoming\n" else {
            throw RemoteSourceArtifactError.artifactHashMismatch
        }
        let requestCopied = try await scp.copy(arguments: settings.scpArguments(
            localFile: request.url, destination: .request, synKnownHosts: synKnownHosts
        ))
        guard requestCopied.status == 0, requestCopied.stdout.isEmpty else {
            throw SSHProbeFailure.classify(requestCopied)
        }
        let requestDigest = try await ssh.run(settings: settings, operation: .requestDigest)
        guard requestDigest.status == 0 else { throw SSHProbeFailure.classify(requestDigest) }
        guard String(decoding: requestDigest.stdout, as: UTF8.self)
            == "\(request.sha256)  .cache/syn-setup/request.incoming\n" else {
            throw RemoteSourceArtifactError.artifactHashMismatch
        }
    }
}
