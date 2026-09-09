import CryptoKit
import Foundation

protocol SSHPrivilegedRunning: Sendable {
    func run(
        settings: SSHConnectionSettings,
        operation: SSHPrivilegedOperation,
        identity: SSHMaintenanceIdentity
    ) async throws -> SSHProbeOutput
}

struct SystemSSHPrivilegedRunner: SSHPrivilegedRunning {
    func run(
        settings: SSHConnectionSettings,
        operation: SSHPrivilegedOperation,
        identity: SSHMaintenanceIdentity
    ) async throws -> SSHProbeOutput {
        let route = try await settings.resolvedMaintenanceRoute()
        return try await SSHProbeProcess(timeout: operation.timeout).run(
            arguments: settings.maintenanceArguments(
                for: operation, identityFile: identity.privateKeyURL,
                synKnownHosts: try settings.preparedSynKnownHostsURL(), route: route
            )
        )
    }
}

protocol SSHSourceTransferring: Sendable {
    func transfer(
        _ source: StagedRemoteSourceArtifact,
        helper: StagedRemoteHelperArtifact,
        request: StagedOnboardingRequest,
        to settings: SSHConnectionSettings,
        synKnownHosts: URL?
    ) async throws
}

extension SSHSourceTransfer: SSHSourceTransferring {}

enum RemoteOnboardingProgress: String, Equatable, Sendable {
    case staging = "Preparing signed release"
    case transferring = "Copying verified release"
    case preparing = "Preparing protected installer"
    case building = "Building on the machine"
    case configuring = "Configuring approval service"
    case activating = "Activating protected recovery"
    case completing = "Verifying and completing setup"
    case recovering = "Restoring local sudo access"
}

enum RemoteOnboardingCoordinatorError: Error, LocalizedError, Equatable {
    case invalidResponse
    case remoteFailed
    case recoveryRequired

    var errorDescription: String? {
        switch self {
        case .invalidResponse: "The machine returned an invalid setup response."
        case .remoteFailed: "The machine could not complete setup. No remote diagnostics were retained."
        case .recoveryRequired: "Setup entered its protected transition and automatic recovery could not be confirmed. Use the machine's recovery access before retrying."
        }
    }
}

struct RemoteOnboardingCoordinator: Sendable {
    typealias Progress = @Sendable (RemoteOnboardingProgress) async -> Void
    typealias ConfigureTarget = @Sendable (TargetRecord) async throws -> Void

    let transfer: any SSHSourceTransferring
    let privileged: any SSHPrivilegedRunning

    init(
        transfer: any SSHSourceTransferring = SSHSourceTransfer(),
        privileged: any SSHPrivilegedRunning = SystemSSHPrivilegedRunner()
    ) {
        self.transfer = transfer
        self.privileged = privileged
    }

    func run(
        request: RemoteOnboardingRequest,
        stagedRequest: StagedOnboardingRequest,
        source: StagedRemoteSourceArtifact,
        helper: StagedRemoteHelperArtifact,
        settings: SSHConnectionSettings,
        identity: SSHMaintenanceIdentity,
        requiresRecovery: Bool = false,
        configureTarget: @escaping ConfigureTarget = { _ in },
        progress: @escaping Progress = { _ in }
    ) async throws -> TargetRecord {
        var activationAttempted = false
        var prepared = false
        do {
            try await verifyMaintenance(settings: settings, identity: identity)
            if requiresRecovery {
                await progress(.recovering)
                try await executeRecovery(settings: settings, identity: identity)
            }
            await progress(.transferring)
            let knownHosts = try settings.preparedSynKnownHostsURL()
            try await transfer.transfer(
                source, helper: helper, request: stagedRequest,
                to: settings, synKnownHosts: knownHosts
            )
            try Task.checkCancellation()

            await progress(.preparing)
            try await executeStatus(
                .retainHelper(operationID: request.operationID,
                              sha256: helper.descriptor.artifact.sha256,
                              size: helper.descriptor.artifact.sizeBytes),
                settings: settings, identity: identity
            )
            let prepare = try await execute(
                .prepare(
                    operationID: request.operationID,
                    requestSHA256: stagedRequest.sha256,
                    sourceSHA256: source.descriptor.artifact.sha256
                ), settings: settings, identity: identity
            )
            try verifyBasic(prepare, operationID: request.operationID, releaseID: request.releaseID)
            prepared = true
            let cleanup = try await execute(
                .cleanup(operationID: request.operationID), settings: settings, identity: identity
            )
            try verifyCleanup(cleanup, operationID: request.operationID)
            prepared = false

            await progress(.building)
            let build = try await execute(
                .build(operationID: request.operationID), settings: settings, identity: identity
            )
            try verifyPhase(build, operationID: request.operationID,
                            releaseID: request.releaseID, phase: "package_built")

            await progress(.configuring)
            let configure = try await execute(
                .configure(operationID: request.operationID), settings: settings, identity: identity
            )
            let target = try decodeTarget(
                configure, operationID: request.operationID, releaseID: request.releaseID
            )
            try await configureTarget(target)

            await progress(.activating)
            activationAttempted = true
            let activate = try await execute(
                .activate(operationID: request.operationID), settings: settings, identity: identity
            )
            try verifyTransition(
                activate, operationID: request.operationID, releaseID: request.releaseID,
                phase: "armed_pending_final_approval", recoveryArmed: true
            )

            await progress(.completing)
            let complete = try await execute(
                .complete(operationID: request.operationID), settings: settings, identity: identity
            )
            try verifyTransition(
                complete, operationID: request.operationID, releaseID: request.releaseID,
                phase: "complete", recoveryArmed: false
            )
            return TargetRecord(
                targetID: target.targetID, displayName: target.displayName,
                webSocketURL: target.webSocketURL,
                targetPublicKeyBase64: target.targetPublicKeyBase64,
                serverCertificateSHA256Hex: target.serverCertificateSHA256Hex,
                clientIdentityLabel: target.clientIdentityLabel,
                ssh: settings,
                installedReleaseID: request.releaseID,
                installedReleaseCommit: request.releaseCommit
            )
        } catch {
            if !activationAttempted, prepared {
                let runner = privileged
                let cleanup = try? await Task.detached {
                    try await runner.run(
                        settings: settings,
                        operation: .cleanup(operationID: request.operationID),
                        identity: identity
                    )
                }.value
                guard let cleanup, cleanup.status == 0,
                      let envelope = try? JSONDecoder().decode(CleanupEnvelope.self, from: cleanup.stdout),
                      envelope.ok, envelope.data.operation_id == request.operationID,
                      envelope.data.cleaned, envelope.data.phase == "staging_cleaned" else {
                    throw RemoteOnboardingCoordinatorError.remoteFailed
                }
                throw error
            }
            guard activationAttempted else { throw error }
            await progress(.recovering)
            do {
                let runner = privileged
                let recovery = try await Task.detached {
                    try await runner.run(settings: settings, operation: .recover, identity: identity)
                }.value
                guard recovery.status == 0 else { throw RemoteOnboardingCoordinatorError.recoveryRequired }
            } catch {
                throw RemoteOnboardingCoordinatorError.recoveryRequired
            }
            throw error
        }
    }

    private func execute(
        _ operation: SSHPrivilegedOperation,
        settings: SSHConnectionSettings,
        identity: SSHMaintenanceIdentity
    ) async throws -> Data {
        try Task.checkCancellation()
        let output = try await privileged.run(settings: settings, operation: operation, identity: identity)
        guard output.status == 0 else { throw RemoteOnboardingCoordinatorError.remoteFailed }
        guard !output.stdout.isEmpty, output.stdout.count <= 65_536 else {
            throw RemoteOnboardingCoordinatorError.invalidResponse
        }
        return output.stdout
    }

    private func executeStatus(
        _ operation: SSHPrivilegedOperation,
        settings: SSHConnectionSettings,
        identity: SSHMaintenanceIdentity
    ) async throws {
        let output = try await privileged.run(
            settings: settings, operation: operation, identity: identity
        )
        guard output.status == 0, output.stdout.isEmpty else {
            throw RemoteOnboardingCoordinatorError.remoteFailed
        }
    }

    private func executeRecovery(
        settings: SSHConnectionSettings,
        identity: SSHMaintenanceIdentity
    ) async throws {
        let output = try await privileged.run(
            settings: settings, operation: .recover, identity: identity
        )
        guard output.status == 0, output.stdout.count <= 65_536 else {
            throw RemoteOnboardingCoordinatorError.remoteFailed
        }
    }

    func verifyMaintenance(settings: SSHConnectionSettings, identity: SSHMaintenanceIdentity) async throws {
        let output = try await privileged.run(settings: settings, operation: .probe, identity: identity)
        guard output.status == 0, output.stdout.count <= 4096,
              let reply = try? JSONDecoder().decode(MaintenanceEnvelope.self, from: output.stdout),
              reply.ok, reply.data.protocol_version == 1,
              reply.data.managed_user == settings.username else {
            throw SynProtocolError.invalid("Syn maintenance access is not ready. Run the one-time command in a trusted administrator terminal, then continue.")
        }
    }

    private struct MaintenanceEnvelope: Decodable {
        let ok: Bool
        let data: MaintenanceStatus
    }
    private struct MaintenanceStatus: Decodable {
        let protocol_version: Int
        let managed_user: String
    }

    private struct BasicEnvelope: Decodable {
        let ok: Bool
        let data: Basic
    }
    private struct Basic: Decodable {
        let operation_id: String
        let release_id: String
        let phase: String?
    }
    private struct TargetEnvelope: Decodable {
        let ok: Bool
        let data: TargetData
    }
    private struct TargetData: Decodable {
        let operation_id: String
        let release_id: String
        let target: TargetPayload
        let phase: String
    }
    private struct TargetPayload: Decodable {
        let targetID: String
        let displayName: String
        let webSocketURL: URL
        let targetPublicKeyBase64: String
        let serverCertificateSHA256Hex: String
        let clientIdentityLabel: String
    }
    private struct TransitionEnvelope: Decodable {
        let ok: Bool
        let data: Transition
    }
    private struct CleanupEnvelope: Decodable {
        let ok: Bool
        let data: Cleanup
    }
    private struct Cleanup: Decodable {
        let operation_id: String
        let cleaned: Bool
        let phase: String
    }
    private struct Transition: Decodable {
        let operation_id: String
        let release_id: String
        let approved: Bool
        let recovery_armed: Bool
        let phase: String
    }

    private func verifyBasic(_ data: Data, operationID: String, releaseID: String) throws {
        let value = try decode(BasicEnvelope.self, data)
        guard value.ok, value.data.operation_id == operationID,
              value.data.release_id == releaseID else { throw RemoteOnboardingCoordinatorError.invalidResponse }
    }

    private func verifyCleanup(_ data: Data, operationID: String) throws {
        let value = try decode(CleanupEnvelope.self, data)
        guard value.ok, value.data.operation_id == operationID,
              value.data.cleaned, value.data.phase == "staging_cleaned" else {
            throw RemoteOnboardingCoordinatorError.invalidResponse
        }
    }

    private func verifyPhase(
        _ data: Data, operationID: String, releaseID: String, phase: String
    ) throws {
        let value = try decode(BasicEnvelope.self, data)
        guard value.ok, value.data.operation_id == operationID,
              value.data.release_id == releaseID, value.data.phase == phase else {
            throw RemoteOnboardingCoordinatorError.invalidResponse
        }
    }

    private func decodeTarget(_ data: Data, operationID: String, releaseID: String) throws -> TargetRecord {
        let value = try decode(TargetEnvelope.self, data)
        let payload = value.data.target
        let target = TargetRecord(
            targetID: payload.targetID, displayName: payload.displayName,
            webSocketURL: payload.webSocketURL,
            targetPublicKeyBase64: payload.targetPublicKeyBase64,
            serverCertificateSHA256Hex: payload.serverCertificateSHA256Hex,
            clientIdentityLabel: payload.clientIdentityLabel
        )
        guard value.ok, value.data.operation_id == operationID,
              value.data.release_id == releaseID,
              value.data.phase == "paired_pending_approval",
              !target.targetID.isEmpty, target.targetID.utf8.count <= 128,
              !target.displayName.isEmpty, target.webSocketURL.scheme == "wss",
              target.publicKey != nil,
              target.serverCertificateSHA256Hex.utf8.count == 64,
              target.serverCertificateSHA256Hex.utf8.allSatisfy({
                  (48...57).contains($0) || (97...102).contains($0)
              }), !target.clientIdentityLabel.isEmpty else {
            throw RemoteOnboardingCoordinatorError.invalidResponse
        }
        return target
    }

    private func verifyTransition(
        _ data: Data, operationID: String, releaseID: String,
        phase: String, recoveryArmed: Bool
    ) throws {
        let value = try decode(TransitionEnvelope.self, data)
        guard value.ok, value.data.operation_id == operationID,
              value.data.release_id == releaseID, value.data.phase == phase,
              value.data.approved, value.data.recovery_armed == recoveryArmed else {
            throw RemoteOnboardingCoordinatorError.invalidResponse
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw RemoteOnboardingCoordinatorError.invalidResponse }
    }
}
