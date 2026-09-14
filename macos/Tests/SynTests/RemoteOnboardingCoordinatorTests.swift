import CryptoKit
import Foundation
import Testing
@testable import Syn

@Test func remoteFailureDescriptionDoesNotClaimDiagnosticsWereDiscarded() {
    #expect(RemoteOnboardingCoordinatorError.remoteFailed.localizedDescription ==
            "The machine could not complete setup.")
}

private actor CoordinatorTransferFixture: SSHSourceTransferring {
    private(set) var calls = 0
    func transfer(
        _ source: StagedRemoteSourceArtifact,
        helper: StagedRemoteHelperArtifact,
        request: StagedOnboardingRequest,
        to settings: SSHConnectionSettings,
        synKnownHosts: URL?
    ) async throws { calls += 1 }
}

private actor CoordinatorRunnerFixture: SSHPrivilegedRunning {
    enum Behavior { case success, fail(SSHPrivilegedOperation), waitAtComplete }
    let behavior: Behavior
    let targetKey = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
    private(set) var calls: [SSHPrivilegedOperation] = []

    init(_ behavior: Behavior = .success) { self.behavior = behavior }

    func run(
        settings: SSHConnectionSettings,
        operation: SSHPrivilegedOperation,
        identity: SSHMaintenanceIdentity
    ) async throws -> SSHProbeOutput {
        calls.append(operation)
        if case let .fail(expected) = behavior, expected == operation {
            return .init(status: 1, stdout: Data(), diagnostics: Data("sensitive remote text".utf8))
        }
        if case .waitAtComplete = behavior, case .complete = operation {
            try await Task.sleep(for: .seconds(30))
        }
        let op = String(repeating: "a", count: 32)
        let release = "20260908000000"
        let body: String
        switch operation {
        case .probe:
            body = #"{"ok":true,"data":{"protocol_version":1,"managed_user":"user"}}"#
        case .retainHelper:
            return .init(status: 0, stdout: Data())
        case .prepare:
            body = #"{"ok":true,"data":{"operation_id":"\#(op)","release_id":"\#(release)"}}"#
        case .build:
            body = #"{"ok":true,"data":{"operation_id":"\#(op)","release_id":"\#(release)","phase":"package_built"}}"#
        case .configure:
            body = #"{"ok":true,"data":{"operation_id":"\#(op)","release_id":"\#(release)","phase":"paired_pending_approval","target":{"targetID":"pi","displayName":"Pi","webSocketURL":"wss://192.168.2.10:7443","targetPublicKeyBase64":"\#(targetKey)","serverCertificateSHA256Hex":"\#(String(repeating: "c", count: 64))","clientIdentityLabel":"Syn pi transport"}}}"#
        case .activate:
            body = #"{"ok":true,"data":{"operation_id":"\#(op)","release_id":"\#(release)","approved":true,"recovery_armed":true,"phase":"armed_pending_final_approval"}}"#
        case .complete:
            body = #"{"ok":true,"data":{"operation_id":"\#(op)","release_id":"\#(release)","approved":true,"recovery_armed":false,"phase":"complete"}}"#
        case .recover:
            return .init(status: 0, stdout: Data())
        case .cleanup:
            body = #"{"ok":true,"data":{"operation_id":"\#(op)","cleaned":true,"phase":"staging_cleaned"}}"#
        }
        return .init(status: 0, stdout: Data(body.utf8))
    }
}

@Test func coordinatorUsesFixedSuccessOrderAndReturnsSSHMetadataOnlyAfterComplete() async throws {
    let fixture = try coordinatorArtifacts()
    defer { fixture.cleanup() }
    let transfer = CoordinatorTransferFixture()
    let runner = CoordinatorRunnerFixture()
    let target = try await RemoteOnboardingCoordinator(transfer: transfer, privileged: runner).run(
        request: fixture.request, stagedRequest: fixture.stagedRequest,
        source: fixture.source, helper: fixture.helper, settings: fixture.settings,
        identity: SSHMaintenanceIdentity(privateKeyURL: URL(fileURLWithPath: "/tmp/test-key"), publicKey: ""),
        configureTarget: { provisional in
            #expect(provisional.targetID == "pi")
            #expect(await runner.calls.last == .configure(operationID: fixture.request.operationID))
        }
    )
    #expect(await transfer.calls == 1)
    #expect(await runner.calls == [
        .probe,
        .retainHelper(operationID: fixture.request.operationID,
                      sha256: fixture.helper.descriptor.artifact.sha256,
                      size: fixture.helper.descriptor.artifact.sizeBytes),
        .prepare(operationID: fixture.request.operationID,
                 requestSHA256: fixture.stagedRequest.sha256,
                 sourceSHA256: fixture.source.descriptor.artifact.sha256),
        .cleanup(operationID: fixture.request.operationID),
        .build(operationID: fixture.request.operationID),
        .configure(operationID: fixture.request.operationID),
        .activate(operationID: fixture.request.operationID),
        .complete(operationID: fixture.request.operationID),
    ])
    #expect(target.targetID == "pi")
    #expect(target.ssh == fixture.settings)
    #expect(target.installedReleaseID == fixture.request.releaseID)
    #expect(target.installedReleaseCommit == fixture.request.releaseCommit)
}

@Test func coordinatorRecoversAfterProtectedTransitionButNotBeforeIt() async throws {
    let fixture = try coordinatorArtifacts()
    defer { fixture.cleanup() }
    let before = CoordinatorRunnerFixture(.fail(.build(operationID: fixture.request.operationID)))
    await #expect(throws: RemoteOnboardingCoordinatorError.remoteFailed) {
        try await RemoteOnboardingCoordinator(
            transfer: CoordinatorTransferFixture(), privileged: before
        ).run(
            request: fixture.request, stagedRequest: fixture.stagedRequest,
            source: fixture.source, helper: fixture.helper, settings: fixture.settings,
            identity: SSHMaintenanceIdentity(privateKeyURL: URL(fileURLWithPath: "/tmp/test-key"), publicKey: "")
        )
    }
    #expect(!(await before.calls).contains(.recover))

    let after = CoordinatorRunnerFixture(.fail(.complete(operationID: fixture.request.operationID)))
    await #expect(throws: RemoteOnboardingCoordinatorError.remoteFailed) {
        try await RemoteOnboardingCoordinator(
            transfer: CoordinatorTransferFixture(), privileged: after
        ).run(
            request: fixture.request, stagedRequest: fixture.stagedRequest,
            source: fixture.source, helper: fixture.helper, settings: fixture.settings,
            identity: SSHMaintenanceIdentity(privateKeyURL: URL(fileURLWithPath: "/tmp/test-key"), publicKey: "")
        )
    }
    #expect((await after.calls).last == .recover)
}

@Test func coordinatorCancellationAfterActivationRoutesRecovery() async throws {
    let fixture = try coordinatorArtifacts()
    defer { fixture.cleanup() }
    let runner = CoordinatorRunnerFixture(.waitAtComplete)
    let coordinator = RemoteOnboardingCoordinator(
        transfer: CoordinatorTransferFixture(), privileged: runner
    )
    let task = Task {
        try await coordinator.run(
            request: fixture.request, stagedRequest: fixture.stagedRequest,
            source: fixture.source, helper: fixture.helper, settings: fixture.settings,
            identity: SSHMaintenanceIdentity(privateKeyURL: URL(fileURLWithPath: "/tmp/test-key"), publicKey: "")
        )
    }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !(await runner.calls).contains(.complete(operationID: fixture.request.operationID)),
          ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect((await runner.calls).last == .recover)
}

@Test func updateRecoveryCompletesBeforeAnyNewReleaseWork() async throws {
    let fixture = try coordinatorArtifacts()
    defer { fixture.cleanup() }
    let runner = CoordinatorRunnerFixture()
    _ = try await RemoteOnboardingCoordinator(
        transfer: CoordinatorTransferFixture(), privileged: runner
    ).run(
        request: fixture.request, stagedRequest: fixture.stagedRequest,
        source: fixture.source, helper: fixture.helper, settings: fixture.settings,
        identity: SSHMaintenanceIdentity(privateKeyURL: URL(fileURLWithPath: "/tmp/test-key"), publicKey: ""),
        requiresRecovery: true
    )
    #expect(Array((await runner.calls).prefix(2)) == [.probe, .recover])
}

@Test func missingMaintenanceAuthorizationStopsBeforeRecoveryOrTransfer() async throws {
    let fixture = try coordinatorArtifacts()
    defer { fixture.cleanup() }
    let transfer = CoordinatorTransferFixture()
    let runner = CoordinatorRunnerFixture(.fail(.probe))
    await #expect(throws: SynProtocolError.self) {
        try await RemoteOnboardingCoordinator(transfer: transfer, privileged: runner).run(
            request: fixture.request, stagedRequest: fixture.stagedRequest,
            source: fixture.source, helper: fixture.helper, settings: fixture.settings,
            identity: SSHMaintenanceIdentity(privateKeyURL: URL(fileURLWithPath: "/tmp/test-key"), publicKey: ""),
            requiresRecovery: true
        )
    }
    #expect(await runner.calls == [.probe])
    #expect(await transfer.calls == 0)
}

private struct CoordinatorArtifacts {
    let directory: URL
    let settings: SSHConnectionSettings
    let request: RemoteOnboardingRequest
    let stagedRequest: StagedOnboardingRequest
    let source: StagedRemoteSourceArtifact
    let helper: StagedRemoteHelperArtifact

    func cleanup() {
        stagedRequest.remove(); source.remove(); helper.remove()
        try? FileManager.default.removeItem(at: directory)
    }
}

private func coordinatorArtifacts() throws -> CoordinatorArtifacts {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("syn-coordinator-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    let release = "20260908000000"
    let commit = String(repeating: "d", count: 40)
    let sourceBytes = Data("source".utf8)
    let sourceURL = directory.appendingPathComponent("source.tar.gz")
    try sourceBytes.write(to: sourceURL)
    let sourceDescriptor = RemoteSourceArtifactDescriptor(
        releaseID: release, commit: commit,
        artifact: .init(
            name: sourceURL.lastPathComponent,
            sha256: Data(SHA256.hash(data: sourceBytes)).hex,
            sizeBytes: UInt64(sourceBytes.count)
        )
    )
    let verifiedSource = try sourceDescriptor.verifyArtifact(at: sourceURL)
    let helperBytes = Data("helper".utf8)
    let helperURL = directory.appendingPathComponent("helper")
    try helperBytes.write(to: helperURL)
    let helperDescriptor = RemoteHelperArtifactDescriptor(
        releaseID: release, commit: commit,
        artifact: .init(
            name: helperURL.lastPathComponent,
            sha256: Data(SHA256.hash(data: helperBytes)).hex,
            sizeBytes: UInt64(helperBytes.count)
        )
    )
    let verifiedHelper = try helperDescriptor.verifyArtifact(at: helperURL)
    let settings = SSHConnectionSettings(hostname: "pi", username: "user", port: nil)
    let request = try RemoteOnboardingRequest.make(
        settings: settings, resolvedHostname: "pi", listenIP: "192.168.2.10",
        displayName: "Pi", targetID: "pi",
        approvalPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        denialPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        clientCertificatePEM: Data("certificate".utf8),
        source: sourceDescriptor, helper: helperDescriptor,
        randomBytes: { Data(repeating: 0xaa, count: 16) }
    )
    return CoordinatorArtifacts(
        directory: directory, settings: settings, request: request,
        stagedRequest: try StagedOnboardingRequest(request),
        source: try verifiedSource.makePrivateTransferCopy(),
        helper: try verifiedHelper.makePrivateTransferCopy()
    )
}
