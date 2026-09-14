import Foundation
import Testing
@testable import Syn

private actor SetupCheckerFixture: MachineSetupChecking {
    enum Reply: Sendable { case result(RemoteMachinePreflight), failure(SSHProbeFailure), wait }
    let reply: Reply
    private(set) var calls: [SSHConnectionSettings] = []

    init(_ reply: Reply) { self.reply = reply }

    func check(_ settings: SSHConnectionSettings) async throws -> RemoteMachinePreflight {
        calls.append(settings)
        switch reply {
        case let .result(value): return value
        case let .failure(error): throw error
        case .wait:
            try await Task.sleep(for: .seconds(30))
            throw CancellationError()
        }
    }
}

private actor SequencedSetupChecker: MachineSetupChecking {
    var replies: [Result<RemoteMachinePreflight, SSHProbeFailure>]
    private(set) var calls: [SSHConnectionSettings] = []
    init(_ replies: [Result<RemoteMachinePreflight, SSHProbeFailure>]) { self.replies = replies }
    func check(_ settings: SSHConnectionSettings) async throws -> RemoteMachinePreflight {
        calls.append(settings)
        guard !replies.isEmpty else { throw SSHProbeFailure.invalidOutput }
        return try replies.removeFirst().get()
    }
}

private actor HostScannerFixture: SSHHostKeyScanning {
    let records: [SSHHostKeyRecord]
    private(set) var calls = 0
    init(records: [SSHHostKeyRecord]) { self.records = records }
    func scan(_ settings: SSHConnectionSettings) async throws -> SSHHostTrustCandidate {
        calls += 1
        return SSHHostTrustCandidate(settings: settings, records: records)
    }
}

private struct RouteResolverFixture: SSHMaintenanceRouteResolving {
    let hostname: String
    func resolve(_ settings: SSHConnectionSettings) async throws -> SSHMaintenanceRoute {
        SSHMaintenanceRoute(hostname: hostname, arguments: [])
    }
}

@MainActor
private func waitForSetup(_ model: SynModel) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while model.addMachineState == .checking, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(model.addMachineState != .checking)
}

@Test @MainActor func addMachineValidatesBeforeOpeningSSH() async throws {
    let checker = SetupCheckerFixture(.wait)
    let model = SynModel(startServices: false, setupChecker: checker)
    model.addMachineHostname = "bad;host"
    model.addMachineUsername = "developer"
    model.checkMachineForSetup()
    guard case .failed = model.addMachineState else {
        Issue.record("invalid destination was not rejected")
        return
    }
    #expect(await checker.calls.isEmpty)
    model.addMachineHostname = "pi.example"
    model.addMachinePort = "70000"
    model.checkMachineForSetup()
    guard case .failed = model.addMachineState else {
        Issue.record("invalid port was not rejected")
        return
    }
    #expect(await checker.calls.isEmpty)
}

@Test @MainActor func addMachineReportsFreshAndInstalledMachines() async throws {
    let settings = SSHConnectionSettings(hostname: "pi.example", username: "developer", port: 2222)
    let fresh = SetupCheckerFixture(.result(.init(
        settings: settings, serverAddress: "192.168.2.10", installation: .notInstalled
    )))
    let freshModel = SynModel(startServices: false, setupChecker: fresh)
    freshModel.addMachineHostname = " pi.example "
    freshModel.addMachineUsername = " developer "
    freshModel.addMachinePort = "2222"
    freshModel.checkMachineForSetup()
    try await waitForSetup(freshModel)
    #expect(freshModel.addMachineState == .readyToInstall)
    #expect(await fresh.calls == [settings])

    let status = RemoteInstallationStatus(
        configuration: .configured,
        release: .init(schemaVersion: 1, releaseID: "20260906160000", commit: String(repeating: "a", count: 40)),
        targetID: "pi", managedUID: 1000
    )
    let installed = SetupCheckerFixture(.result(.init(
        settings: settings, serverAddress: "192.168.2.10", installation: .installed(status)
    )))
    let installedModel = SynModel(startServices: false, setupChecker: installed)
    installedModel.addMachineHostname = settings.hostname
    installedModel.addMachineUsername = settings.username
    installedModel.addMachinePort = "2222"
    installedModel.checkMachineForSetup()
    try await waitForSetup(installedModel)
    #expect(installedModel.addMachineState == .installed(releaseID: "20260906160000", configuration: "configured"))
}

@Test func checkedMachineUsesEffectiveSSHHostnameForTransportWithoutReplacingAlias() {
    for (sshHost, effectiveHost) in [
        ("pi", "ferrerluis97-everest.nord"),
        ("pi.example", "pi.example"),
    ] {
        let settings = SSHConnectionSettings(hostname: sshHost, username: "developer", port: 2222)
        let checked = RemoteMachinePreflight(
            settings: settings, serverAddress: "100.99.102.171",
            transportHostname: effectiveHost, installation: .notInstalled
        )
        #expect(checked.transportHostname == effectiveHost)
        #expect(checked.serverAddress == "100.99.102.171")
        #expect(checked.settings.hostname == sshHost)
    }
}

@Test @MainActor func addMachineFailureCanRetryAndCancellationIsQuiet() async throws {
    let failed = SetupCheckerFixture(.failure(.unavailable))
    let model = SynModel(startServices: false, setupChecker: failed)
    model.addMachineHostname = "pi"
    model.addMachineUsername = "developer"
    model.checkMachineForSetup()
    try await waitForSetup(model)
    guard case let .failed(message) = model.addMachineState else {
        Issue.record("connection failure was not reported")
        return
    }
    #expect(message.contains("could not be verified"))

    let waiting = SetupCheckerFixture(.wait)
    let cancellation = SynModel(startServices: false, setupChecker: waiting)
    cancellation.addMachineHostname = "pi"
    cancellation.addMachineUsername = "developer"
    cancellation.checkMachineForSetup()
    #expect(cancellation.addMachineState == .checking)
    cancellation.cancelMachineCheck()
    #expect(cancellation.addMachineState == .idle)
    try await Task.sleep(for: .milliseconds(20))
    #expect(cancellation.addMachineState == .idle)
}

@Test @MainActor func partiallyConfiguredRetryPreservesReservedTargetIdentity() async throws {
    let settings = SSHConnectionSettings(hostname: "pi", username: "developer", port: nil)
    let checker = SequencedSetupChecker([
        .success(.init(settings: settings, serverAddress: "100.99.102.171", installation: .notInstalled)),
        .success(.init(settings: settings, serverAddress: "100.99.102.171", installation: .updateRequired(nil))),
        .success(.init(
            settings: SSHConnectionSettings(hostname: "other", username: "developer", port: nil),
            serverAddress: "100.99.102.172", installation: .notInstalled
        )),
    ])
    let model = SynModel(startServices: false, setupChecker: checker)
    model.addMachineHostname = settings.hostname
    model.addMachineUsername = settings.username

    model.checkMachineForSetup()
    try await waitForSetup(model)
    model.installCheckedMachine()
    let reserved = try #require(model.setupTargetID)
    #expect(reserved.hasPrefix("target_"))

    // A failed activation may recover the remote configuration before the user
    // checks the same machine again. Keep the request-bound identity locally.
    model.checkMachineForSetup()
    try await waitForSetup(model)
    #expect(model.addMachineState == .updateRequired)
    model.installCheckedMachine()
    #expect(model.setupTargetID == reserved)

    model.addMachineHostname = "other"
    model.checkMachineForSetup()
    try await waitForSetup(model)
    #expect(model.setupTargetID == nil)
    model.installCheckedMachine()
    #expect(model.setupTargetID != reserved)
}

@Test @MainActor func savedTargetUpdateReusesSSHAndPreservesVisibleIdentity() async throws {
    let settings = SSHConnectionSettings(hostname: "pi.example", username: "developer", port: 2222)
    let checker = SetupCheckerFixture(.result(.init(
        settings: settings, serverAddress: "192.168.2.10",
        installation: .updateRequired(nil)
    )))
    let model = SynModel(startServices: false, setupChecker: checker)
    let target = TargetRecord(
        targetID: "preserved-id", displayName: "Workshop Pi",
        webSocketURL: try #require(URL(string: "wss://pi.example:7443")),
        targetPublicKeyBase64: "", serverCertificateSHA256Hex: "",
        clientIdentityLabel: "Syn preserved-id transport", ssh: settings
    )
    model.updateMachine(target)
    try await waitForSetup(model)
    #expect(await checker.calls == [settings])
    #expect(model.addMachineHostname == settings.hostname)
    #expect(model.addMachineUsername == settings.username)
    #expect(model.addMachinePort == "2222")
    #expect(model.addMachineState == .updateRequired)
}

@Test @MainActor func unknownHostRequiresExplicitTrustThenRetriesFromSynStore() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("syn-guided-trust-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let store = try SynKnownHostsStore(fileURL: root.appendingPathComponent("SSH/known_hosts"))
    let initial = SSHConnectionSettings(hostname: "pi.example", username: "developer", port: 2222)
    let trusted = SSHConnectionSettings(
        hostname: initial.hostname, username: initial.username, port: initial.port,
        hostTrustSource: .synKnownHosts
    )
    let checker = SequencedSetupChecker([
        .failure(.unknownHost),
        .success(.init(settings: trusted, serverAddress: "192.168.2.10", installation: .notInstalled)),
    ])
    let record = SSHHostKeyRecord(
        hostField: "[pi.example]:2222", algorithm: "ssh-ed25519",
        keyBase64: Data([1, 2, 3]).base64EncodedString()
    )
    let scanner = HostScannerFixture(records: [record])
    let model = SynModel(
        startServices: false, setupChecker: checker,
        hostKeyScanner: scanner, knownHostsStore: store
    )
    model.addMachineHostname = initial.hostname
    model.addMachineUsername = initial.username
    model.addMachinePort = "2222"
    model.checkMachineForSetup()
    try await waitForSetup(model)
    guard case let .confirmHost(candidate) = model.addMachineState else {
        Issue.record("unknown host did not require confirmation")
        return
    }
    #expect(candidate.records == [record])
    #expect(await scanner.calls == 1)
    model.trustPendingSSHHost()
    try await waitForSetup(model)
    #expect(model.addMachineState == .readyToInstall)
    #expect((await checker.calls).last?.hostTrustSource == .synKnownHosts)
    #expect(try String(contentsOf: store.fileURL, encoding: .utf8) == record.line + "\n")
}

@Test @MainActor func changedSavedHostIdentityHasNoScanOrOverwritePath() async throws {
    let scanner = HostScannerFixture(records: [])
    let checker = SetupCheckerFixture(.failure(.changedHostKey))
    let model = SynModel(startServices: false, setupChecker: checker, hostKeyScanner: scanner)
    model.addMachineHostname = "pi.example"
    model.addMachineUsername = "developer"
    model.checkMachineForSetup()
    try await waitForSetup(model)
    guard case .failed = model.addMachineState else {
        Issue.record("changed host key was not a hard stop")
        return
    }
    #expect(await scanner.calls == 0)
}

@Test @MainActor func provisionalSuccessClearsGhostConnectedStateBeforePromotion() throws {
    let model = SynModel(startServices: false)
    let target = provisionalTarget()
    model.handleTargetMessage(.success(.init(
        kind: .hello, body: try SynProtocol.helloBody(targetID: target.targetID)
    )), from: target)
    #expect(model.connectedTargets.contains(target.targetID))
    model.removeProvisionalTarget(target.targetID)
    #expect(!model.connectedTargets.contains(target.targetID))
    #expect(!model.hasReconnectState(for: target.targetID))
}

@Test @MainActor func provisionalFailureClearsErrorsPauseAndPendingApproval() throws {
    let model = SynModel(startServices: false)
    let target = provisionalTarget()
    let request = provisionalRequest(targetID: target.targetID)
    try model.enqueueVerified(request)
    model.selectedRequestID = request.id
    model.recordConnectionFailure(TransportError.clientAuthorizationIncomplete, from: target)
    #expect(model.pausedConnections.contains(target.targetID))
    #expect(model.connectionErrors[target.targetID] != nil)
    #expect(!model.pending.isEmpty)
    model.removeProvisionalTarget(target.targetID)
    #expect(!model.pausedConnections.contains(target.targetID))
    #expect(model.connectionErrors[target.targetID] == nil)
    #expect(model.pending.isEmpty)
    #expect(model.selectedRequestID == nil)
    #expect(!model.hasReconnectState(for: target.targetID))
}

@Test @MainActor func provisionalCancellationClearsQueuedRequestsAndSelection() throws {
    let model = SynModel(startServices: false)
    let target = provisionalTarget()
    let request = provisionalRequest(targetID: target.targetID)
    try model.enqueueVerified(request)
    model.selectedRequestID = request.id
    model.removeProvisionalTarget(target.targetID)
    #expect(model.pending.isEmpty)
    #expect(model.selectedRequestID == nil)
    #expect(!model.connectedTargets.contains(target.targetID))
    #expect(!model.hasReconnectState(for: target.targetID))
}

private func provisionalTarget() -> TargetRecord {
    TargetRecord(
        targetID: "provisional", displayName: "Provisional machine",
        webSocketURL: URL(string: "wss://machine.example:7443")!,
        targetPublicKeyBase64: "", serverCertificateSHA256Hex: "",
        clientIdentityLabel: "Syn provisional transport"
    )
}

private func provisionalRequest(targetID: String) -> VerifiedApprovalRequest {
    VerifiedApprovalRequest(
        signedBytes: Data(), payloadHash: Data(repeating: 1, count: 32),
        requestID: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
        targetID: targetID, issuedAt: .now, expiresAt: Date().addingTimeInterval(90),
        invokingUID: 1000, invokingUser: "user", runAsUID: 0, runAsUser: "root",
        runAsGroup: "root", workingDirectory: Data("/tmp".utf8),
        executable: Data("/usr/bin/true".utf8), arguments: [], environmentNames: [],
        environmentDigest: Data(repeating: 4, count: 32), riskMarkers: [],
        releaseID: ReleaseIdentity.current.releaseID,
        releaseCommit: SynProtocol.developmentCommit
    )
}

@Test func preflightTreatsOnlyEmptyRemote127AsNotInstalled() async throws {
    let settings = SSHConnectionSettings(hostname: "pi", username: "developer", port: nil)
    let replies = ProbeFixtureForSetup([
        .init(status: 0, stdout: Data("Linux aarch64\n".utf8)),
        .init(status: 0, stdout: Data("ID=ubuntu\nVERSION_ID=26.04\n".utf8)),
        .init(status: 0, stdout: Data("192.168.2.20 50000 192.168.2.10 22\n".utf8)),
        .init(status: 127, stdout: Data()),
    ])
    let result = try await SSHMachineSetupChecker(
        probe: .init(runner: replies), routeResolver: RouteResolverFixture(hostname: "pi")
    ).check(settings)
    #expect(result.installation == .notInstalled)
}

@Test func preflightRecognizesTheExistingAlphaAsUpdateRequired() async throws {
    let settings = SSHConnectionSettings(hostname: "pi", username: "developer", port: nil)
    let legacy = #"{"ok":true,"data":{"configured":false,"target_id":null,"managed_user":null,"managed_uid":null,"listen":null,"overlay":null,"approver_ip":null,"timeout_seconds":null,"agent_socket":null,"target_key_id":null}}"#
    let replies = ProbeFixtureForSetup([
        .init(status: 0, stdout: Data("Linux aarch64\n".utf8)),
        .init(status: 0, stdout: Data("ID=ubuntu\nVERSION_ID=26.04\n".utf8)),
        .init(status: 0, stdout: Data("192.168.2.20 50000 192.168.2.10 22\n".utf8)),
        .init(status: 0, stdout: Data(legacy.utf8)),
    ])
    let result = try await SSHMachineSetupChecker(
        probe: .init(runner: replies), routeResolver: RouteResolverFixture(hostname: "pi")
    ).check(settings)
    #expect(result.installation == .updateRequired(nil))

    let malformed = ProbeFixtureForSetup([
        .init(status: 0, stdout: Data("Linux aarch64\n".utf8)),
        .init(status: 0, stdout: Data("ID=ubuntu\nVERSION_ID=26.04\n".utf8)),
        .init(status: 0, stdout: Data("192.168.2.20 50000 192.168.2.10 22\n".utf8)),
        .init(status: 0, stdout: Data(legacy.dropLast().utf8)),
    ])
    await #expect(throws: SSHProbeFailure.invalidOutput) {
        try await SSHMachineSetupChecker(
            probe: .init(runner: malformed), routeResolver: RouteResolverFixture(hostname: "pi")
        ).check(settings)
    }
}

@Test func preflightDerivesServerAddressAndRequiresExactInstalledRelease() async throws {
    let settings = SSHConnectionSettings(hostname: "pi", username: "developer", port: nil)
    let release = ReleaseIdentity(
        schemaVersion: 1, releaseID: "20260908000000", commit: String(repeating: "a", count: 40)
    )
    let status = #"{"ok":true,"data":{"schema_version":1,"configured":true,"configuration_state":"configured","release_id":"20260908000000","release_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_id":"pi","managed_uid":1000}}"#
    func replies(_ body: String) -> ProbeFixtureForSetup {
        ProbeFixtureForSetup([
            .init(status: 0, stdout: Data("Linux aarch64\n".utf8)),
            .init(status: 0, stdout: Data("ID=ubuntu\nVERSION_ID=26.04\n".utf8)),
            .init(status: 0, stdout: Data("192.168.2.20 50000 192.168.2.10 22\n".utf8)),
            .init(status: 0, stdout: Data(body.utf8)),
        ])
    }
    let exact = try await SSHMachineSetupChecker(
        probe: .init(runner: replies(status)), expectedRelease: release,
        routeResolver: RouteResolverFixture(hostname: "ferrerluis97-everest.nord")
    ).check(settings)
    #expect(exact.serverAddress == "192.168.2.10")
    #expect(exact.transportHostname == "ferrerluis97-everest.nord")
    guard case .installed = exact.installation else {
        Issue.record("exact configured release was not accepted")
        return
    }

    let mismatch = status.replacingOccurrences(of: String(repeating: "a", count: 40),
                                                with: String(repeating: "b", count: 40))
    let update = try await SSHMachineSetupChecker(
        probe: .init(runner: replies(mismatch)), expectedRelease: release,
        routeResolver: RouteResolverFixture(hostname: "ferrerluis97-everest.nord")
    ).check(settings)
    guard case .updateRequired = update.installation else {
        Issue.record("release mismatch was not marked for update")
        return
    }
}

@Test func sshConnectionServerAddressParsingFailsClosed() throws {
    #expect(try SSHMachineSetupChecker.parseServerAddress(.init(
        status: 0, stdout: Data("2001:db8::2 50000 2001:db8::1 22\n".utf8)
    )) == "2001:db8::1")
    for line in [
        "192.168.2.20 50000 127.0.0.1 22\n",
        "192.168.2.20 nope 192.168.2.10 22\n",
        "192.168.2.20 50000 192.168.2.10 0\n",
        "192.168.2.20 50000 $(command) 22\n",
        "192.168.2.20 50000 192.168.2.10 22 extra\n",
    ] {
        #expect(throws: SSHProbeFailure.self) {
            try SSHMachineSetupChecker.parseServerAddress(.init(status: 0, stdout: Data(line.utf8)))
        }
    }
}

@Test @MainActor func oldTargetRecordsMigrateAsOfflineUpdateRequired() throws {
    let old = #"{"targetID":"pi","displayName":"Pi","webSocketURL":"wss://pi:7443","targetPublicKeyBase64":"","serverCertificateSHA256Hex":"","clientIdentityLabel":"Syn pi transport"}"#
    let target = try JSONDecoder().decode(TargetRecord.self, from: Data(old.utf8))
    #expect(target.installedReleaseID == nil)
    #expect(SynModel.requiresUpdate(target, for: .init(
        schemaVersion: 1, releaseID: "20260908000000", commit: String(repeating: "a", count: 40)
    )))
}

private actor ProbeFixtureForSetup: SSHProbeRunning {
    var replies: [SSHProbeOutput]
    init(_ replies: [SSHProbeOutput]) { self.replies = replies }
    func run(settings: SSHConnectionSettings, operation: SSHReadOnlyOperation) async throws -> SSHProbeOutput {
        guard !replies.isEmpty else { throw SSHProbeFailure.invalidOutput }
        return replies.removeFirst()
    }
}
