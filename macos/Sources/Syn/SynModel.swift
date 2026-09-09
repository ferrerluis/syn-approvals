import AppKit
import Combine
import CryptoKit
import Foundation
import ServiceManagement

@MainActor
final class SynModel: ObservableObject {
    enum AddMachineState: Equatable {
        case idle
        case checking
        case readyToInstall
        case updateRequired
        case confirmHost(SSHHostTrustCandidate)
        case installing(RemoteOnboardingProgress)
        case installed(releaseID: String, configuration: String)
        case failed(String)
    }

    static func requiresUpdate(_ target: TargetRecord, for release: ReleaseIdentity) -> Bool {
        target.installedReleaseID != release.releaseID
            || target.installedReleaseCommit != release.commit
    }

    @Published private(set) var targets: [TargetRecord] = []
    @Published private(set) var pending: [VerifiedApprovalRequest] = []
    @Published private(set) var connectedTargets: Set<String> = []
    @Published private(set) var authenticatingRequests: Set<String> = []
    @Published private(set) var connectionErrors: [String: String] = [:]
    @Published private(set) var pausedConnections: Set<String> = []
    @Published private(set) var updateRequiredTargets: Set<String> = []
    @Published private(set) var preparingKeys = false
    @Published private(set) var keysReady = false
    @Published var showStartupPrompt = false
    @Published var selectedRequestID: String?
    @Published var lastError: String?
    @Published var pairingProfileText = ""
    @Published var addMachineHostname = ""
    @Published var addMachineUsername = ""
    @Published var addMachinePort = ""
    @Published private(set) var addMachineState: AddMachineState = .idle
    @Published private(set) var maintenanceBootstrapCommand: String?
    @Published private(set) var approverIdentityText = "Generate the Mac identities before pairing."
    var openMainWindow: (() -> Void)?

    private let store: TargetStore?
    private let keyStore: SynKeyStore
    private let signer: any DecisionSigning
    private let servicesEnabled: Bool
    private let startupPreference: StartupPreference?
    private let decisionSender: (@MainActor (WireMessage, String) async throws -> Void)?
    private let setupChecker: any MachineSetupChecking
    private let hostKeyScanner: any SSHHostKeyScanning
    private let knownHostsStore: SynKnownHostsStore?
    private let onboardingCoordinator = RemoteOnboardingCoordinator()
    private let transportIdentityStore = TransportIdentityStore()
    private let notifications = SynNotificationCenter()
    private var connections: [String: TargetConnection] = [:]
    private var seenRequests: [String: (hash: Data, expiresAt: Date)] = [:]
    private var reconnectAttempts: [String: Int] = [:]
    private var reconnectTasks: [String: Task<Void, Never>] = [:]
    private var approvalCancellations: [String: ApprovalCancellation] = [:]
    private var setupTask: Task<Void, Never>?
    private var checkedSetup: RemoteMachinePreflight?
    private var setupIdentity: (targetID: String, displayName: String)?
    private var pendingHostCandidate: SSHHostTrustCandidate?
    private var provisionalConnections: [String: TargetConnection] = [:]
    private var provisionalTargets: [String: TargetRecord] = [:]
    private var provisionalStreams: [String: AsyncThrowingStream<WireMessage, Error>.Continuation] = [:]
    private var verifiedProvisionalTargets: Set<String> = []

    init(
        startServices: Bool = true,
        signer: (any DecisionSigning)? = nil,
        decisionSender: (@MainActor (WireMessage, String) async throws -> Void)? = nil,
        setupChecker: any MachineSetupChecking = SSHMachineSetupChecker(),
        hostKeyScanner: any SSHHostKeyScanning = SystemSSHHostKeyScanner(),
        knownHostsStore: SynKnownHostsStore? = nil
    ) {
        let keyStore = SynKeyStore()
        self.keyStore = keyStore
        self.signer = signer ?? keyStore
        servicesEnabled = startServices
        startupPreference = startServices ? StartupPreference() : nil
        self.decisionSender = decisionSender
        self.setupChecker = setupChecker
        self.hostKeyScanner = hostKeyScanner
        self.knownHostsStore = knownHostsStore ?? (try? SynKnownHostsStore())
        guard startServices else { store = nil; return }
        store = try? TargetStore()
        if let store {
            do {
                targets = try store.load()
                let release = ReleaseIdentity.current
                for target in targets where Self.requiresUpdate(target, for: release) {
                    updateRequiredTargets.insert(target.targetID)
                    connectionErrors[target.targetID] = "Update required: this machine has not been verified for this Mac release."
                }
            }
            catch { lastError = "The saved target list is unreadable: \(error.localizedDescription)" }
        } else {
            lastError = "Syn cannot open its Application Support directory."
        }
        showStartupPrompt = startupPreference?.shouldAsk(existingTargets: !targets.isEmpty) == true
        notifications.onReview = { [weak self] requestID in
            Task { @MainActor in self?.review(requestID) }
        }
        notifications.onDeny = { [weak self] requestID in
            Task { @MainActor in await self?.deny(requestID) }
        }
        Task {
            do { try await notifications.configure() }
            catch { lastError = "Notifications are unavailable: \(error.localizedDescription)" }
        }
        if !targets.isEmpty {
            Task { await prepareApproverIdentities(); if keysReady { connectAll() } }
        }
    }

    func checkMachineForSetup() {
        setupIdentity = nil
        checkMachineForSetup(preserving: nil, settingsOverride: nil)
    }

    func updateMachine(_ target: TargetRecord) {
        guard let ssh = target.ssh else {
            connectionErrors[target.targetID] = "Saved SSH settings are required to update this machine."
            return
        }
        addMachineHostname = ssh.hostname
        addMachineUsername = ssh.username
        addMachinePort = ssh.port.map(String.init) ?? ""
        setupIdentity = (target.targetID, target.displayName)
        checkMachineForSetup(preserving: setupIdentity, settingsOverride: ssh)
    }

    private func checkMachineForSetup(
        preserving identity: (targetID: String, displayName: String)?,
        settingsOverride: SSHConnectionSettings?
    ) {
        setupTask?.cancel()
        maintenanceBootstrapCommand = nil
        let port: UInt16?
        if addMachinePort.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            port = nil
        } else if let value = UInt16(addMachinePort), value != 0 {
            port = value
        } else {
            addMachineState = .failed("Enter a valid SSH port from 1 through 65535.")
            return
        }
        let settings = settingsOverride ?? SSHConnectionSettings(
            hostname: addMachineHostname.trimmingCharacters(in: .whitespacesAndNewlines),
            username: addMachineUsername.trimmingCharacters(in: .whitespacesAndNewlines),
            port: port
        )
        do { try settings.validate() }
        catch {
            addMachineState = .failed(error.localizedDescription)
            return
        }
        addMachineState = .checking
        let checker = setupChecker
        setupTask = Task { [weak self] in
            do {
                let result = try await checker.check(settings)
                try Task.checkCancellation()
                guard let self else { return }
                self.checkedSetup = result
                switch result.installation {
                case .notInstalled:
                    self.addMachineState = .readyToInstall
                case let .updateRequired(status):
                    if identity == nil, let targetID = status?.targetID {
                        if let saved = self.targets.first(where: { $0.targetID == targetID }) {
                            self.setupIdentity = (saved.targetID, saved.displayName)
                        } else {
                            self.setupIdentity = (targetID, settings.hostname)
                        }
                    }
                    self.addMachineState = .updateRequired
                case let .installed(status):
                    self.addMachineState = .installed(
                        releaseID: status.release.releaseID,
                        configuration: status.configuration.rawValue
                    )
                }
            } catch is CancellationError {
                // Explicit cancellation is quiet and makes retry immediately available.
            } catch let failure as SSHProbeFailure where failure == .unknownHost
                && settings.hostTrustSource == .existingOpenSSH {
                do {
                    let candidate = try await self?.hostKeyScanner.scan(settings)
                    guard let self, let candidate else { return }
                    self.pendingHostCandidate = candidate
                    self.addMachineState = .confirmHost(candidate)
                } catch {
                    self?.addMachineState = .failed(error.localizedDescription)
                }
            } catch {
                self?.addMachineState = .failed(error.localizedDescription)
            }
        }
    }

    func trustPendingSSHHost() {
        guard let candidate = pendingHostCandidate else { return }
        do {
            guard let knownHostsStore else { throw SSHProbeFailure.unavailable }
            _ = try knownHostsStore.trust(candidate)
            pendingHostCandidate = nil
            let trusted = SSHConnectionSettings(
                hostname: candidate.settings.hostname,
                username: candidate.settings.username,
                port: candidate.settings.port,
                hostTrustSource: .synKnownHosts
            )
            checkMachineForSetup(preserving: setupIdentity, settingsOverride: trusted)
        } catch {
            addMachineState = .failed(error.localizedDescription)
        }
    }

    func cancelHostConfirmation() {
        pendingHostCandidate = nil
        addMachineState = .idle
    }

    func cancelMachineCheck() {
        setupTask?.cancel()
        setupTask = nil
        switch addMachineState {
        case .checking: addMachineState = .idle
        case .installing: break
        default: break
        }
    }

    func installCheckedMachine() {
        guard let checkedSetup else {
            addMachineState = .failed("Check the SSH connection before starting setup.")
            return
        }
        let targetID = setupIdentity?.targetID
            ?? "target_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())"
        let displayName = setupIdentity?.displayName ?? checkedSetup.settings.hostname
        let listenIP = checkedSetup.serverAddress
        let requiresRecovery: Bool
        switch checkedSetup.installation {
        case .notInstalled: requiresRecovery = false
        case .updateRequired, .installed: requiresRecovery = true
        }
        setupTask?.cancel()
        let settings = checkedSetup.settings
        let keyStore = self.keyStore
        let identityStore = transportIdentityStore
        let coordinator = onboardingCoordinator
        addMachineState = .installing(.staging)
        setupTask = Task { [weak self] in
            do {
                let source = try BundledRemoteSource.current()
                let helper = try BundledRemoteHelper.current()
                let stagedSource = try source.makePrivateTransferCopy()
                let stagedHelper = try helper.makePrivateTransferCopy()
                defer { stagedSource.remove(); stagedHelper.remove() }
                let maintenance = try await Task.detached {
                    try SSHMaintenanceIdentity.prepare(for: settings)
                }.value
                do {
                    try await coordinator.verifyMaintenance(settings: settings, identity: maintenance)
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    try await SSHSourceTransfer().transferBootstrapHelper(stagedHelper, to: settings)
                    let command = try SSHMaintenanceBootstrap.command(
                        settings: settings, identity: maintenance, helper: helper.descriptor
                    )
                    guard let self else { return }
                    self.maintenanceBootstrapCommand = command
                    self.addMachineState = requiresRecovery ? .updateRequired : .readyToInstall
                    return
                }
                self?.maintenanceBootstrapCommand = nil
                let publicKeys = try await Task.detached { try keyStore.publicIdentities() }.value
                let transport = try await Task.detached {
                    try identityStore.identity(for: targetID)
                }.value
                let request = try RemoteOnboardingRequest.make(
                    settings: settings,
                    resolvedHostname: settings.hostname,
                    listenIP: listenIP,
                    displayName: displayName,
                    targetID: targetID,
                    approvalPublicKey: publicKeys.approval,
                    denialPublicKey: publicKeys.denial,
                    clientCertificatePEM: transport.certificatePEM,
                    source: source.descriptor,
                    helper: helper.descriptor
                )
                guard request.clientIdentityLabel == transport.label else {
                    throw SynProtocolError.invalid("The transport identity does not match this target.")
                }
                let stagedRequest = try StagedOnboardingRequest(request)
                defer { stagedRequest.remove() }
                guard let model = self else { throw CancellationError() }
                let target = try await coordinator.run(
                    request: request, stagedRequest: stagedRequest,
                    source: stagedSource, helper: stagedHelper,
                    settings: settings, identity: maintenance,
                    requiresRecovery: requiresRecovery,
                    configureTarget: { target in
                        try await model.prepareProvisionalTarget(target)
                    }
                ) { phase in
                    await MainActor.run { model.addMachineState = .installing(phase) }
                }
                guard let self else { return }
                try self.validate(target)
                guard let store = self.store else {
                    throw SynProtocolError.invalid("target storage is unavailable")
                }
                var next = self.targets.filter { $0.targetID != target.targetID }
                next.append(target)
                try store.save(next)
                self.removeProvisionalTarget(target.targetID)
                self.connections.removeValue(forKey: target.targetID)?.stop()
                self.targets = next
                self.addMachineState = .installed(
                    releaseID: request.releaseID, configuration: "configured"
                )
                if self.keysReady { self.connect(target) }
            } catch is CancellationError {
                self?.removeProvisionalTarget(targetID)
                self?.addMachineState = .idle
            } catch {
                self?.removeProvisionalTarget(targetID)
                self?.addMachineState = .failed(error.localizedDescription)
            }
        }
    }

    var selectedRequest: VerifiedApprovalRequest? {
        guard let selectedRequestID else { return pending.first }
        return pending.first { $0.id == selectedRequestID }
    }

    func target(for request: VerifiedApprovalRequest) -> TargetRecord? {
        targets.first { $0.targetID == request.targetID } ?? provisionalTargets[request.targetID]
    }

    func importTargetProfile() {
        do {
            let target = try JSONDecoder().decode(TargetRecord.self, from: Data(pairingProfileText.utf8))
            try validate(target)
            guard !targets.contains(where: { $0.targetID == target.targetID }) else {
                throw SynProtocolError.invalid("A target with this ID is already paired")
            }
            guard let store else { throw SynProtocolError.invalid("target storage is unavailable") }
            try store.save(targets + [target])
            targets.append(target)
            pairingProfileText = ""
            Task {
                if !keysReady { await prepareApproverIdentities() }
                if keysReady { connect(target) }
            }
        } catch {
            lastError = "Target import failed: \(error.localizedDescription)"
        }
    }

    func generateApproverIdentities() {
        Task { await prepareApproverIdentities(); if keysReady { connectAll() } }
    }

    private func prepareApproverIdentities() async {
        guard !preparingKeys else { return }
        preparingKeys = true
        defer { preparingKeys = false }
        do {
            let keyStore = self.keyStore
            let identities = try await Task.detached { try keyStore.publicIdentities() }.value
            let object: [String: Any] = [
                "schema_version": 1,
                "approval_public_key_x963_base64": identities.approval.base64EncodedString(),
                "approval_key_id": Data(SHA256.hash(data: identities.approval)).hex,
                "denial_public_key_x963_base64": identities.denial.base64EncodedString(),
                "denial_key_id": Data(SHA256.hash(data: identities.denial)).hex,
            ]
            let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
            approverIdentityText = String(decoding: data, as: UTF8.self)
            keysReady = true
        } catch {
            keysReady = false
            lastError = "Approver identities could not be created: \(error.localizedDescription)"
        }
    }

    func copyApproverIdentities() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(approverIdentityText, forType: .string)
    }

    func removeTarget(_ target: TargetRecord) {
        reconnectTasks.removeValue(forKey: target.targetID)?.cancel()
        pausedConnections.remove(target.targetID)
        connectionErrors.removeValue(forKey: target.targetID)
        updateRequiredTargets.remove(target.targetID)
        connections.removeValue(forKey: target.targetID)?.stop()
        targets.removeAll { $0.targetID == target.targetID }
        pending.removeAll { $0.targetID == target.targetID }
        connectedTargets.remove(target.targetID)
        do {
            guard let store else { throw SynProtocolError.invalid("target storage is unavailable") }
            try store.save(targets)
        }
        catch { lastError = "Target removal could not be saved: \(error.localizedDescription)" }
    }

    func approve(_ requestID: String) async {
        guard let request = pending.first(where: { $0.id == requestID }) else { return }
        guard authenticatingRequests.insert(requestID).inserted else { return }
        let cancellation = ApprovalCancellation()
        approvalCancellations[requestID] = cancellation
        defer {
            authenticatingRequests.remove(requestID)
            approvalCancellations.removeValue(forKey: requestID)?.cancel()
        }
        guard !request.isExpired else {
            finish(request)
            lastError = "That approval request has expired."
            return
        }
        let decision: Data
        do {
            decision = try await DecisionBuilder.sign(
                request: request,
                approve: true,
                reason: "Approve this one sudo invocation on \(target(for: request)?.displayName ?? request.targetID)",
                signer: signer,
                cancellation: cancellation
            )
        } catch {
            // Canceling or failing system authentication is a denial, not silence
            // that could later open the remote machine's ordinary-unavailability fallback.
            await deny(requestID)
            if lastError == nil { lastError = "Approval canceled or unsuccessful. Nothing was approved." }
            return
        }
        guard !request.isExpired, pending.contains(where: { $0.id == request.id }) else {
            finish(request)
            lastError = "The request expired or was canceled while macOS checked your identity. Nothing was approved."
            return
        }
        // Once delivery starts, a lost connection cannot tell us whether the
        // target received the decision. Never describe that as proven denial.
        finish(request)
        do {
            try await send(.init(kind: .decision, body: decision), to: request.targetID)
        } catch {
            lastError = "Approval delivery could not be confirmed. Check the original remote machine invocation before retrying."
        }
    }

    func deny(_ requestID: String) async {
        guard let request = pending.first(where: { $0.id == requestID }) else { return }
        // Remove first: an approval already waiting for authentication may no
        // longer send, even if denial signing or delivery subsequently fails.
        finish(request)
        guard !request.isExpired else { return }
        do {
            let decision = try await DecisionBuilder.sign(
                request: request,
                approve: false,
                reason: "",
                signer: signer
            )
            guard !request.isExpired else { return }
            try await send(.init(kind: .decision, body: decision), to: request.targetID)
        } catch {
            lastError = "Denial could not reach the remote machine. Nothing was approved, but it may offer its timeout fallback."
        }
    }

    func review(_ requestID: String) {
        selectedRequestID = requestID
        openMainWindow?()
        if servicesEnabled { NSApp.activate(ignoringOtherApps: true) }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        lastError = nil
        // SMAppService is not observable; refresh its status-backed toggle
        // after registration rather than waiting for an unrelated model change.
        defer { objectWillChange.send() }
        do {
            try startupPreference?.choose(enabled)
            showStartupPrompt = false
        } catch {
            lastError = "Launch at login could not be changed: \(error.localizedDescription)"
        }
    }

    func dismissStartupPrompt() {
        startupPreference?.dismiss()
        showStartupPrompt = false
    }

    private func validate(_ target: TargetRecord) throws {
        guard !target.targetID.isEmpty, target.targetID.count <= 128,
              !target.displayName.isEmpty,
              target.webSocketURL.scheme == "wss",
              target.publicKey != nil,
              target.serverCertificateSHA256Hex.count == 64,
              target.serverCertificateSHA256Hex.allSatisfy({ $0.isHexDigit }),
              !target.clientIdentityLabel.isEmpty else {
            throw SynProtocolError.invalid("The pairing profile is incomplete or unsafe")
        }
    }

    private func prepareProvisionalTarget(_ target: TargetRecord) async throws {
        try validate(target)
        removeProvisionalTarget(target.targetID)
        var streamContinuation: AsyncThrowingStream<WireMessage, Error>.Continuation?
        let stream = AsyncThrowingStream<WireMessage, Error> { streamContinuation = $0 }
        guard let continuation = streamContinuation else { throw SSHProbeFailure.unavailable }
        provisionalStreams[target.targetID] = continuation
        let connection = TargetConnection(target: target) { [weak self] result in
            Task { @MainActor in
                guard let self else { return }
                if self.verifiedProvisionalTargets.contains(target.targetID) {
                    self.handleTargetMessage(result, from: target)
                } else {
                    switch result {
                    case let .success(message): continuation.yield(message)
                    case let .failure(error): continuation.finish(throwing: error)
                    }
                }
            }
        }
        provisionalConnections[target.targetID] = connection
        provisionalTargets[target.targetID] = target
        connection.start()
        do {
            let hello = try await withThrowingTaskGroup(of: WireMessage.self) { group in
                group.addTask {
                    for try await message in stream { return message }
                    throw SSHProbeFailure.unavailable
                }
                group.addTask {
                    try await Task.sleep(for: .seconds(20))
                    throw SSHProbeFailure.timedOut
                }
                guard let first = try await group.next() else { throw SSHProbeFailure.unavailable }
                group.cancelAll()
                return first
            }
            guard hello.kind == .hello else { throw SSHProbeFailure.invalidOutput }
            try SynProtocol.verifyHello(hello.body, targetID: target.targetID)
            verifiedProvisionalTargets.insert(target.targetID)
            try await connection.send(.init(
                kind: .hello, body: try SynProtocol.helloBody(targetID: target.targetID)
            ))
        } catch {
            removeProvisionalTarget(target.targetID)
            throw error
        }
    }

    func removeProvisionalTarget(_ targetID: String) {
        verifiedProvisionalTargets.remove(targetID)
        provisionalStreams.removeValue(forKey: targetID)?.finish()
        provisionalConnections.removeValue(forKey: targetID)?.stop()
        provisionalTargets.removeValue(forKey: targetID)
        connectedTargets.remove(targetID)
        connectionErrors.removeValue(forKey: targetID)
        pausedConnections.remove(targetID)
        reconnectTasks.removeValue(forKey: targetID)?.cancel()
        reconnectAttempts.removeValue(forKey: targetID)
        let provisionalRequests = pending.filter { $0.targetID == targetID }
        for request in provisionalRequests {
            authenticatingRequests.remove(request.id)
            finish(request)
        }
    }

    func hasReconnectState(for targetID: String) -> Bool {
        reconnectTasks[targetID] != nil || reconnectAttempts[targetID] != nil
    }

    private func connectAll() {
        for target in targets where connections[target.targetID] == nil { connect(target) }
    }

    private func connect(_ target: TargetRecord) {
        let connection = TargetConnection(target: target) { [weak self] result in
            Task { @MainActor in self?.handleTargetMessage(result, from: target) }
        }
        connections[target.targetID] = connection
        connection.start()
    }

    func handleTargetMessage(_ result: Result<WireMessage, Error>, from target: TargetRecord) {
        switch result {
        case let .failure(error):
            recordConnectionFailure(error, from: target)
        case let .success(message):
            do {
                switch message.kind {
                case .hello:
                    do {
                        try SynProtocol.verifyHello(message.body, targetID: target.targetID)
                    } catch {
                        if helloHasReleaseMismatch(message.body, targetID: target.targetID) {
                            markUpdateRequired(target)
                            return
                        }
                        throw error
                    }
                    guard recordCurrentRelease(for: target) else { return }
                    connectedTargets.insert(target.targetID)
                    updateRequiredTargets.remove(target.targetID)
                    connectionErrors.removeValue(forKey: target.targetID)
                    pausedConnections.remove(target.targetID)
                    reconnectTasks.removeValue(forKey: target.targetID)?.cancel()
                    reconnectAttempts[target.targetID] = 0
                    let hello = try SynProtocol.helloBody(targetID: target.targetID)
                    let connection = connections[target.targetID]
                    Task { try? await connection?.send(.init(kind: .hello, body: hello)) }
                case .request:
                    let request = try SynProtocol.verifyRequest(message.body, target: target)
                    // Future clock skew is bounded separately from the 90-second approval TTL.
                    guard !request.isExpired, request.issuedAt.timeIntervalSinceNow < 30 else {
                        throw SynProtocolError.invalid("request is expired or issued in the future")
                    }
                    pruneExpiredRequests()
                    if let existing = seenRequests[request.id] {
                        guard existing.hash == request.payloadHash else {
                            throw SynProtocolError.invalid("request ID was reused with a different payload")
                        }
                        return
                    }
                    try enqueueVerified(request)
                    Task { try? await notifications.post(request: request, targetName: target.displayName) }
                case .cancel:
                    let map = try CBORCodec.decodeCanonical(message.body).integerKeyedMap()
                    guard map.count == 1, let requestID = map[0]?.bytesValue else {
                        throw SynProtocolError.invalid("invalid cancellation")
                    }
                    if let request = pending.first(where: {
                        $0.targetID == target.targetID && $0.requestID == requestID
                    }) { finish(request) }
                case .ping:
                    let connection = connections[target.targetID]
                    Task { try? await connection?.send(.init(kind: .pong, body: message.body)) }
                case .result, .pong: break
                default: throw SynProtocolError.invalid("unexpected target message")
                }
            } catch {
                lastError = "Rejected data from \(target.displayName): \(error.localizedDescription)"
            }
        }
    }

    private func helloHasReleaseMismatch(_ data: Data, targetID: String) -> Bool {
        guard let remote = try? CBORCodec.decodeCanonical(data).integerKeyedMap(),
              remote.count == 5,
              remote[0]?.unsignedValue == SynProtocol.version,
              remote[1]?.unsignedValue == SynProtocol.version,
              remote[2]?.textValue == targetID,
              let localData = try? SynProtocol.helloBody(targetID: targetID),
              let local = try? CBORCodec.decodeCanonical(localData).integerKeyedMap() else {
            return false
        }
        return remote[3]?.textValue != local[3]?.textValue
            || remote[4]?.textValue != local[4]?.textValue
    }

    private func markUpdateRequired(_ target: TargetRecord) {
        connections[target.targetID]?.stop()
        connectedTargets.remove(target.targetID)
        pausedConnections.insert(target.targetID)
        updateRequiredTargets.insert(target.targetID)
        reconnectTasks.removeValue(forKey: target.targetID)?.cancel()
        connectionErrors[target.targetID] = "Update required: this machine and Mac app use different Syn releases."
    }

    private func recordCurrentRelease(for target: TargetRecord) -> Bool {
        guard let index = targets.firstIndex(where: { $0.targetID == target.targetID }) else {
            updateRequiredTargets.remove(target.targetID)
            return true
        }
        let release = ReleaseIdentity.current
        var next = targets
        next[index].installedReleaseID = release.releaseID
        next[index].installedReleaseCommit = release.commit
        do {
            if let store { try store.save(next) }
            targets = next
            updateRequiredTargets.remove(target.targetID)
            return true
        } catch {
            markUpdateRequired(target)
            connectionErrors[target.targetID] = "Update verification could not be saved."
            return false
        }
    }

    private func send(_ message: WireMessage, to targetID: String) async throws {
        if let decisionSender { try await decisionSender(message, targetID); return }
        guard let connection = connections[targetID] ?? provisionalConnections[targetID] else {
            throw URLError(.notConnectedToInternet)
        }
        try await connection.send(message)
    }

    private func scheduleReconnect(_ target: TargetRecord) {
        guard servicesEnabled, !pausedConnections.contains(target.targetID) else { return }
        reconnectTasks.removeValue(forKey: target.targetID)?.cancel()
        let attempt = min((reconnectAttempts[target.targetID] ?? 0) + 1, 10)
        reconnectAttempts[target.targetID] = attempt
        let base = min(pow(2.0, Double(attempt - 1)), 60)
        let jitter = Double.random(in: 0...(base * 0.2))
        reconnectTasks[target.targetID] = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(base + jitter)) }
            catch { return }
            guard let self, self.targets.contains(target),
                  !self.pausedConnections.contains(target.targetID),
                  !self.connectedTargets.contains(target.targetID) else { return }
            self.connections[target.targetID]?.start()
        }
    }

    func recordConnectionFailure(_ error: Error, from target: TargetRecord) {
        connectedTargets.remove(target.targetID)
        connectionErrors[target.targetID] = error.localizedDescription
        if let error = error as? TransportError, error.requiresUserRetry {
            pausedConnections.insert(target.targetID)
            reconnectTasks.removeValue(forKey: target.targetID)?.cancel()
        } else {
            scheduleReconnect(target)
        }
    }

    func retryConnection(_ target: TargetRecord) {
        guard keysReady, !updateRequiredTargets.contains(target.targetID) else { return }
        pausedConnections.remove(target.targetID)
        connectionErrors.removeValue(forKey: target.targetID)
        reconnectTasks.removeValue(forKey: target.targetID)?.cancel()
        reconnectAttempts[target.targetID] = 0
        if let connection = connections[target.targetID] { connection.start() }
        else { connect(target) }
    }

    private func finish(_ request: VerifiedApprovalRequest) {
        approvalCancellations.removeValue(forKey: request.id)?.cancel()
        pending.removeAll { $0.id == request.id }
        if servicesEnabled { notifications.remove(requestID: request.id) }
        if selectedRequestID == request.id { selectedRequestID = pending.first?.id }
    }

    func enqueueVerified(_ request: VerifiedApprovalRequest) throws {
        pruneExpiredRequests()
        guard !request.isExpired else { throw SynProtocolError.invalid("request has expired") }
        guard pending.filter({ $0.targetID == request.targetID }).count < 16, seenRequests.count < 4096 else {
            throw SynProtocolError.invalid("target approval queue is full")
        }
        guard !pending.contains(where: { $0.id == request.id }) else {
            throw SynProtocolError.invalid("request is already pending")
        }
        seenRequests[request.id] = (request.payloadHash, request.expiresAt)
        pending.append(request)
        if servicesEnabled {
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(max(0, request.expiresAt.timeIntervalSinceNow)))
                guard let self else { return }
                self.pruneExpiredRequests()
            }
        }
    }

    func pruneExpiredRequests() {
        for request in pending where request.isExpired { finish(request) }
        seenRequests = seenRequests.filter { $0.value.expiresAt > .now }
    }
}
