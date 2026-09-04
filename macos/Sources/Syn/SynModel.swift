import AppKit
import Combine
import CryptoKit
import Foundation
import ServiceManagement

@MainActor
final class SynModel: ObservableObject {
    @Published private(set) var targets: [TargetRecord] = []
    @Published private(set) var pending: [VerifiedApprovalRequest] = []
    @Published private(set) var connectedTargets: Set<String> = []
    @Published private(set) var authenticatingRequests: Set<String> = []
    @Published private(set) var connectionErrors: [String: String] = [:]
    @Published private(set) var pausedConnections: Set<String> = []
    @Published private(set) var preparingKeys = false
    @Published private(set) var keysReady = false
    @Published var selectedRequestID: String?
    @Published var lastError: String?
    @Published var pairingProfileText = ""
    @Published private(set) var approverIdentityText = "Generate the Mac identities before pairing."
    var openMainWindow: (() -> Void)?

    private let store: TargetStore?
    private let keyStore: SynKeyStore
    private let signer: any DecisionSigning
    private let servicesEnabled: Bool
    private let decisionSender: (@MainActor (WireMessage, String) async throws -> Void)?
    private let notifications = SynNotificationCenter()
    private var connections: [String: TargetConnection] = [:]
    private var seenRequests: [String: (hash: Data, expiresAt: Date)] = [:]
    private var reconnectAttempts: [String: Int] = [:]
    private var reconnectTasks: [String: Task<Void, Never>] = [:]
    private var approvalCancellations: [String: ApprovalCancellation] = [:]

    init(
        startServices: Bool = true,
        signer: (any DecisionSigning)? = nil,
        decisionSender: (@MainActor (WireMessage, String) async throws -> Void)? = nil
    ) {
        let keyStore = SynKeyStore()
        self.keyStore = keyStore
        self.signer = signer ?? keyStore
        servicesEnabled = startServices
        self.decisionSender = decisionSender
        guard startServices else { store = nil; return }
        store = try? TargetStore()
        if let store {
            do { targets = try store.load() }
            catch { lastError = "The saved target list is unreadable: \(error.localizedDescription)" }
        } else {
            lastError = "Syn cannot open its Application Support directory."
        }
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

    var selectedRequest: VerifiedApprovalRequest? {
        guard let selectedRequestID else { return pending.first }
        return pending.first { $0.id == selectedRequestID }
    }

    func target(for request: VerifiedApprovalRequest) -> TargetRecord? {
        targets.first { $0.targetID == request.targetID }
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
            // that could later open the Pi's ordinary-unavailability fallback.
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
            lastError = "Approval delivery could not be confirmed. Check the original Pi invocation before retrying."
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
            lastError = "Denial could not reach the Pi. Nothing was approved, but the Pi may offer its timeout fallback."
        }
    }

    func review(_ requestID: String) {
        selectedRequestID = requestID
        openMainWindow?()
        if servicesEnabled { NSApp.activate(ignoringOtherApps: true) }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        // SMAppService is not observable; refresh its status-backed toggle
        // after registration rather than waiting for an unrelated model change.
        defer { objectWillChange.send() }
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            lastError = "Launch at login could not be changed: \(error.localizedDescription)"
        }
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

    private func connectAll() {
        for target in targets where connections[target.targetID] == nil { connect(target) }
    }

    private func connect(_ target: TargetRecord) {
        let connection = TargetConnection(target: target) { [weak self] result in
            Task { @MainActor in self?.handle(result, from: target) }
        }
        connections[target.targetID] = connection
        connection.start()
    }

    private func handle(_ result: Result<WireMessage, Error>, from target: TargetRecord) {
        switch result {
        case let .failure(error):
            recordConnectionFailure(error, from: target)
        case let .success(message):
            do {
                switch message.kind {
                case .hello:
                    let map = try CBORCodec.decodeCanonical(message.body).integerKeyedMap()
                    guard map.count == 3, map[0]?.unsignedValue == 1, map[1]?.unsignedValue == 1,
                          map[2]?.textValue == target.targetID else {
                        throw SynProtocolError.invalid("target hello did not match the pinned target")
                    }
                    connectedTargets.insert(target.targetID)
                    connectionErrors.removeValue(forKey: target.targetID)
                    pausedConnections.remove(target.targetID)
                    reconnectTasks.removeValue(forKey: target.targetID)?.cancel()
                    reconnectAttempts[target.targetID] = 0
                    let hello = try CBORCodec.encode(.map([
                        (.unsigned(0), .unsigned(1)),
                        (.unsigned(1), .unsigned(1)),
                        (.unsigned(2), .text(target.targetID)),
                    ]))
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

    private func send(_ message: WireMessage, to targetID: String) async throws {
        if let decisionSender { try await decisionSender(message, targetID); return }
        guard let connection = connections[targetID] else { throw URLError(.notConnectedToInternet) }
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
        guard keysReady else { return }
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
