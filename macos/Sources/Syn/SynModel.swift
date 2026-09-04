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
    @Published var selectedRequestID: String?
    @Published var lastError: String?
    @Published var pairingProfileText = ""
    @Published private(set) var approverIdentityText = "Generate the Mac identities before pairing."

    private let store: TargetStore?
    private let keyStore = SynKeyStore()
    private let notifications = SynNotificationCenter()
    private var connections: [String: TargetConnection] = [:]
    private var seenRequestHashes: [String: Data] = [:]
    private var reconnectAttempts: [String: Int] = [:]

    init() {
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
        connectAll()
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
            targets.append(target)
            guard let store else { throw SynProtocolError.invalid("target storage is unavailable") }
            try store.save(targets)
            pairingProfileText = ""
            connect(target)
        } catch {
            lastError = "Target import failed: \(error.localizedDescription)"
        }
    }

    func generateApproverIdentities() {
        do {
            let identities = try keyStore.publicIdentities()
            let object: [String: Any] = [
                "schema_version": 1,
                "approval_public_key_x963_base64": identities.approval.base64EncodedString(),
                "approval_key_id": Data(SHA256.hash(data: identities.approval)).hex,
                "denial_public_key_x963_base64": identities.denial.base64EncodedString(),
                "denial_key_id": Data(SHA256.hash(data: identities.denial)).hex,
            ]
            let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
            approverIdentityText = String(decoding: data, as: UTF8.self)
        } catch {
            lastError = "Approver identities could not be created: \(error.localizedDescription)"
        }
    }

    func copyApproverIdentities() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(approverIdentityText, forType: .string)
    }

    func removeTarget(_ target: TargetRecord) {
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
        guard !request.isExpired else {
            finish(request)
            lastError = "That approval request has expired."
            return
        }
        do {
            let publicKeys = try keyStore.publicIdentities()
            let keyID = Data(SHA256.hash(data: publicKeys.approval))
            let payload = try SynProtocol.decisionPayload(
                request: request,
                approve: true,
                approverKeyID: keyID
            )
            let protected = try SynProtocol.protectedHeader(keyID: keyID)
            let signatureInput = try SynProtocol.signatureStructure(protected: protected, payload: payload)
            let signed = try keyStore.signApproval(
                payload: signatureInput,
                reason: "Approve this one sudo invocation on \(target(for: request)?.displayName ?? request.targetID)"
            )
            guard signed.keyID == keyID else { throw SynProtocolError.invalid("approval key changed unexpectedly") }
            let decision = try SynProtocol.coseSign1(payload: payload, keyID: keyID, signature: signed.signature)
            try await send(.init(kind: .decision, body: decision), to: request.targetID)
            finish(request)
        } catch {
            lastError = "Approval was not sent: \(error.localizedDescription)"
        }
    }

    func deny(_ requestID: String) async {
        guard let request = pending.first(where: { $0.id == requestID }) else { return }
        do {
            let publicKeys = try keyStore.publicIdentities()
            let keyID = Data(SHA256.hash(data: publicKeys.denial))
            let payload = try SynProtocol.decisionPayload(
                request: request,
                approve: false,
                approverKeyID: keyID
            )
            let protected = try SynProtocol.protectedHeader(keyID: keyID)
            let signatureInput = try SynProtocol.signatureStructure(protected: protected, payload: payload)
            let signed = try keyStore.signDenial(payload: signatureInput)
            guard signed.keyID == keyID else { throw SynProtocolError.invalid("denial key changed unexpectedly") }
            let decision = try SynProtocol.coseSign1(payload: payload, keyID: keyID, signature: signed.signature)
            try await send(.init(kind: .decision, body: decision), to: request.targetID)
            finish(request)
        } catch {
            lastError = "Denial was not sent: \(error.localizedDescription)"
        }
    }

    func review(_ requestID: String) {
        selectedRequestID = requestID
        NSApp.activate(ignoringOtherApps: true)
    }

    func setLaunchAtLogin(_ enabled: Bool) {
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
        for target in targets { connect(target) }
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
            connectedTargets.remove(target.targetID)
            lastError = "\(target.displayName) disconnected: \(error.localizedDescription)"
            scheduleReconnect(target)
        case let .success(message):
            do {
                switch message.kind {
                case .hello:
                    let map = try CBORCodec.decodeCanonical(message.body).integerKeyedMap()
                    guard map[0]?.unsignedValue == 1, map[1]?.unsignedValue == 1,
                          map[2]?.textValue == target.targetID else {
                        throw SynProtocolError.invalid("target hello did not match the pinned target")
                    }
                    connectedTargets.insert(target.targetID)
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
                    guard !request.isExpired, request.issuedAt.timeIntervalSinceNow < 30 else {
                        throw SynProtocolError.invalid("request is expired or issued in the future")
                    }
                    if let existing = seenRequestHashes[request.id] {
                        guard existing == request.payloadHash else {
                            throw SynProtocolError.invalid("request ID was reused with a different payload")
                        }
                        return
                    }
                    seenRequestHashes[request.id] = request.payloadHash
                    pending.append(request)
                    Task { try? await notifications.post(request: request, targetName: target.displayName) }
                case .cancel:
                    let map = try CBORCodec.decodeCanonical(message.body).integerKeyedMap()
                    guard map.count == 1, let requestID = map[0]?.bytesValue else {
                        throw SynProtocolError.invalid("invalid cancellation")
                    }
                    if let request = pending.first(where: { $0.requestID == requestID }) { finish(request) }
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
        guard let connection = connections[targetID] else { throw URLError(.notConnectedToInternet) }
        try await connection.send(message)
    }

    private func scheduleReconnect(_ target: TargetRecord) {
        let attempt = min((reconnectAttempts[target.targetID] ?? 0) + 1, 10)
        reconnectAttempts[target.targetID] = attempt
        let base = min(pow(2.0, Double(attempt - 1)), 60)
        let jitter = Double.random(in: 0...(base * 0.2))
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(base + jitter))
            guard let self, self.targets.contains(target),
                  !self.connectedTargets.contains(target.targetID) else { return }
            self.connections[target.targetID]?.start()
        }
    }

    private func finish(_ request: VerifiedApprovalRequest) {
        pending.removeAll { $0.id == request.id }
        notifications.remove(requestID: request.id)
        if selectedRequestID == request.id { selectedRequestID = pending.first?.id }
    }
}
