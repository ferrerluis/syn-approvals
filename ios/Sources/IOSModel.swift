import Combine
import Foundation
import CryptoKit
import Network

@MainActor
final class IOSModel: ObservableObject {
    @Published private(set) var targets: [TargetRecord] = []
    @Published private(set) var pending: [VerifiedApprovalRequest] = []
    @Published private(set) var connected: Set<String> = []
    @Published private(set) var authenticating: Set<String> = []
    @Published var error: String?
    @Published var status: String?
    @Published var profileText = ""
    @Published var enrollmentText = ""
    @Published var machineHost = ""
    @Published var machinePort = "22"
    @Published private(set) var hostCandidate: MobileHostKey?
    @Published private(set) var bootstrapCommand: String?
    @Published private(set) var checkingHost = false
    private var checkedHost: String?
    private var checkedPort: Int?
    private var approvedHostKey: String?
    let deviceID: String
    let developmentSigner: Bool
    private let signer: any DecisionSigning
    private let store: TargetStore
    private var connections: [String: TargetConnection] = [:]
    private var connectionEpochs: [String: UUID] = [:]
    private var seen: [String: (hash: Data, expires: Date, completed: Bool)] = [:]
    private var cancellations: [String: ApprovalCancellation] = [:]
    private var reconnectTasks: [String: Task<Void, Never>] = [:]
    private var failures: Set<String> = []
    private var foreground = false

    init(fileURL: URL? = nil) throws {
        store = try TargetStore(fileURL: fileURL)
        targets = try store.load()
        if let saved = UserDefaults.standard.string(forKey: "deviceID") { deviceID = saved }
        else {
            deviceID = UUID().uuidString.lowercased()
            UserDefaults.standard.set(deviceID, forKey: "deviceID")
        }
        #if targetEnvironment(simulator) && DEBUG
        signer = try SimulatorDecisionSigner()
        developmentSigner = true
        #else
        signer = SynKeyStore()
        developmentSigner = false
        #endif
    }

    func prepareEnrollment() async {
        do {
            let signer = signer
            let identities = try await Task.detached {
                (try signer.approvalPublicKey(), try signer.denialPublicKey())
            }.value
            let label = "Syn iOS \(deviceID) transport"
            let der = try IOSTransportIdentityStore.certificate(label: label)
            let value = IOSEnrollment(deviceID: deviceID, displayName: "iPhone", development: developmentSigner,
                approvalPublicX963Base64: identities.0.base64EncodedString(),
                denialPublicX963Base64: identities.1.base64EncodedString(),
                clientCertificatePEM: IOSTransportIdentityStore.pem(der))
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let publicEnrollment = try encoder.encode(value)
            enrollmentText = String(decoding: publicEnrollment, as: UTF8.self)
            let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            let directory = base.appendingPathComponent("Syn", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try publicEnrollment.write(to: directory.appendingPathComponent("enrollment.json"), options: [.atomic, .completeFileProtection])
        } catch { self.error = "Could not prepare this device’s identity: \(error.localizedDescription)" }
    }

    func checkHost() async {
        guard !checkingHost else { return }
        checkingHost = true
        // A failed check must not display a previous machine's trust context.
        hostCandidate = nil; bootstrapCommand = nil; approvedHostKey = nil
        checkedHost = nil; checkedPort = nil
        defer { checkingHost = false }
        do {
            guard let port = Int(machinePort) else { throw SynProtocolError.invalid("Enter a valid SSH port.") }
            let hostname = machineHost.trimmingCharacters(in: .whitespacesAndNewlines)
            let client = try MobileSSH(host: hostname, port: port, hostKey: nil)
            let candidate = try await client.inspectHost()
            checkedHost = hostname; checkedPort = port; hostCandidate = candidate
            approvedHostKey = nil; bootstrapCommand = nil
            let saved = UserDefaults.standard.string(forKey: "trustedSSH:\(hostname):\(port)")
            if saved == candidate.publicKey { await trustHost() }
            else if saved != nil { error = "SSH host identity changed. Verify the machine independently before continuing." }
        } catch { self.error = error.localizedDescription }
    }

    func trustHost() async {
        guard let candidate = hostCandidate, let host = checkedHost, let port = checkedPort,
              machineHost.trimmingCharacters(in: .whitespacesAndNewlines) == host, Int(machinePort) == port else { return }
        UserDefaults.standard.set(candidate.publicKey, forKey: "trustedSSH:\(host):\(port)")
        approvedHostKey = candidate.publicKey
        await prepareEnrollment()
        guard !enrollmentText.isEmpty else { return }
        do {
            let client = try MobileSSH(host: host, port: port, hostKey: candidate.publicKey)
            // Every interpolated field comes from a generated UUID or canonical Ed25519 public key.
            bootstrapCommand = "/usr/bin/sudo /usr/bin/synctl approvers authorize --device-id \(deviceID) --public-key '\(client.publicKey)'"
                + (developmentSigner ? " --allow-development" : "") + " --apply"
        } catch { self.error = error.localizedDescription }
    }

    func connectMobile() async {
        guard let host = checkedHost, let port = checkedPort, let approvedHostKey,
              machineHost.trimmingCharacters(in: .whitespacesAndNewlines) == host, Int(machinePort) == port,
              !enrollmentText.isEmpty else { error = "Check and verify the machine’s SSH identity first."; return }
        do {
            let client = try MobileSSH(host: host, port: port, hostKey: approvedHostKey)
            let data = try await client.enroll(Data(enrollmentText.utf8))
            profileText = String(decoding: data, as: UTF8.self)
            importProfile()
        } catch { self.error = "Setup could not complete: \(error.localizedDescription)" }
    }

    func importProfile() {
        do {
            var target = try JSONDecoder().decode(TargetRecord.self, from: Data(profileText.utf8))
            guard !target.targetID.isEmpty, target.publicKey != nil,
                  target.webSocketURL.scheme == "wss", target.webSocketURL.host != nil,
                  target.webSocketURL.user == nil, target.webSocketURL.password == nil,
                  target.webSocketURL.query == nil, target.webSocketURL.fragment == nil,
                  target.serverCertificateSHA256Hex.count == 64,
                  target.serverCertificateSHA256Hex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
                throw SynProtocolError.invalid("The machine profile is invalid.")
            }
            // Identity labels are local state, never trusted from an imported profile.
            target.clientIdentityLabel = "Syn iOS \(deviceID) transport"
            guard try IOSTransportIdentityStore.connectionIdentity(label: target.clientIdentityLabel) != nil else {
                throw SynProtocolError.invalid("Prepare this iPhone’s identity before pairing.")
            }
            var updated = targets.filter { $0.id != target.id }
            updated.append(target)
            try store.save(updated)
            if let prior = targets.first(where: { $0.id == target.id }) { disconnect(prior, retry: false) }
            targets = updated
            profileText = ""
            failures.remove(target.id)
            if foreground { connect(target) }
        } catch { self.error = error.localizedDescription }
    }

    func setForeground(_ active: Bool) {
        foreground = active
        if active { for target in targets where !failures.contains(target.id) { connect(target) } }
        else {
            reconnectTasks.values.forEach { $0.cancel() }
            reconnectTasks.removeAll()
            connectionEpochs.removeAll()
            connections.values.forEach { $0.stop() }
            connections.removeAll()
            connected.removeAll()
            for request in pending { finish(request, terminal: false) }
        }
    }

    func retry() {
        failures.removeAll()
        if foreground { for target in targets { connect(target) } }
    }

    private func connect(_ target: TargetRecord) {
        guard foreground, connections[target.id] == nil else { return }
        reconnectTasks.removeValue(forKey: target.id)?.cancel()
        let epoch = UUID()
        connectionEpochs[target.id] = epoch
        let connection = TargetConnection(target: target) { [weak self] event in
            Task { @MainActor in
                guard let self, self.foreground, self.connectionEpochs[target.id] == epoch else { return }
                self.receive(event, target: target)
            }
        }
        connections[target.id] = connection
        connection.start()
    }

    func receive(_ event: Result<WireMessage, Error>, target: TargetRecord) {
        do {
            let message = try event.get()
            switch message.kind {
            case .hello:
                guard !connected.contains(target.id) else { throw SynProtocolError.invalid("Duplicate machine identity handshake.") }
                try SynProtocol.verifyHello(message.body, targetID: target.id)
                connected.insert(target.id)
                let connection = connections[target.id]
                let hello = try SynProtocol.helloBody(targetID: target.id)
                Task {
                    do {
                        try await connection?.send(.init(kind: .hello, body: hello))
                    } catch { self.disconnect(target, retry: true) }
                }
            case .request:
                guard connected.contains(target.id) else { throw SynProtocolError.invalid("Request arrived before identity verification.") }
                let request = try SynProtocol.verifyRequest(message.body, target: target)
                guard !request.isExpired, request.issuedAt.timeIntervalSinceNow < 30 else {
                    throw SynProtocolError.invalid("Request is expired or issued in the future.")
                }
                expire()
                if let existing = seen[request.id] {
                    guard existing.hash == request.payloadHash else { throw SynProtocolError.invalid("Request identity was reused.") }
                    if existing.completed || pending.contains(where: { $0.id == request.id }) { return }
                }
                guard pending.count < 64, seen.count < 128 else { throw SynProtocolError.invalid("Too many approval requests.") }
                seen[request.id] = (request.payloadHash, request.expiresAt, false)
                pending.append(request)
            case .cancel:
                let map = try CBORCodec.decodeCanonical(message.body).integerKeyedMap()
                guard map.count == 1, let id = map[0]?.bytesValue, id.count == 16 else {
                    throw SynProtocolError.invalid("Invalid cancellation.")
                }
                for request in pending where request.targetID == target.id && request.requestID == id { finish(request) }
            case .ping:
                let connection = connections[target.id]
                Task { try? await connection?.send(.init(kind: .pong, body: message.body)) }
            case .pong, .result: break
            default: throw SynProtocolError.invalid("Unexpected machine message.")
            }
        } catch {
            self.error = "Connection to \(target.displayName) stopped: \(error.localizedDescription)"
            // Integrity failures stay stopped until an explicit retry.
            let unavailable = event.failureIsUnavailable
            if !unavailable { failures.insert(target.id) }
            disconnect(target, retry: unavailable)
        }
    }

    private func disconnect(_ target: TargetRecord, retry: Bool) {
        connectionEpochs.removeValue(forKey: target.id)
        connections.removeValue(forKey: target.id)?.stop()
        connected.remove(target.id)
        for request in pending where request.targetID == target.id { finish(request, terminal: false) }
        guard retry, foreground, reconnectTasks[target.id] == nil else { return }
        reconnectTasks[target.id] = Task {
            do { try await Task.sleep(for: .seconds(3)) } catch { return }
            self.reconnectTasks.removeValue(forKey: target.id)
            if self.foreground { self.connect(target) }
        }
    }

    func expire() {
        for request in pending where request.isExpired { finish(request) }
        seen = seen.filter { $0.value.expires > Date() }
    }

    func approve(_ id: String) async {
        guard let request = pending.first(where: { $0.id == id }), !request.isExpired,
              authenticating.insert(id).inserted else { return }
        let cancellation = ApprovalCancellation()
        cancellations[id] = cancellation
        defer { authenticating.remove(id); cancellations.removeValue(forKey: id)?.cancel() }
        do {
            let signed = try await DecisionBuilder.sign(request: request, approve: true,
                reason: "Approve this one invocation on \(request.targetID)", signer: signer, cancellation: cancellation)
            guard !request.isExpired, pending.contains(where: { $0.id == id }) else { return }
            finish(request)
            guard let connection = connections[request.targetID] else { throw URLError(.networkConnectionLost) }
            try await connection.send(.init(kind: .decision, body: signed))
            status = "Approval sent. Check the original machine invocation for its result."
        } catch {
            if pending.contains(where: { $0.id == id }) { await deny(id) }
            self.error = "Approval was canceled or delivery could not be confirmed. Check the original invocation."
        }
    }

    func deny(_ id: String) async {
        guard let request = pending.first(where: { $0.id == id }) else { return }
        finish(request)
        guard !request.isExpired else { return }
        do {
            let signed = try await DecisionBuilder.sign(request: request, approve: false, reason: "", signer: signer)
            guard !request.isExpired, let connection = connections[request.targetID] else { return }
            try await connection.send(.init(kind: .decision, body: signed))
        } catch { self.error = "Denial delivery could not be confirmed. The machine may offer password fallback after timeout." }
    }

    private func finish(_ request: VerifiedApprovalRequest, terminal: Bool = true) {
        if terminal, let previous = seen[request.id] { seen[request.id] = (previous.hash, previous.expires, true) }
        cancellations.removeValue(forKey: request.id)?.cancel()
        pending.removeAll { $0.id == request.id }
    }
}

private extension Result where Success == WireMessage, Failure == Error {
    var failureIsUnavailable: Bool {
        guard case let .failure(error) = self else { return false }
        return error is URLError || error is Network.NWError
    }
}

struct IOSEnrollment: Encodable {
    let schemaVersion = 1
    let deviceID: String
    let displayName: String
    let development: Bool
    let approvalPublicX963Base64: String
    let denialPublicX963Base64: String
    let clientCertificatePEM: String
}
