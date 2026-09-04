import CryptoKit
import Foundation
import Network
import Security

enum TransportError: Error, LocalizedError {
    case invalidPin
    case missingClientIdentity(String)
    case unexpectedMessage
    case clientAuthorizationIncomplete

    var errorDescription: String? {
        switch self {
        case .invalidPin: "The target TLS certificate does not match its pinned fingerprint"
        case let .missingClientIdentity(label): "The client identity \(label) is missing from Keychain"
        case .unexpectedMessage: "The target sent an unsupported WebSocket message"
        case .clientAuthorizationIncomplete: "Secure connection setup was interrupted after certificate verification. Finish any Syn Keychain permission, then choose Retry. Automatic retries are paused."
        }
    }

    var requiresUserRetry: Bool { true }
}

final class HandshakeProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var checked = false
    private var trusted = false
    private var ready = false

    func recordTrust(_ accepted: Bool) { lock.withLock { checked = true; trusted = accepted } }
    func recordReady() { lock.withLock { ready = true } }
    func classified(_ error: Error) -> Error {
        lock.withLock {
            if checked && !trusted { return TransportError.invalidPin }
            if trusted && !ready { return TransportError.clientAuthorizationIncomplete }
            return error
        }
    }
}

// Network.framework permits per-connection trust without weakening ATS globally
// or installing a target certificate in the system trust store.
@MainActor
final class TargetConnection {
    let target: TargetRecord
    private let onMessage: @Sendable (Result<WireMessage, Error>) -> Void
    private var connection: NWConnection?
    private var connectionDeadline: Task<Void, Never>?
    private var handshake = HandshakeProgress()
    static let setupTimeoutSeconds: Double = 130

    init(target: TargetRecord, onMessage: @escaping @Sendable (Result<WireMessage, Error>) -> Void) {
        self.target = target
        self.onMessage = onMessage
    }

    func start() {
        guard connection == nil else { return }
        guard target.webSocketURL.scheme == "wss", let hostname = target.webSocketURL.host,
              let identity = Self.identity(label: target.clientIdentityLabel),
              let localIdentity = sec_identity_create(identity) else {
            onMessage(.failure(TransportError.missingClientIdentity(target.clientIdentityLabel)))
            return
        }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, hostname)
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, localIdentity)
        let pin = target.serverCertificateSHA256Hex
        let handshake = HandshakeProgress()
        self.handshake = handshake
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { @Sendable _, trust, complete in
            let trustRef = sec_trust_copy_ref(trust).takeRetainedValue()
            let accepted = Self.verifyTrust(trustRef, hostname: hostname, pin: pin)
            handshake.recordTrust(accepted)
            complete(accepted)
        }, DispatchQueue(label: "org.syn-approvals.tls-verification"))

        let parameters = NWParameters(tls: tls)
        let websocket = NWProtocolWebSocket.Options()
        websocket.autoReplyPing = true
        websocket.maximumMessageSize = 64 * 1024
        parameters.defaultProtocolStack.applicationProtocols.insert(websocket, at: 0)
        let connection = NWConnection(to: .url(target.webSocketURL), using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            Task { @MainActor in
                guard let self, let connection, self.connection === connection else { return }
                switch state {
                case .ready:
                    handshake.recordReady()
                    self.connectionDeadline?.cancel()
                    self.connectionDeadline = nil
                    self.receiveNext(connection)
                case let .failed(error), let .waiting(error):
                    self.fail(error)
                case .cancelled:
                    self.fail(URLError(.networkConnectionLost))
                default: break
                }
            }
        }
        connectionDeadline = Task { [weak self, weak connection] in
            do { try await Task.sleep(for: .seconds(Self.setupTimeoutSeconds)) }
            catch { return }
            guard let self, let connection, self.connection === connection else { return }
            self.fail(URLError(.timedOut))
        }
        connection.start(queue: .main)
    }

    func stop() {
        connectionDeadline?.cancel()
        connectionDeadline = nil
        let previous = connection
        connection = nil
        previous?.stateUpdateHandler = nil
        previous?.cancel()
    }

    func send(_ wire: WireMessage) async throws {
        guard let connection else { throw URLError(.notConnectedToInternet) }
        let data = try wire.encoded()
        let metadata = NWProtocolWebSocket.Metadata(opcode: .binary)
        let context = NWConnection.ContentContext(identifier: "syn-binary", metadata: [metadata])
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, contentContext: context, isComplete: true, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            })
        }
    }

    private func receiveNext(_ connection: NWConnection) {
        connection.receiveMessage { [weak self, weak connection] data, context, isComplete, error in
            Task { @MainActor in
                guard let self, let connection, self.connection === connection else { return }
                if let error { self.fail(error); return }
                guard let metadata = context?.protocolMetadata(definition: NWProtocolWebSocket.definition) as? NWProtocolWebSocket.Metadata else {
                    self.fail(Self.missingMetadataError(data: data, isComplete: isComplete))
                    return
                }
                switch metadata.opcode {
                case .binary:
                    do {
                        guard let data, data.count <= 64 * 1024 else { throw TransportError.unexpectedMessage }
                        self.onMessage(.success(try WireMessage(data: data)))
                    } catch { self.fail(error); return }
                case .ping, .pong: break
                case .close: self.fail(URLError(.networkConnectionLost)); return
                default: self.fail(TransportError.unexpectedMessage); return
                }
                self.receiveNext(connection)
            }
        }
    }

    nonisolated static func missingMetadataError(data: Data?, isComplete: Bool) -> Error {
        // Network.framework can finish a closed stream with no content or
        // WebSocket metadata. That is ordinary disconnection, not a frame to
        // approve. Nonempty, empty-but-present, or incomplete messages without
        // WebSocket metadata still fail as protocol errors.
        if data == nil && isComplete { return URLError(.networkConnectionLost) }
        return TransportError.unexpectedMessage
    }

    private func fail(_ error: Error) {
        let classified = handshake.classified(error)
        stop()
        onMessage(.failure(classified))
    }

    nonisolated static func verifyTrust(_ trust: SecTrust, hostname: String, pin: String) -> Bool {
        // Fresh SecTrust objects have no evaluated chain yet. This first pass
        // only builds it; its result is never an authorization decision.
        guard SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { return false }
        _ = SecTrustEvaluateWithError(trust, nil)
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let certificate = chain.first else { return false }
        let digest = Data(SHA256.hash(data: SecCertificateCopyData(certificate) as Data)).hex
        guard constantTimeEqual(digest, pin.lowercased()) else { return false }
        return SecTrustSetAnchorCertificates(trust, [certificate] as CFArray) == errSecSuccess
            && SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
            && SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess
            && SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, hostname as CFString)) == errSecSuccess
            && SecTrustEvaluateWithError(trust, nil)
    }

    private static func identity(label: String) -> SecIdentity? {
        // Identity queries do not reliably honor kSecAttrLabel on macOS.
        // Resolve the labeled certificate first, then its exact matching key.
        let query: [CFString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: label,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnRef: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        guard let result, CFGetTypeID(result) == SecCertificateGetTypeID() else { return nil }
        let certificate = result as! SecCertificate
        var commonName: CFString?
        guard SecCertificateCopyCommonName(certificate, &commonName) == errSecSuccess,
              commonName as String? == label else { return nil }
        var identity: SecIdentity?
        guard SecIdentityCreateWithCertificate(nil, certificate, &identity) == errSecSuccess,
              let identity else { return nil }
        var identityCertificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &identityCertificate) == errSecSuccess,
              let identityCertificate,
              SecCertificateCopyData(identityCertificate) as Data == SecCertificateCopyData(certificate) as Data else { return nil }
        return identity
    }

    nonisolated private static func constantTimeEqual(_ left: String, _ right: String) -> Bool {
        let a = Array(left.utf8)
        let b = Array(right.utf8)
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
