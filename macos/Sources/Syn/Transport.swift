import CryptoKit
import Foundation
import Security

enum TransportError: Error, LocalizedError {
    case invalidPin
    case missingClientIdentity(String)
    case unexpectedMessage

    var errorDescription: String? {
        switch self {
        case .invalidPin: "The target TLS certificate does not match its pinned fingerprint"
        case let .missingClientIdentity(label): "The client identity \(label) is missing from Keychain"
        case .unexpectedMessage: "The target sent an unsupported WebSocket message"
        }
    }
}

final class TargetConnection: @unchecked Sendable {
    let target: TargetRecord
    private let onMessage: @Sendable (Result<WireMessage, Error>) -> Void
    private let delegate: PinnedSessionDelegate
    private var session: URLSession?
    private var task: URLSessionWebSocketTask?

    init(target: TargetRecord, onMessage: @escaping @Sendable (Result<WireMessage, Error>) -> Void) {
        self.target = target
        self.onMessage = onMessage
        self.delegate = PinnedSessionDelegate(target: target)
    }

    func start() {
        guard task == nil else { return }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = true
        configuration.timeoutIntervalForRequest = 20
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        let task = session.webSocketTask(with: target.webSocketURL)
        self.session = session
        self.task = task
        task.resume()
        receiveNext()
    }

    func stop() {
        task?.cancel(with: .goingAway, reason: nil)
        session?.invalidateAndCancel()
        task = nil
        session = nil
    }

    func send(_ wire: WireMessage) async throws {
        guard let task else { throw URLError(.notConnectedToInternet) }
        try await task.send(.data(try wire.encoded()))
    }

    private func receiveNext() {
        guard let task else { return }
        task.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case let .success(.data(data)):
                do {
                    self.onMessage(.success(try WireMessage(data: data)))
                    self.receiveNext()
                } catch {
                    self.onMessage(.failure(error))
                    self.stop()
                }
            case .success(.string):
                self.onMessage(.failure(TransportError.unexpectedMessage))
                self.stop()
            case let .failure(error):
                self.onMessage(.failure(error))
                self.stop()
            @unknown default:
                self.onMessage(.failure(TransportError.unexpectedMessage))
                self.stop()
            }
        }
    }
}

private final class PinnedSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    let target: TargetRecord

    init(target: TargetRecord) { self.target = target }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            guard let trust = challenge.protectionSpace.serverTrust,
                  let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let certificate = chain.first else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            let digest = Data(SHA256.hash(data: SecCertificateCopyData(certificate) as Data)).hex
            guard constantTimeEqual(digest.lowercased(), target.serverCertificateSHA256Hex.lowercased()) else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))

        case NSURLAuthenticationMethodClientCertificate:
            guard let identity = Self.identity(label: target.clientIdentityLabel) else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(
                .useCredential,
                URLCredential(identity: identity, certificates: [certificate], persistence: .forSession)
            )

        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }

    private static func identity(label: String) -> SecIdentity? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecAttrLabel: label,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnRef: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return (result as! SecIdentity)
    }

    private func constantTimeEqual(_ left: String, _ right: String) -> Bool {
        let a = Array(left.utf8)
        let b = Array(right.utf8)
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
