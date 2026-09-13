import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum KeyStoreError: Error, LocalizedError {
    case keychain(OSStatus)
    case secureEnclaveUnavailable

    var errorDescription: String? {
        switch self {
        case let .keychain(status): "Keychain operation failed (\(status))"
        case .secureEnclaveUnavailable: "Secure Enclave is unavailable on this Mac"
        }
    }
}

protocol DecisionSigning: Sendable {
    func approvalPublicKey() throws -> Data
    func denialPublicKey() throws -> Data
    func signApproval(payload: Data, reason: String, cancellation: ApprovalCancellation) throws -> (keyID: Data, signature: Data)
    func signDenial(payload: Data) throws -> (keyID: Data, signature: Data)
}

protocol DecisionSignerProviding: Sendable {
    func publicIdentities() throws -> (approval: Data, denial: Data)
    func signer(for request: VerifiedApprovalRequest) throws -> any DecisionSigning
}

struct FixedDecisionSignerProvider: DecisionSignerProviding {
    let signer: any DecisionSigning
    func publicIdentities() throws -> (approval: Data, denial: Data) {
        (try signer.approvalPublicKey(), try signer.denialPublicKey())
    }
    func signer(for request: VerifiedApprovalRequest) throws -> any DecisionSigning { signer }
}

final class ApprovalCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var canceled = false
    private var handler: (@Sendable () -> Void)?

    func install(_ handler: @escaping @Sendable () -> Void) {
        let invoke = lock.withLock {
            if canceled { return true }
            self.handler = handler
            return false
        }
        if invoke { handler() }
    }

    func cancel() {
        let handler = lock.withLock {
            canceled = true
            let current = self.handler
            self.handler = nil
            return current
        }
        handler?()
    }

    func check() throws {
        if lock.withLock({ canceled }) { throw CancellationError() }
    }
}

// The signing worker alone configures/uses the context. Other threads may only
// invalidate it, the API specifically provided to cancel an in-flight evaluation.
// No authentication properties or key operations are exposed across threads.
final class AuthenticationInvalidator: @unchecked Sendable {
    private let context: LAContext
    init(_ context: LAContext) { self.context = context }
    func invalidate() { context.invalidate() }
}

// Serializes first access so public-key lookup and signing do not each reopen
// the same Keychain permission dialog. This stores no authentication context.
final class KeyMaterialCache: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]

    func value(for account: String, load: () throws -> Data) throws -> Data {
        try lock.withLock {
            if let value = values[account] { return value }
            let value = try load()
            values[account] = value
            return value
        }
    }
}

final class SynKeyStore: DecisionSigning, @unchecked Sendable {
    private let service = "org.syn-approvals.Syn"
    private let approvalAccount = "approval-key-v1"
    private let denialAccount = "denial-key-v1"
    private let cache = KeyMaterialCache()

    func publicIdentities() throws -> (approval: Data, denial: Data) {
        (try approvalPublicKey(), try denialPublicKey())
    }

    func approvalPublicKey() throws -> Data { try approvalKey(context: nil).publicKey.x963Representation }
    func denialPublicKey() throws -> Data { try denialKey().publicKey.x963Representation }

    func signApproval(payload: Data, reason: String, cancellation: ApprovalCancellation) throws -> (keyID: Data, signature: Data) {
        try cancellation.check()
        let context = Self.freshApprovalContext(reason: reason)
        let invalidator = AuthenticationInvalidator(context)
        cancellation.install { invalidator.invalidate() }
        defer { context.invalidate() }
        let key = try approvalKey(context: context)
        let signature = try key.signature(for: payload)
        try cancellation.check()
        return (Data(SHA256.hash(data: key.publicKey.x963Representation)), signature.rawRepresentation)
    }

    static func freshApprovalContext(reason: String) -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        return context
    }

    func signDenial(payload: Data) throws -> (keyID: Data, signature: Data) {
        let key = try denialKey()
        let signature = try key.signature(for: payload)
        return (Data(SHA256.hash(data: key.publicKey.x963Representation)), signature.rawRepresentation)
    }

    private func approvalKey(context: LAContext?) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw KeyStoreError.secureEnclaveUnavailable }
        let representation = try cache.value(for: approvalAccount) {
            if let stored = try read(account: approvalAccount) { return stored }
            return try createApprovalRepresentation()
        }
        // Cache only the opaque Enclave-wrapped representation. Reconstruct the
        // key with THIS operation's fresh context; never reuse authenticated keys.
        return try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: representation,
            authenticationContext: context
        )
    }

    private func createApprovalRepresentation() throws -> Data {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else { throw accessError!.takeRetainedValue() as Error }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: access,
            authenticationContext: nil
        )
        try write(key.dataRepresentation, account: approvalAccount)
        return key.dataRepresentation
    }

    private func denialKey() throws -> P256.Signing.PrivateKey {
        let representation = try cache.value(for: denialAccount) {
            if let stored = try read(account: denialAccount) { return stored }
            let key = P256.Signing.PrivateKey()
            try write(key.rawRepresentation, account: denialAccount)
            return key.rawRepresentation
        }
        return try P256.Signing.PrivateKey(rawRepresentation: representation)
    }

    private func read(account: String) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw KeyStoreError.keychain(status) }
        return data
    }

    private func write(_ data: Data, account: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: data,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeyStoreError.keychain(status) }
    }
}

extension SynKeyStore: DecisionSignerProviding {
    func signer(for request: VerifiedApprovalRequest) throws -> any DecisionSigning { self }
}
