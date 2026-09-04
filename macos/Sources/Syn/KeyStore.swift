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

struct SynKeyStore: Sendable {
    private let service = "org.syn-approvals.Syn"
    private let approvalAccount = "approval-key-v1"
    private let denialAccount = "denial-key-v1"

    func publicIdentities() throws -> (approval: Data, denial: Data) {
        let approval = try approvalKey(context: nil).publicKey.x963Representation
        let denial = try denialKey().publicKey.x963Representation
        return (approval, denial)
    }

    func signApproval(payload: Data, reason: String) throws -> (keyID: Data, signature: Data) {
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let key = try approvalKey(context: context)
        let signature = try key.signature(for: payload)
        return (Data(SHA256.hash(data: key.publicKey.x963Representation)), signature.rawRepresentation)
    }

    func signDenial(payload: Data) throws -> (keyID: Data, signature: Data) {
        let key = try denialKey()
        let signature = try key.signature(for: payload)
        return (Data(SHA256.hash(data: key.publicKey.x963Representation)), signature.rawRepresentation)
    }

    private func approvalKey(context: LAContext?) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw KeyStoreError.secureEnclaveUnavailable }
        if let representation = try read(account: approvalAccount) {
            return try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: representation,
                authenticationContext: context
            )
        }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else { throw accessError!.takeRetainedValue() as Error }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: access,
            authenticationContext: context
        )
        try write(key.dataRepresentation, account: approvalAccount)
        return key
    }

    private func denialKey() throws -> P256.Signing.PrivateKey {
        if let representation = try read(account: denialAccount) {
            return try P256.Signing.PrivateKey(rawRepresentation: representation)
        }
        let key = P256.Signing.PrivateKey()
        try write(key.rawRepresentation, account: denialAccount)
        return key
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
