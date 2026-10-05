import CryptoKit
import Foundation
import Security

#if targetEnvironment(simulator) && DEBUG
/// Compiled only for Debug simulators. Public identity is explicitly tagged in enrollment/UI.
final class SimulatorDecisionSigner: DecisionSigning, @unchecked Sendable {
    private let approval: P256.Signing.PrivateKey
    private let denial: P256.Signing.PrivateKey
    init() throws {
        approval = try Self.key("simulator-approval")
        denial = try Self.key("simulator-denial")
    }
    private static func key(_ name: String) throws -> P256.Signing.PrivateKey {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.syn-approvals.SynIOS.Debug", kSecAttrAccount: name]
        var value: CFTypeRef?
        var read = query
        read[kSecReturnData] = true
        let status = SecItemCopyMatching(read as CFDictionary, &value)
        if status == errSecSuccess, let data = value as? Data { return try .init(rawRepresentation: data) }
        guard status == errSecItemNotFound else { throw KeyStoreError.keychain(status) }
        let key = P256.Signing.PrivateKey()
        var write = query
        write[kSecValueData] = key.rawRepresentation
        write[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(write as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeyStoreError.keychain(added) }
        return key
    }
    func approvalPublicKey() throws -> Data { approval.publicKey.x963Representation }
    func denialPublicKey() throws -> Data { denial.publicKey.x963Representation }
    func signApproval(payload: Data, reason: String, cancellation: ApprovalCancellation) throws -> (keyID: Data, signature: Data) {
        try cancellation.check()
        return (Data(SHA256.hash(data: approval.publicKey.x963Representation)), try approval.signature(for: payload).rawRepresentation)
    }
    func signDenial(payload: Data) throws -> (keyID: Data, signature: Data) {
        (Data(SHA256.hash(data: denial.publicKey.x963Representation)), try denial.signature(for: payload).rawRepresentation)
    }
}
#endif
