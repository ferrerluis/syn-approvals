import CryptoKit
import Foundation
import Security
import X509
import SwiftASN1

/// Creates the TLS identity on the phone; no private material is imported from a Mac.
enum IOSTransportIdentityStore {
    static func certificate(label: String) throws -> Data {
        if let identity = try connectionIdentity(label: label) {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
                throw SynProtocolError.invalid("The saved client identity is unreadable.")
            }
            return SecCertificateCopyData(certificate) as Data
        }
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(label) }
        let cert = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey),
            notValidBefore: Date().addingTimeInterval(-300),
            notValidAfter: Date().addingTimeInterval(365 * 24 * 60 * 60),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.clientAuth])
            }, issuerPrivateKey: .init(key)
        )
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        let data = Data(serializer.serializedBytes)
        guard let secCert = SecCertificateCreateWithData(nil, data as CFData) else {
            throw SynProtocolError.invalid("Could not create the client certificate.")
        }
        // Security expects ANSI X9.63 EC private material (public point + scalar).
        var material = key.publicKey.x963Representation + key.rawRepresentation
        defer { material.resetBytes(in: material.indices) }
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(material as CFData, [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 256,
        ] as CFDictionary, &error) else {
            throw SynProtocolError.invalid("Could not store the TLS private key.")
        }
        let keyQuery: [CFString: Any] = [
            kSecClass: kSecClassKey, kSecValueRef: secKey, kSecAttrLabel: label,
            kSecAttrApplicationTag: Data(label.utf8),
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let keyStatus = SecItemAdd(keyQuery as CFDictionary, nil)
        guard keyStatus == errSecSuccess else { throw KeyStoreError.keychain(keyStatus) }
        let status = SecItemAdd([
            kSecClass: kSecClassCertificate, kSecValueRef: secCert, kSecAttrLabel: label,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard status == errSecSuccess else {
            SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: Data(label.utf8)] as CFDictionary)
            throw KeyStoreError.keychain(status)
        }
        guard try connectionIdentity(label: label) != nil else {
            throw SynProtocolError.invalid("Could not resolve the created client identity.")
        }
        return data
    }

    static func connectionIdentity(label: String) throws -> SecIdentity? {
        // Querying identities by label varies across iOS releases; bind by exact certificate subject.
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassIdentity, kSecReturnRef: true, kSecMatchLimit: kSecMatchLimitAll,
        ] as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let identities = result as? [SecIdentity] else {
            throw KeyStoreError.keychain(status)
        }
        var matches: [SecIdentity] = []
        for identity in identities {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { continue }
            let data = SecCertificateCopyData(certificate) as Data
            let parsed = try Certificate(derEncoded: Array(data))
            let expected = try DistinguishedName { CommonName(label) }
            guard parsed.subject == expected else { continue }
            guard parsed.notValidBefore <= Date(), parsed.notValidAfter > Date().addingTimeInterval(30 * 24 * 60 * 60),
                  try parsed.extensions.extendedKeyUsage == ExtendedKeyUsage([.clientAuth]),
                  let publicKey = P256.Signing.PublicKey(parsed.publicKey) else {
                throw SynProtocolError.invalid("The client certificate must be renewed.")
            }
            var privateKey: SecKey?
            guard SecIdentityCopyPrivateKey(identity, &privateKey) == errSecSuccess, let privateKey,
                  let key = SecKeyCopyPublicKey(privateKey),
                  let exported = SecKeyCopyExternalRepresentation(key, nil),
                  exported as Data == publicKey.x963Representation else {
                throw SynProtocolError.invalid("The client certificate and key do not match.")
            }
            matches.append(identity)
        }
        guard matches.count <= 1 else { throw SynProtocolError.invalid("Conflicting client identities.") }
        return matches.first
    }

    static func pem(_ der: Data) -> String {
        "-----BEGIN CERTIFICATE-----\n" + der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) + "\n-----END CERTIFICATE-----\n"
    }
}
