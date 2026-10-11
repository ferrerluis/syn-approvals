import CryptoKit
import Foundation

protocol UpdateHealthSigning: DecisionSignerProviding {
    func signUpdateHealth(payload: Data) throws -> (keyID: Data, signature: Data)
}

extension FixedDecisionSignerProvider: UpdateHealthSigning {
    func signUpdateHealth(payload: Data) throws -> (keyID: Data, signature: Data) {
        try signer.signDenial(payload: payload)
    }
}

extension SynKeyStore: UpdateHealthSigning {
    func signUpdateHealth(payload: Data) throws -> (keyID: Data, signature: Data) {
        try signDenial(payload: payload)
    }
}

enum UpdateHealth {
    static let domain = "org.syn-approvals.update-health.v1"

    // Never creates a decision, reads command fields, posts a notification, or
    // calls signApproval. A health response has no authorization meaning.
    static func response(
        to signed: Data, target: TargetRecord, provider: any DecisionSignerProviding,
        now: Date = .now
    ) async throws -> Data {
        try await Task.detached {
            guard let healthSigner = provider as? any UpdateHealthSigning else {
                throw SynProtocolError.invalid("update health signing is unavailable")
            }
            guard let bytes = Data(base64Encoded: target.targetPublicKeyBase64) else {
                throw SynProtocolError.invalid("invalid health target key")
            }
            let key = try P256.Signing.PublicKey(x963Representation: bytes)
            let (payload, keyID) = try SynProtocol.verifyCOSE(signed, key: key)
            let map = try CBORCodec.decodeCanonical(payload).integerKeyedMap()
            let release = try SynProtocol.currentReleaseIdentity()
            let identities = try provider.publicIdentities()
            let milliseconds = Int64(now.timeIntervalSince1970 * 1_000)
            guard map.count == 8, map[0]?.textValue == domain,
                  map[1]?.textValue == target.targetID, map[2]?.bytesValue?.count == 32,
                  let issued = map[3]?.unsignedValue, let timestamp = Int64(exactly: issued),
                  map[4]?.unsignedValue == 10_000,
                  timestamp <= milliseconds, milliseconds - timestamp < 10_000,
                  map[5]?.textValue == release.id, map[6]?.textValue == release.commit,
                  map[7]?.bytesValue == Data(SHA256.hash(data: identities.approval)),
                  keyID == Data(SHA256.hash(data: bytes)) else {
                throw SynProtocolError.invalid("invalid update health challenge")
            }
            let deviceID = Data(SHA256.hash(data: identities.denial))
            let header = try SynProtocol.protectedHeader(keyID: deviceID)
            let structure = try SynProtocol.signatureStructure(protected: header, payload: payload)
            let signature = try healthSigner.signUpdateHealth(payload: structure)
            guard signature.keyID == deviceID else { throw SynProtocolError.invalid("health key changed") }
            return try SynProtocol.coseSign1(payload: payload, keyID: deviceID, signature: signature.signature)
        }.value
    }
}
