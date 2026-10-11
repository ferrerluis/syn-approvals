import CryptoKit
import Foundation
import Testing
@testable import Syn

private extension Data {
    init(hex: String) throws {
        self.init()
        guard hex.count.isMultiple(of: 2) else { throw SynProtocolError.invalid("invalid test hex") }
        var offset = hex.startIndex
        while offset < hex.endIndex {
            let next = hex.index(offset, offsetBy: 2)
            append(try #require(UInt8(hex[offset..<next], radix: 16)))
            offset = next
        }
    }
}

private final class HealthSigner: DecisionSigning, @unchecked Sendable {
    let approval = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 2, count: 32))
    let device = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
    func approvalPublicKey() throws -> Data { approval.publicKey.x963Representation }
    func denialPublicKey() throws -> Data { device.publicKey.x963Representation }
    func signApproval(payload: Data, reason: String, cancellation: ApprovalCancellation) throws -> (keyID: Data, signature: Data) {
        Issue.record("Background verification must never request user-presence signing")
        throw CancellationError()
    }
    func signDenial(payload: Data) throws -> (keyID: Data, signature: Data) {
        (Data(SHA256.hash(data: device.publicKey.x963Representation)), try device.signature(for: payload).rawRepresentation)
    }
}

@Test func rustHealthVectorUsesDeviceKeyWithoutCreatingADecision() async throws {
    let fixtureURL = try #require(Bundle.module.url(forResource: "protocol-v2", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any])
    let check = try Data(hex: #require(fixture["signed_health_check_hex"] as? String))
    let target = TargetRecord(targetID: "pi-dev", displayName: "Pi", webSocketURL: URL(string: "wss://pi:7443")!,
        targetPublicKeyBase64: try Data(hex: #require(fixture["target_public_sec1_hex"] as? String)).base64EncodedString(),
        serverCertificateSHA256Hex: String(repeating: "0", count: 64), clientIdentityLabel: "test")
    let signer = HealthSigner()
    let provider = FixedDecisionSignerProvider(signer: signer)
    let now = Date(timeIntervalSince1970: 1_700_000_001)
    let response = try await UpdateHealth.response(to: check, target: target, provider: provider, now: now)
    let (payload, _) = try SynProtocol.verifyCOSE(response, key: signer.device.publicKey)
    let expected = try Data(hex: #require(fixture["signed_health_response_hex"] as? String))
    #expect(try SynProtocol.verifyCOSE(expected, key: signer.device.publicKey).0 == payload)
    let map = try CBORCodec.decodeCanonical(payload).integerKeyedMap()
    #expect(map.count == 8)
    #expect(map[0]?.textValue == UpdateHealth.domain)
    #expect(map[0]?.unsignedValue == nil)
    await #expect(throws: SynProtocolError.self) {
        try await UpdateHealth.response(to: check, target: target, provider: provider,
            now: Date(timeIntervalSince1970: 1_700_000_010))
    }
    let authorization = try Data(hex: #require(fixture["signed_request_hex"] as? String))
    await #expect(throws: SynProtocolError.self) {
        try await UpdateHealth.response(to: authorization, target: target, provider: provider, now: now)
    }
    let targetKey = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
    let original = try SynProtocol.verifyCOSE(check, key: targetKey.publicKey).0
    let fields = try CBORCodec.decodeCanonical(original).integerKeyedMap()
    let invalid: [(UInt64, CBOR)] = [
        (0, .text("approval")), (1, .text("other-target")),
        (2, .bytes(Data(repeating: 7, count: 16))), (3, .unsigned(1_700_000_002_000)),
        (4, .unsigned(90_000)), (5, .text("20261011000000")),
        (6, .text(String(repeating: "1", count: 40))),
        (7, .bytes(Data(repeating: 9, count: 32))),
    ]
    for (field, value) in invalid {
        var altered = fields
        altered[field] = value
        let body = try CBORCodec.encode(.map(altered.map { (.unsigned($0.key), $0.value) }))
        let id = Data(SHA256.hash(data: targetKey.publicKey.x963Representation))
        let header = try SynProtocol.protectedHeader(keyID: id)
        let signature = try targetKey.signature(for: SynProtocol.signatureStructure(protected: header, payload: body))
        let signed = try SynProtocol.coseSign1(payload: body, keyID: id, signature: signature.rawRepresentation)
        await #expect(throws: SynProtocolError.self) {
            try await UpdateHealth.response(to: signed, target: target, provider: provider, now: now)
        }
    }
}
