import CryptoKit
import Foundation
import Testing
@testable import SynIOS

private final class IOSFixtureBundle: NSObject {}
extension Bundle { static var module: Bundle { Bundle(for: IOSFixtureBundle.self) } }

@MainActor
private func testModel() throws -> IOSModel {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return try IOSModel(fileURL: directory.appendingPathComponent("targets.json"))
}
private func data(hex: String) -> Data {
    Data(stride(from: 0, to: hex.count, by: 2).map { offset in
        let start = hex.index(hex.startIndex, offsetBy: offset)
        return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
    })
}
private func freshRequest() throws -> (TargetRecord, Data) {
    let url = try #require(Bundle.module.url(forResource: "protocol-v2", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    let original = data(hex: fixture["signed_request_hex"] as! String)
    guard case let .tag(18, tagged) = try CBORCodec.decodeCanonical(original) else { throw SynProtocolError.invalid("Invalid test COSE.") }
    let cose = try #require(tagged.arrayValue)
    var fields = try CBORCodec.decodeCanonical(try #require(cose[2].bytesValue)).integerKeyedMap()
    fields[7] = .unsigned(UInt64(Date().timeIntervalSince1970 * 1000))
    let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
    let payload = try CBORCodec.encode(.map(fields.map { (.unsigned($0.key), $0.value) }))
    let keyID = Data(SHA256.hash(data: key.publicKey.x963Representation))
    let header = try SynProtocol.protectedHeader(keyID: keyID)
    let signature = try key.signature(for: SynProtocol.signatureStructure(protected: header, payload: payload))
    let signed = try SynProtocol.coseSign1(payload: payload, keyID: keyID, signature: signature.rawRepresentation)
    let target = TargetRecord(targetID: "pi-dev", displayName: "Test machine", webSocketURL: URL(string: "wss://test.invalid:41781")!,
        targetPublicKeyBase64: key.publicKey.x963Representation.base64EncodedString(), serverCertificateSHA256Hex: String(repeating: "0", count: 64), clientIdentityLabel: "test")
    return (target, signed)
}
@Test @MainActor func pendingRequestReturnsAfterForegroundReconnect() throws {
    let model = try testModel()
    let (target, signed) = try freshRequest()
    model.receive(.success(WireMessage(kind: .hello, body: try SynProtocol.helloBody(targetID: target.id))), target: target)
    model.receive(.success(WireMessage(kind: .request, body: signed)), target: target)
    #expect(model.pending.count == 1)
    model.setForeground(false)
    #expect(model.pending.isEmpty)
    model.receive(.success(WireMessage(kind: .hello, body: try SynProtocol.helloBody(targetID: target.id))), target: target)
    model.receive(.success(WireMessage(kind: .request, body: signed)), target: target)
    #expect(model.pending.count == 1)
}
@Test @MainActor func canceledRequestNeverReturnsAfterReconnect() throws {
    let model = try testModel()
    let (target, signed) = try freshRequest()
    model.receive(.success(WireMessage(kind: .hello, body: try SynProtocol.helloBody(targetID: target.id))), target: target)
    model.receive(.success(WireMessage(kind: .request, body: signed)), target: target)
    let request = try #require(model.pending.first)
    let cancellation = try CBORCodec.encode(.map([(.unsigned(0), .bytes(request.requestID))]))
    model.receive(.success(WireMessage(kind: .cancel, body: cancellation)), target: target)
    model.setForeground(false)
    model.receive(.success(WireMessage(kind: .hello, body: try SynProtocol.helloBody(targetID: target.id))), target: target)
    model.receive(.success(WireMessage(kind: .request, body: signed)), target: target)
    #expect(model.pending.isEmpty)
}
@Test @MainActor func requestBeforeIdentityHandshakeIsRejected() throws {
    let model = try testModel()
    let (target, signed) = try freshRequest()
    model.receive(.success(WireMessage(kind: .request, body: signed)), target: target)
    #expect(model.pending.isEmpty)
    #expect(model.error != nil)
}

private func reviewRequest() -> VerifiedApprovalRequest {
    VerifiedApprovalRequest(signedBytes: Data("opaque test request".utf8), payloadHash: Data(repeating: 3, count: 32),
        requestID: Data(repeating: 2, count: 16), nonce: Data(repeating: 4, count: 16), targetID: "pi",
        issuedAt: Date(timeIntervalSince1970: 30), expiresAt: Date(timeIntervalSince1970: 120),
        invokingUID: 1000, invokingUser: "test", runAsUID: 0, runAsUser: "root", runAsGroup: "root",
        workingDirectory: Data("/tmp".utf8), executable: Data("/usr/bin/true".utf8),
        arguments: [Data("/usr/bin/true".utf8), Data("token=test-only".utf8)], environmentNames: ["PATH"],
        environmentDigest: Data(repeating: 0xa7, count: 32), riskMarkers: ["noninteractive", "marker\u{202e}"],
        releaseID: ReleaseIdentity.developmentID, releaseCommit: String(repeating: "0", count: 40))
}
@Test func mobileReviewMatchesJavaScriptGoldenWithoutWireData() throws {
    let review = MobileReview(request: reviewRequest(), target: nil, revealed: [], authenticating: false)
    let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(review)) as! [String: Any]
    let url = try #require(Bundle.module.url(forResource: "mobile-review", withExtension: "json", subdirectory: "Fixtures"))
    let golden = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    #expect(NSDictionary(dictionary: encoded).isEqual(to: golden))
}
@Test func mobileReviewRevealChangesOnlyTheSelectedDisplayArgument() {
    let request = reviewRequest()
    let masked = MobileReview(request: request, target: nil, revealed: [], authenticating: false)
    let revealed = MobileReview(request: request, target: nil, revealed: [1], authenticating: true)
    #expect(masked.arguments[1].value == nil)
    #expect(revealed.arguments[1].value == SafeDisplay.render(request.arguments[1]))
    #expect(revealed.arguments[0].value == masked.arguments[0].value)
    #expect(revealed.id == masked.id)
    #expect(revealed.environmentDigest == masked.environmentDigest)
    #expect(revealed.authenticating)
}
@Test func mobileReviewCannotDisplayAnotherTargetsNameOrFingerprint() throws {
    let (foreignTarget, _) = try freshRequest()
    let review = MobileReview(request: reviewRequest(), target: foreignTarget, revealed: [], authenticating: false)
    #expect(review.targetName == "pi")
    #expect(review.targetKeyFingerprint == nil)
}
