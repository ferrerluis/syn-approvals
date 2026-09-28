import CryptoKit
import Foundation
import Testing
@testable import Syn

private struct GoldenFixture: Decodable {
    let targetPublicSec1Hex: String
    let signedRequestHex: String
    let signedWrongReleaseRequestHex: String
    let signedWrongCommitRequestHex: String
    let requestPayloadHashHex: String
    let legacy30SecondRequestHex: String
    let signedNoTTYRequestHex: String
    let signedNoTTYNoninteractiveRequestHex: String

    enum CodingKeys: String, CodingKey {
        case targetPublicSec1Hex = "target_public_sec1_hex"
        case signedRequestHex = "signed_request_hex"
        case signedWrongReleaseRequestHex = "signed_wrong_release_request_hex"
        case signedWrongCommitRequestHex = "signed_wrong_commit_request_hex"
        case requestPayloadHashHex = "request_payload_hash_hex"
        case legacy30SecondRequestHex = "legacy_30_second_request_hex"
        case signedNoTTYRequestHex = "signed_no_tty_request_hex"
        case signedNoTTYNoninteractiveRequestHex = "signed_no_tty_noninteractive_request_hex"
    }
}

private struct LegacyGoldenFixture: Decodable {
    let targetPublicSec1Hex: String
    let signedRequestHex: String

    enum CodingKeys: String, CodingKey {
        case targetPublicSec1Hex = "target_public_sec1_hex"
        case signedRequestHex = "signed_request_hex"
    }
}

@Test func canonicalRoundTrip() throws {
    let value: CBOR = .map([
        (.unsigned(2), .bytes(Data([0, 1, 2]))),
        (.unsigned(0), .unsigned(1)),
        (.unsigned(1), .array([.text("Syn"), .negative(-7)])),
    ])
    let encoded = try CBORCodec.encode(value)
    #expect(try CBORCodec.encode(CBORCodec.decodeCanonical(encoded)) == encoded)
}

@Test func nonCanonicalIntegerFails() {
    #expect(throws: CBORError.self) {
        _ = try CBORCodec.decodeCanonical(Data([0x18, 0x01]))
    }
}

@Test func unsafeUnicodeIsEscaped() {
    #expect(SafeDisplay.render(Data("safe\u{202e}unsafe".utf8)) == "\"safe\\u{202E}unsafe\"")
}

@Test func invalidUTF8IsHexadecimal() {
    #expect(SafeDisplay.render(Data([0xff, 0x00])) == "hex:ff00")
}

@Test func wireMessageRoundTrip() throws {
    let message = WireMessage(kind: .ping, body: Data([1, 2, 3]))
    let decoded = try WireMessage(data: message.encoded())
    #expect(decoded.kind == .ping)
    #expect(decoded.body == Data([1, 2, 3]))
}

@Test func helloBindsTargetAndExactRelease() throws {
    let hello = try SynProtocol.helloBody(targetID: "remote-one")
    try SynProtocol.verifyHello(hello, targetID: "remote-one")

    #expect(throws: SynProtocolError.self) {
        try SynProtocol.verifyHello(hello, targetID: "remote-two")
    }

    var map = try CBORCodec.decodeCanonical(hello).integerKeyedMap()
    map[3] = .text("20260908000000")
    let wrongRelease = try CBORCodec.encode(.map(map.map { (.unsigned($0.key), $0.value) }))
    #expect(throws: SynProtocolError.self) {
        try SynProtocol.verifyHello(wrongRelease, targetID: "remote-one")
    }
}

@Test func oversizedWireKindFailsWithoutIntegerTrap() throws {
    for kind in [UInt64(256), UInt64.max] {
        let data = try CBORCodec.encode(.map([
            (.unsigned(0), .unsigned(SynProtocol.version)), (.unsigned(1), .unsigned(kind)),
            (.unsigned(2), .bytes(Data())),
        ]))
        #expect(throws: SynProtocolError.self) { _ = try WireMessage(data: data) }
    }
}

@Test func rustGoldenRequestVerifiesInSwift() throws {
    let fixture = try goldenFixture()
    let target = try goldenTarget(fixture)
    let request = try SynProtocol.verifyRequest(Data(hex: fixture.signedRequestHex), target: target)
    #expect(request.payloadHash.hex == fixture.requestPayloadHashHex)
    #expect(SafeDisplay.render(request.executable) == "\"/usr/bin/apt\"")
    #expect(request.arguments.map(SafeDisplay.render) == ["\"apt\"", "\"install\"", "\"gh\""])
    #expect(request.expiresAt.timeIntervalSince(request.issuedAt) == 90)
    #expect(request.releaseID == ReleaseIdentity.current.releaseID)
    #expect(request.releaseCommit == SynProtocol.developmentCommit)
    for signed in [fixture.signedWrongReleaseRequestHex, fixture.signedWrongCommitRequestHex] {
        #expect(throws: SynProtocolError.self) {
            _ = try SynProtocol.verifyRequest(Data(hex: signed), target: target)
        }
    }
    for signed in [fixture.signedNoTTYRequestHex, fixture.signedNoTTYNoninteractiveRequestHex] {
        let request = try SynProtocol.verifyRequest(Data(hex: signed), target: target)
        #expect(request.arguments.map(SafeDisplay.render) == ["\"apt\"", "\"install\"", "\"gh\""])
    }
    #expect(throws: SynProtocolError.self) {
        _ = try SynProtocol.verifyRequest(Data(hex: fixture.legacy30SecondRequestHex), target: target)
    }
}

@Test func versionOneGoldenRequestIsRejected() throws {
    let fixture = try legacyGoldenFixture()
    let target = try goldenTarget(
        targetPublicSec1Hex: fixture.targetPublicSec1Hex
    )
    #expect(throws: SynProtocolError.self) {
        _ = try SynProtocol.verifyRequest(Data(hex: fixture.signedRequestHex), target: target)
    }
}

@Test func absentTTYDoesNotPermitMissingOrUnknownIntentFields() throws {
    let fixture = try goldenFixture()
    let target = try goldenTarget(fixture)
    let signed = try CBORCodec.decodeCanonical(Data(hex: fixture.signedNoTTYRequestHex))
    guard case let .tag(18, envelope) = signed,
          let payload = envelope.arrayValue?[2].bytesValue else {
        throw SynProtocolError.invalid("invalid fixture")
    }
    let request = try CBORCodec.decodeCanonical(payload).integerKeyedMap()
    let sudo = try #require(request[9]).integerKeyedMap()
    #expect(sudo.count == 20)
    #expect(sudo[5] == nil)
    var missingIdentity = sudo
    missingIdentity.removeValue(forKey: 0)
    var missingMode = sudo
    missingMode.removeValue(forKey: 6)
    var unknownField = sudo
    unknownField[21] = .text("unknown")
    var invalidTTY = sudo
    invalidTTY[5] = .unsigned(1)
    var nullTTY = sudo
    nullTTY[5] = .null
    for fields in [missingIdentity, missingMode, unknownField, invalidTTY, nullTTY] {
        var changed = request
        changed[9] = .map(fields.map { (.unsigned($0.key), $0.value) })
        let payload = try CBORCodec.encode(.map(changed.map { (.unsigned($0.key), $0.value) }))
        // Published offline fixture key only, never a real target identity.
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        let keyID = Data(SHA256.hash(data: key.publicKey.x963Representation))
        let protected = try SynProtocol.protectedHeader(keyID: keyID)
        let signature = try key.signature(for: SynProtocol.signatureStructure(protected: protected, payload: payload))
        let signed = try SynProtocol.coseSign1(payload: payload, keyID: keyID, signature: signature.rawRepresentation)
        #expect(throws: SynProtocolError.self) { _ = try SynProtocol.verifyRequest(signed, target: target) }
    }
}

private func goldenFixture() throws -> GoldenFixture {
    let url = try #require(
        Bundle.module.url(forResource: "protocol-v2", withExtension: "json", subdirectory: "Fixtures")
    )
    return try JSONDecoder().decode(GoldenFixture.self, from: Data(contentsOf: url))
}

private func legacyGoldenFixture() throws -> LegacyGoldenFixture {
    let url = try #require(
        Bundle.module.url(forResource: "protocol-v1", withExtension: "json", subdirectory: "Fixtures")
    )
    return try JSONDecoder().decode(LegacyGoldenFixture.self, from: Data(contentsOf: url))
}

private func goldenTarget(_ fixture: GoldenFixture) throws -> TargetRecord {
    try goldenTarget(targetPublicSec1Hex: fixture.targetPublicSec1Hex)
}

private func goldenTarget(targetPublicSec1Hex: String) throws -> TargetRecord {
    TargetRecord(
        targetID: "pi-dev",
        displayName: "Pi development",
        webSocketURL: try #require(URL(string: "wss://pi-dev.example:41781")),
        targetPublicKeyBase64: try Data(hex: targetPublicSec1Hex).base64EncodedString(),
        serverCertificateSHA256Hex: String(repeating: "0", count: 64),
        clientIdentityLabel: "test"
    )
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2), hex.allSatisfy(\.isHexDigit) else {
            throw SynProtocolError.invalid("invalid test hex")
        }
        self.init()
        reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw SynProtocolError.invalid("invalid test hex")
            }
            append(byte)
            index = next
        }
    }
}
