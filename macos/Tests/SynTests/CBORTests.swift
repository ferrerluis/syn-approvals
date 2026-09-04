import Foundation
import Testing
@testable import Syn

private struct GoldenFixture: Decodable {
    let targetPublicSec1Hex: String
    let signedRequestHex: String
    let requestPayloadHashHex: String

    enum CodingKeys: String, CodingKey {
        case targetPublicSec1Hex = "target_public_sec1_hex"
        case signedRequestHex = "signed_request_hex"
        case requestPayloadHashHex = "request_payload_hash_hex"
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
    #expect(SafeDisplay.render(Data("safe\u{202e}unsafe".utf8)) == "safe\\u{202E}unsafe")
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

@Test func oversizedWireKindFailsWithoutIntegerTrap() throws {
    for kind in [UInt64(256), UInt64.max] {
        let data = try CBORCodec.encode(.map([
            (.unsigned(0), .unsigned(1)), (.unsigned(1), .unsigned(kind)),
            (.unsigned(2), .bytes(Data())),
        ]))
        #expect(throws: SynProtocolError.self) { _ = try WireMessage(data: data) }
    }
}

@Test func rustGoldenRequestVerifiesInSwift() throws {
    let url = try #require(
        Bundle.module.url(forResource: "protocol-v1", withExtension: "json", subdirectory: "Fixtures")
    )
    let fixture = try JSONDecoder().decode(GoldenFixture.self, from: Data(contentsOf: url))
    let publicKey = try Data(hex: fixture.targetPublicSec1Hex)
    let target = TargetRecord(
        targetID: "pi-dev",
        displayName: "Pi development",
        webSocketURL: try #require(URL(string: "wss://pi-dev.example:41781")),
        targetPublicKeyBase64: publicKey.base64EncodedString(),
        serverCertificateSHA256Hex: String(repeating: "0", count: 64),
        clientIdentityLabel: "test"
    )
    let request = try SynProtocol.verifyRequest(Data(hex: fixture.signedRequestHex), target: target)
    #expect(request.payloadHash.hex == fixture.requestPayloadHashHex)
    #expect(SafeDisplay.render(request.executable) == "/usr/bin/apt")
    #expect(request.arguments.map(SafeDisplay.render) == ["apt", "install", "gh"])
    #expect(request.expiresAt.timeIntervalSince(request.issuedAt) == 30)
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
