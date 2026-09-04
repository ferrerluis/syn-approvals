import CryptoKit
import Foundation

enum SynProtocolError: Error, LocalizedError {
    case invalid(String)

    var errorDescription: String? {
        if case let .invalid(message) = self { message } else { nil }
    }
}

enum SynMessageKind: UInt8, Sendable {
    case hello = 1, request = 2, cancel = 3, decision = 4, result = 5, ping = 6, pong = 7, error = 8, unavailable = 9
}

struct WireMessage: Sendable {
    let kind: SynMessageKind
    let body: Data

    init(data: Data) throws {
        guard data.count <= 65_536 else { throw SynProtocolError.invalid("message exceeds 64 KiB") }
        let map = try CBORCodec.decodeCanonical(data).integerKeyedMap()
        guard map.count == 3, map[0]?.unsignedValue == 1,
              let rawKind = map[1]?.unsignedValue, let byteKind = UInt8(exactly: rawKind),
              let kind = SynMessageKind(rawValue: byteKind),
              let body = map[2]?.bytesValue else { throw SynProtocolError.invalid("invalid wire envelope") }
        self.kind = kind
        self.body = body
    }

    init(kind: SynMessageKind, body: Data) {
        self.kind = kind
        self.body = body
    }

    func encoded() throws -> Data {
        let value: CBOR = .map([
            (.unsigned(0), .unsigned(1)),
            (.unsigned(1), .unsigned(UInt64(kind.rawValue))),
            (.unsigned(2), .bytes(body)),
        ])
        let data = try CBORCodec.encode(value)
        guard data.count <= 65_536 else { throw SynProtocolError.invalid("message exceeds 64 KiB") }
        return data
    }
}

struct VerifiedApprovalRequest: Identifiable, Sendable {
    let signedBytes: Data
    let payloadHash: Data
    let requestID: Data
    let nonce: Data
    let targetID: String
    let issuedAt: Date
    let expiresAt: Date
    let invokingUID: UInt32
    let invokingUser: String
    let runAsUID: UInt32
    let runAsUser: String
    let runAsGroup: String
    let workingDirectory: Data
    let executable: Data
    let arguments: [Data]
    let environmentNames: [String]
    let environmentDigest: Data
    let riskMarkers: [String]

    // IDs used by UI, notifications, and in-memory routing include the pinned
    // target. A second target cannot collide with another target's request ID.
    var id: String { "\(targetID):\(requestID.hex)" }
    var isExpired: Bool { Date() >= expiresAt }
}

struct TargetRecord: Codable, Identifiable, Hashable, Sendable {
    var targetID: String
    var displayName: String
    var webSocketURL: URL
    var targetPublicKeyBase64: String
    var serverCertificateSHA256Hex: String
    var clientIdentityLabel: String

    var id: String { targetID }

    var publicKey: P256.Signing.PublicKey? {
        guard let data = Data(base64Encoded: targetPublicKeyBase64) else { return nil }
        return try? P256.Signing.PublicKey(x963Representation: data)
    }
}

enum SynProtocol {
    static let sudoAdapter = "org.syn-approvals.sudo"
    static let approvalTTLMilliseconds: UInt64 = 90_000

    static func verifyRequest(_ signed: Data, target: TargetRecord) throws -> VerifiedApprovalRequest {
        guard let key = target.publicKey else { throw SynProtocolError.invalid("target public key is invalid") }
        let (payload, signerKeyID) = try verifyCOSE(signed, key: key)
        guard signerKeyID == Data(SHA256.hash(data: key.x963Representation)) else {
            throw SynProtocolError.invalid("target key ID does not match")
        }
        let map = try CBORCodec.decodeCanonical(payload).integerKeyedMap()
        guard map.count == 10,
              map[0]?.unsignedValue == 1,
              let requestID = map[1]?.bytesValue, requestID.count == 16,
              let nonce = map[2]?.bytesValue, nonce.count == 32,
              let targetID = map[3]?.textValue, targetID == target.targetID,
              map[4]?.bytesValue == signerKeyID,
              map[5]?.textValue == sudoAdapter,
              map[6]?.unsignedValue == 1,
              let issuedRaw = signedInteger(map[7]),
              let ttl = map[8]?.unsignedValue, ttl == approvalTTLMilliseconds,
              let sudoValue = map[9] else { throw SynProtocolError.invalid("invalid approval request") }
        let sudo = try parseSudo(sudoValue)
        let issuedAt = Date(timeIntervalSince1970: Double(issuedRaw) / 1_000)
        return VerifiedApprovalRequest(
            signedBytes: signed,
            payloadHash: Data(SHA256.hash(data: payload)),
            requestID: requestID,
            nonce: nonce,
            targetID: targetID,
            issuedAt: issuedAt,
            expiresAt: issuedAt.addingTimeInterval(Double(ttl) / 1_000),
            invokingUID: sudo.invokingUID,
            invokingUser: sudo.invokingUser,
            runAsUID: sudo.runAsUID,
            runAsUser: sudo.runAsUser,
            runAsGroup: sudo.runAsGroup,
            workingDirectory: sudo.workingDirectory,
            executable: sudo.executable,
            arguments: sudo.arguments,
            environmentNames: sudo.environmentNames,
            environmentDigest: sudo.environmentDigest,
            riskMarkers: sudo.riskMarkers
        )
    }

    static func decisionPayload(
        request: VerifiedApprovalRequest,
        approve: Bool,
        approverKeyID: Data,
        now: Date = Date()
    ) throws -> Data {
        let milliseconds = Int64(now.timeIntervalSince1970 * 1_000)
        return try CBORCodec.encode(.map([
            (.unsigned(0), .unsigned(1)),
            (.unsigned(1), .bytes(request.requestID)),
            (.unsigned(2), .bytes(request.payloadHash)),
            (.unsigned(3), .text(request.targetID)),
            (.unsigned(4), .unsigned(approve ? 1 : 2)),
            (.unsigned(5), integer(milliseconds)),
            (.unsigned(6), .bytes(approverKeyID)),
            (.unsigned(7), .unsigned(approve ? 1 : 2)),
        ]))
    }

    static func coseSign1(payload: Data, keyID: Data, signature: Data) throws -> Data {
        guard keyID.count == 32, signature.count == 64 else { throw SynProtocolError.invalid("invalid signing material") }
        let protected = try protectedHeader(keyID: keyID)
        return try CBORCodec.encode(.tag(18, .array([
            .bytes(protected), .map([]), .bytes(payload), .bytes(signature),
        ])))
    }

    static func signatureStructure(protected: Data, payload: Data) throws -> Data {
        try CBORCodec.encode(.array([.text("Signature1"), .bytes(protected), .bytes(Data()), .bytes(payload)]))
    }

    static func protectedHeader(keyID: Data) throws -> Data {
        try CBORCodec.encode(.map([
            (.unsigned(1), .negative(-7)),
            (.unsigned(4), .bytes(keyID)),
        ]))
    }

    private static func verifyCOSE(_ signed: Data, key: P256.Signing.PublicKey) throws -> (Data, Data) {
        guard signed.count <= 65_536,
              case let .tag(18, tagged) = try CBORCodec.decodeCanonical(signed),
              let values = tagged.arrayValue, values.count == 4,
              let protected = values[0].bytesValue,
              case let .map(unprotected) = values[1], unprotected.isEmpty,
              let payload = values[2].bytesValue,
              let signatureData = values[3].bytesValue, signatureData.count == 64 else {
            throw SynProtocolError.invalid("invalid COSE Sign1 envelope")
        }
        let header = try CBORCodec.decodeCanonical(protected).integerKeyedMap()
        guard header.count == 2, header[1]?.negativeValue == -7,
              let keyID = header[4]?.bytesValue, keyID.count == 32 else {
            throw SynProtocolError.invalid("invalid COSE protected header")
        }
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
        let structure = try signatureStructure(protected: protected, payload: payload)
        guard key.isValidSignature(signature, for: structure) else { throw SynProtocolError.invalid("request signature is invalid") }
        return (payload, keyID)
    }

    private struct ParsedSudo {
        let invokingUID: UInt32
        let invokingUser: String
        let runAsUID: UInt32
        let runAsUser: String
        let runAsGroup: String
        let workingDirectory: Data
        let executable: Data
        let arguments: [Data]
        let environmentNames: [String]
        let environmentDigest: Data
        let riskMarkers: [String]
    }

    private static func parseSudo(_ value: CBOR) throws -> ParsedSudo {
        let map = try value.integerKeyedMap()
        // minicbor omits key 5 when Rust's Option<String> is None. All other
        // fields remain required; accepting a missing TTY must not admit an
        // unknown field or a missing identity/intent field.
        let requiredKeys = Set((UInt64(0)...UInt64(20)).filter { $0 != 5 })
        let keys = Set(map.keys)
        guard keys == requiredKeys || keys == requiredKeys.union([5]),
              let invokingUID = uint32(map[0]),
              uint32(map[1]) != nil,
              let invokingUser = map[2]?.textValue,
              uint32(map[3]) != nil,
              uint32(map[4]) != nil,
              validOptionalText(map[5]),
              map[6]?.boolValue != nil,
              let workingDirectory = map[7]?.bytesValue,
              let runAsUID = uint32(map[8]),
              uint32(map[9]) != nil,
              let runAsUser = map[10]?.textValue,
              let runAsGroup = map[11]?.textValue,
              let sudoMode = map[12]?.textValue, !sudoMode.isEmpty,
              let executable = map[13]?.bytesValue, !executable.isEmpty,
              let argumentValues = map[14]?.arrayValue,
              let commandInfoValues = map[15]?.arrayValue,
              let environmentDigest = map[16]?.bytesValue, environmentDigest.count == 32,
              let environmentNameValues = map[17]?.arrayValue,
              map[18]?.unsignedValue == 1,
              let provider = map[19]?.textValue, !provider.isEmpty,
              let riskValues = map[20]?.arrayValue else { throw SynProtocolError.invalid("invalid sudo intent") }
        guard !invokingUser.isEmpty, invokingUser.count <= 256,
              !runAsUser.isEmpty, runAsUser.count <= 256,
              !runAsGroup.isEmpty, runAsGroup.count <= 256,
              workingDirectory.count <= 8_192,
              executable.count <= 8_192, !argumentValues.isEmpty, argumentValues.count <= 256,
              environmentNameValues.count <= 1_024, commandInfoValues.count <= 128 else {
            throw SynProtocolError.invalid("sudo intent collection exceeds its limit")
        }
        let arguments = try argumentValues.map { value -> Data in
            guard let bytes = value.bytesValue, bytes.count <= 8_192 else {
                throw SynProtocolError.invalid("argv contains an invalid byte value")
            }
            return bytes
        }
        var previousCommandInfoKey: String?
        for value in commandInfoValues {
            let entry = try value.integerKeyedMap()
            guard entry.count == 2, let key = entry[0]?.textValue, !key.isEmpty,
                  key.count <= 128, let bytes = entry[1]?.bytesValue, bytes.count <= 8_192,
                  previousCommandInfoKey.map({ $0 < key }) ?? true else {
                throw SynProtocolError.invalid("command info is malformed or not sorted")
            }
            previousCommandInfoKey = key
        }
        let environmentNames = try environmentNameValues.map { value -> String in
            guard let text = value.textValue else { throw SynProtocolError.invalid("environment name is not text") }
            return text
        }
        guard environmentNames == environmentNames.sorted(), Set(environmentNames).count == environmentNames.count else {
            throw SynProtocolError.invalid("environment names are not sorted and unique")
        }
        let riskMarkers = try riskValues.map { value -> String in
            guard let text = value.textValue, !text.isEmpty, text.count <= 128 else {
                throw SynProtocolError.invalid("risk marker is not valid text")
            }
            return text
        }
        return ParsedSudo(
            invokingUID: invokingUID, invokingUser: invokingUser, runAsUID: runAsUID,
            runAsUser: runAsUser, runAsGroup: runAsGroup, workingDirectory: workingDirectory,
            executable: executable, arguments: arguments, environmentNames: environmentNames,
            environmentDigest: environmentDigest, riskMarkers: riskMarkers
        )
    }

    private static func uint32(_ value: CBOR?) -> UInt32? {
        guard let number = value?.unsignedValue, number <= UInt64(UInt32.max) else { return nil }
        return UInt32(number)
    }

    private static func signedInteger(_ value: CBOR?) -> Int64? {
        if let positive = value?.unsignedValue, positive <= UInt64(Int64.max) { return Int64(positive) }
        return value?.negativeValue
    }

    private static func validOptionalText(_ value: CBOR?) -> Bool {
        guard let value else { return true }
        // A present null is not Rust's canonical encoding of None.
        return value.textValue != nil
    }

    private static func integer(_ value: Int64) -> CBOR {
        value >= 0 ? .unsigned(UInt64(value)) : .negative(value)
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
