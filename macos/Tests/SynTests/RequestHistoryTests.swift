import CryptoKit
import Foundation
import Testing
@testable import Syn

// Fixed software fixture keys; no production authorization key is used.
private func historyKey() throws -> P256.Signing.PrivateKey {
    try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
}

private func historyTarget(_ id: String = "test-target") throws -> TargetRecord {
    TargetRecord(targetID: id, displayName: id, webSocketURL: URL(string: "wss://localhost:41781")!,
                 targetPublicKeyBase64: try historyKey().publicKey.x963Representation.base64EncodedString(),
                 serverCertificateSHA256Hex: String(repeating: "0", count: 64), clientIdentityLabel: "test")
}

@MainActor private func historyModel(store: RequestHistoryStore? = nil) throws -> SynModel {
    let model = SynModel(startServices: false, historyStore: store)
    return model
}

private func historyRequest(target: String = "test-target", id: UInt8 = 2, expiresIn: Double = 90) -> VerifiedApprovalRequest {
    let issued = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970 * 1_000) / 1_000)
    return VerifiedApprovalRequest(
        signedBytes: Data("signed-payload-private-marker".utf8), payloadHash: Data(repeating: 1, count: 32),
        requestID: Data(repeating: id, count: 16), nonce: Data(repeating: 3, count: 32),
        targetID: target, issuedAt: issued, expiresAt: issued.addingTimeInterval(expiresIn),
        invokingUID: 1000, invokingUser: "private-user-marker", runAsUID: 0, runAsUser: "root",
        runAsGroup: "root", workingDirectory: Data("private-directory-marker".utf8),
        executable: Data("private-executable-marker".utf8), arguments: [Data("private-argument-marker".utf8)],
        environmentNames: ["PRIVATE_ENV_MARKER"], environmentDigest: Data(repeating: 4, count: 32), riskMarkers: [],
        releaseID: ReleaseIdentity.current.releaseID, releaseCommit: SynProtocol.developmentCommit)
}

private func receipt(_ request: VerifiedApprovalRequest, outcome: UInt64 = 1, hash: Data? = nil) throws -> Data {
    let payload = try CBORCodec.encode(.map([
        (.unsigned(0), .text(request.targetID)), (.unsigned(1), .bytes(request.requestID)),
        (.unsigned(2), .bytes(hash ?? request.payloadHash)), (.unsigned(3), .text(request.releaseID)),
        (.unsigned(4), .text(request.releaseCommit)),
        (.unsigned(5), .unsigned(UInt64(request.issuedAt.timeIntervalSince1970 * 1_000))),
        (.unsigned(6), .unsigned(UInt64(Date().timeIntervalSince1970 * 1_000))),
        (.unsigned(7), .unsigned(outcome)), (.unsigned(8), .unsigned(UInt64(request.invokingUID))),
        (.unsigned(9), .unsigned(UInt64(request.runAsUID))),
        (.unsigned(10), .text("org.syn-approvals.permission-result.v1")),
    ]))
    let key = try historyKey()
    let header = try SynProtocol.protectedHeader(keyID: Data(SHA256.hash(data: key.publicKey.x963Representation)))
    let signature = try key.signature(for: SynProtocol.signatureStructure(protected: header, payload: payload))
    return try CBORCodec.encode(.tag(18, .array([.bytes(header), .map([]), .bytes(payload), .bytes(signature.rawRepresentation)])))
}

@Test @MainActor func historyReceiptIsBoundAndDoesNotAuthorize() throws {
    let model = try historyModel()
    let first = historyRequest()
    let other = historyRequest(target: "other-target")
    try model.enqueueVerified(first)
    try model.enqueueVerified(other)
    let result = try receipt(first)
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(result, from: historyTarget(other.targetID)) }
    #expect(throws: SynProtocolError.self) {
        try model.receiveHistoryReceipt(receipt(first, hash: Data(repeating: 9, count: 32)), from: historyTarget(first.targetID))
    }
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(receipt(first, outcome: 7), from: historyTarget(first.targetID)) }
    #expect(model.pending.count == 2)
    try model.receiveHistoryReceipt(result, from: historyTarget(first.targetID))
    try model.receiveHistoryReceipt(result, from: historyTarget(first.targetID))
    #expect(model.history(for: first.targetID).count == 1)
    #expect(model.history(for: first.targetID).first?.status == .approved)
    #expect(model.pending.map(\.targetID) == [other.targetID])
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(receipt(first, outcome: 2), from: historyTarget(first.targetID)) }
}

@Test @MainActor func historyPersistsPrivatelyWithoutCommandContents() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try RequestHistoryStore(fileURL: directory.appendingPathComponent("history.json"))
    let model = try historyModel(store: store)
    let request = historyRequest()
    try model.enqueueVerified(request)
    try model.receiveHistoryReceipt(receipt(request, outcome: 2), from: historyTarget(request.targetID))
    let restored = try historyModel(store: store)
    #expect(restored.history == model.history)
    let text = try String(contentsOf: store.fileURL, encoding: .utf8)
    for marker in ["private-", "PRIVATE_ENV_MARKER", "signed-payload", "nonce", "arguments", "executable"] {
        #expect(!text.contains(marker))
    }
    let mode = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)[.posixPermissions] as? NSNumber
    #expect(mode?.intValue == 0o600)
}

@Test @MainActor func expiryAndRestartDoNotInventConfirmedResults() throws {
    let model = try historyModel()
    let request = historyRequest(expiresIn: 0.01)
    try model.enqueueVerified(request)
    Thread.sleep(forTimeInterval: 0.03)
    model.pruneExpiredRequests()
    #expect(model.history.first?.status == .timedOut)
    #expect(model.history.first?.confirmed == false)
    try model.receiveHistoryReceipt(receipt(request, outcome: 3), from: historyTarget(request.targetID))
    #expect(model.history.first?.confirmed == true)
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try RequestHistoryStore(fileURL: directory.appendingPathComponent("history.json"))
    try store.save([RequestHistoryEntry(historyRequest())])
    #expect(SynModel(startServices: false, historyStore: store).history.first?.status == .unconfirmed)
}

@Test func historyRetentionIsPerDeviceAndKeepsLiveRequests() {
    var entries: [RequestHistoryEntry] = []
    for index in 0..<1_005 {
        var entry = RequestHistoryEntry(historyRequest())
        entry.completedAt = Date(timeIntervalSince1970: Double(index))
        entries.append(entry)
    }
    entries.append(RequestHistoryEntry(historyRequest(target: "other-target")))
    #expect(RequestHistoryStore.retained(entries).count == 1_001)
}

@Test func rustPermissionReceiptGoldenVectorsDecodeInSwift() throws {
    let url = try #require(Bundle.module.url(forResource: "protocol-v2", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    for (name, expected) in [("approved_result_hex", RequestHistoryStatus.approved),
                             ("timed_out_result_hex", RequestHistoryStatus.timedOut)] {
        let hex = try #require(fixture[name] as? String)
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            data.append(try #require(UInt8(hex[index..<next], radix: 16)))
            index = next
        }
        let publicHex = try #require(fixture["target_public_sec1_hex"] as? String)
        var publicBytes = Data()
        var offset = publicHex.startIndex
        while offset < publicHex.endIndex {
            let next = publicHex.index(offset, offsetBy: 2)
            publicBytes.append(try #require(UInt8(publicHex[offset..<next], radix: 16)))
            offset = next
        }
        var target = try historyTarget("pi-dev")
        target.targetPublicKeyBase64 = publicBytes.base64EncodedString()
        let result = try RequestResultReceipt(data, target: target)
        #expect(result.status == expected)
        #expect(result.invokingUID == 1000)
        #expect(result.requestID == "000102030405060708090a0b0c0d0e0f")
        #expect(try CBORCodec.encode(CBORCodec.decodeCanonical(data)) == data)
    }
}

@Test @MainActor func brokenHistoryIsVisibleAndNeverOverwritten() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("history.json")
    let invalid = Data("corrupt-history".utf8)
    try invalid.write(to: url)
    let store = try RequestHistoryStore(fileURL: url)
    let model = try historyModel(store: store)
    #expect(model.historyError != nil)
    try model.enqueueVerified(historyRequest())
    #expect(model.pending.count == 1)
    #expect(try Data(contentsOf: url) == invalid)
}

@Test @MainActor func unsignedAndWrongKeyReceiptsCannotConfirmHistory() throws {
    let model = try historyModel()
    let request = historyRequest()
    try model.enqueueVerified(request)
    let signed = try receipt(request)
    let payload = try SynProtocol.verifyCOSE(signed, key: historyKey().publicKey).0
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(payload, from: historyTarget(request.targetID)) }
    var forged = signed
    forged[forged.count - 1] ^= 1
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(forged, from: historyTarget(request.targetID)) }
    var wrongTarget = try historyTarget()
    wrongTarget.targetPublicKeyBase64 = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(signed, from: wrongTarget) }
    #expect(model.history.first?.confirmed == false)
    #expect(model.pending.count == 1)
}

@Test @MainActor func cancelWithoutReceiptStaysUnconfirmedAndCanRecover() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try RequestHistoryStore(fileURL: directory.appendingPathComponent("history.json"))
    let model = try historyModel(store: store)
    let request = historyRequest()
    try model.enqueueVerified(request)
    let cancel = try CBORCodec.encode(.map([(.unsigned(0), .bytes(request.requestID))]))
    model.handleTargetMessage(.success(WireMessage(kind: .cancel, body: cancel)), from: try historyTarget())
    #expect(model.pending.isEmpty)
    #expect(model.history.first?.status == .unconfirmed)
    #expect(model.history.first?.confirmed == false)
    let restored = try historyModel(store: store)
    #expect(restored.history.first?.status == .unconfirmed)
    try restored.receiveHistoryReceipt(receipt(request), from: historyTarget(request.targetID))
    #expect(restored.history.first?.status == .approved)
    #expect(restored.history.first?.confirmed == true)
}

@Test @MainActor func legacyRelayConfirmationIsDowngradedOnLoad() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try RequestHistoryStore(fileURL: directory.appendingPathComponent("history.json"))
    var old = RequestHistoryEntry(historyRequest())
    old.status = .approved
    old.confirmed = true
    old.completedAt = .now
    try store.save([old])
    let model = try historyModel(store: store)
    #expect(model.history.first?.status == .unconfirmed)
    #expect(model.history.first?.confirmed == false)
}
