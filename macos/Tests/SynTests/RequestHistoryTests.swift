import CryptoKit
import Foundation
import Testing
@testable import Syn

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
    try CBORCodec.encode(.map([
        (.unsigned(0), .text(request.targetID)), (.unsigned(1), .bytes(request.requestID)),
        (.unsigned(2), .bytes(hash ?? request.payloadHash)), (.unsigned(3), .text(request.releaseID)),
        (.unsigned(4), .text(request.releaseCommit)),
        (.unsigned(5), .unsigned(UInt64(request.issuedAt.timeIntervalSince1970 * 1_000))),
        (.unsigned(6), .unsigned(UInt64(Date().timeIntervalSince1970 * 1_000))),
        (.unsigned(7), .unsigned(outcome)), (.unsigned(8), .unsigned(UInt64(request.invokingUID))),
        (.unsigned(9), .unsigned(UInt64(request.runAsUID))),
    ]))
}

@Test @MainActor func historyReceiptIsBoundAndDoesNotAuthorize() throws {
    let model = SynModel(startServices: false)
    let first = historyRequest()
    let other = historyRequest(target: "other-target")
    try model.enqueueVerified(first)
    try model.enqueueVerified(other)
    let result = try receipt(first)
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(result, targetID: other.targetID) }
    #expect(throws: SynProtocolError.self) {
        try model.receiveHistoryReceipt(receipt(first, hash: Data(repeating: 9, count: 32)), targetID: first.targetID)
    }
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(receipt(first, outcome: 7), targetID: first.targetID) }
    #expect(model.pending.count == 2)
    try model.receiveHistoryReceipt(result, targetID: first.targetID)
    try model.receiveHistoryReceipt(result, targetID: first.targetID)
    #expect(model.history(for: first.targetID).count == 1)
    #expect(model.history(for: first.targetID).first?.status == .approved)
    #expect(model.pending.map(\.targetID) == [other.targetID])
    #expect(throws: SynProtocolError.self) { try model.receiveHistoryReceipt(receipt(first, outcome: 2), targetID: first.targetID) }
}

@Test @MainActor func historyPersistsPrivatelyWithoutCommandContents() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try RequestHistoryStore(fileURL: directory.appendingPathComponent("history.json"))
    let model = SynModel(startServices: false, historyStore: store)
    let request = historyRequest()
    try model.enqueueVerified(request)
    try model.receiveHistoryReceipt(receipt(request, outcome: 2), targetID: request.targetID)
    let restored = SynModel(startServices: false, historyStore: store)
    #expect(restored.history == model.history)
    let text = try String(contentsOf: store.fileURL, encoding: .utf8)
    for marker in ["private-", "PRIVATE_ENV_MARKER", "signed-payload", "nonce", "arguments", "executable"] {
        #expect(!text.contains(marker))
    }
    let mode = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)[.posixPermissions] as? NSNumber
    #expect(mode?.intValue == 0o600)
}

@Test @MainActor func expiryAndRestartDoNotInventConfirmedResults() throws {
    let model = SynModel(startServices: false)
    let request = historyRequest(expiresIn: 0.01)
    try model.enqueueVerified(request)
    Thread.sleep(forTimeInterval: 0.03)
    model.pruneExpiredRequests()
    #expect(model.history.first?.status == .timedOut)
    #expect(model.history.first?.confirmed == false)
    try model.receiveHistoryReceipt(receipt(request, outcome: 3), targetID: request.targetID)
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
        let result = try RequestResultReceipt(data, targetID: "pi-dev")
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
    let model = SynModel(startServices: false, historyStore: store)
    #expect(model.historyError != nil)
    try model.enqueueVerified(historyRequest())
    #expect(model.pending.count == 1)
    #expect(try Data(contentsOf: url) == invalid)
}
