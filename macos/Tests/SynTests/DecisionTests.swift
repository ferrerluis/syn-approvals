import CryptoKit
import Foundation
import Testing
@testable import Syn

// Deliberately software-only test keys; production signing still uses Keychain
// and the Secure Enclave. No private material is printed or persisted.
private final class TestSigner: DecisionSigning, @unchecked Sendable {
    let approval = P256.Signing.PrivateKey()
    let denial = P256.Signing.PrivateKey()
    let lock = NSLock()
    var approvalReads = 0
    var approvalSigns = 0
    var denialSigns = 0
    var failApproval = false
    var approvalDelay: TimeInterval = 0

    func approvalPublicKey() throws -> Data {
        lock.withLock { approvalReads += 1 }
        return approval.publicKey.x963Representation
    }

    func denialPublicKey() throws -> Data { denial.publicKey.x963Representation }

    func signApproval(payload: Data, reason: String) throws -> (keyID: Data, signature: Data) {
        lock.withLock { approvalSigns += 1 }
        if approvalDelay > 0 { Thread.sleep(forTimeInterval: approvalDelay) }
        if failApproval { throw CancellationError() }
        return (Data(SHA256.hash(data: approval.publicKey.x963Representation)), try approval.signature(for: payload).rawRepresentation)
    }

    func signDenial(payload: Data) throws -> (keyID: Data, signature: Data) {
        lock.withLock { denialSigns += 1 }
        return (Data(SHA256.hash(data: denial.publicKey.x963Representation)), try denial.signature(for: payload).rawRepresentation)
    }

    var approvalStarted: Bool { lock.withLock { approvalSigns > 0 } }
}

private func request(expiresIn: TimeInterval = 30, target: String = "test-target") -> VerifiedApprovalRequest {
    VerifiedApprovalRequest(
        signedBytes: Data(), payloadHash: Data(repeating: 1, count: 32),
        requestID: Data(repeating: 2, count: 16), nonce: Data(repeating: 3, count: 32),
        targetID: target, issuedAt: .now, expiresAt: Date().addingTimeInterval(expiresIn),
        invokingUID: 1000, invokingUser: "test-user", runAsUID: 0, runAsUser: "root",
        runAsGroup: "root", workingDirectory: Data("/test".utf8), executable: Data("/usr/bin/true".utf8),
        arguments: [Data("unique-private-argument-marker".utf8)], environmentNames: ["TEST"],
        environmentDigest: Data(repeating: 4, count: 32), riskMarkers: []
    )
}

private func decisionAction(_ message: WireMessage, key: P256.Signing.PublicKey) throws -> UInt64? {
    #expect(message.kind == .decision)
    guard case let .tag(18, inner) = try CBORCodec.decodeCanonical(message.body),
          let array = inner.arrayValue, array.count == 4,
          let header = array[0].bytesValue, let payload = array[2].bytesValue,
          let signature = array[3].bytesValue else { throw SynProtocolError.invalid("bad test decision") }
    #expect(key.isValidSignature(
        try P256.Signing.ECDSASignature(rawRepresentation: signature),
        for: try SynProtocol.signatureStructure(protected: header, payload: payload)
    ))
    return try CBORCodec.decodeCanonical(payload).integerKeyedMap()[4]?.unsignedValue
}

@Test @MainActor func denialNeverReadsApprovalKey() async throws {
    let signer = TestSigner()
    var messages: [WireMessage] = []
    let model = SynModel(startServices: false, signer: signer) { message, _ in messages.append(message) }
    let item = request()
    try model.enqueueVerified(item)
    await model.deny(item.id)
    #expect(signer.approvalReads == 0)
    #expect(signer.approvalSigns == 0)
    #expect(signer.denialSigns == 1)
    #expect(messages.count == 1)
    #expect(try decisionAction(#require(messages.first), key: signer.denial.publicKey) == 2)
    #expect(model.pending.isEmpty)
}

@Test @MainActor func approvalSignsAndSendsOnlyOnce() async throws {
    let signer = TestSigner()
    var messages: [WireMessage] = []
    let model = SynModel(startServices: false, signer: signer) { message, target in
        #expect(target == "test-target")
        messages.append(message)
    }
    let item = request()
    try model.enqueueVerified(item)
    await model.approve(item.id)
    await model.approve(item.id)
    #expect(messages.count == 1)
    #expect(signer.approvalSigns == 1)
    #expect(signer.denialSigns == 0)
    #expect(try decisionAction(#require(messages.first), key: signer.approval.publicKey) == 1)
    #expect(model.pending.isEmpty)
}

@Test @MainActor func canceledAuthenticationSendsSignedDenial() async throws {
    let signer = TestSigner()
    signer.failApproval = true
    var messages: [WireMessage] = []
    let model = SynModel(startServices: false, signer: signer) { message, _ in messages.append(message) }
    let item = request()
    try model.enqueueVerified(item)
    await model.approve(item.id)
    #expect(messages.count == 1)
    #expect(try decisionAction(#require(messages.first), key: signer.denial.publicKey) == 2)
    #expect(model.pending.isEmpty)
    #expect(model.authenticatingRequests.isEmpty)
}

@Test @MainActor func approvalFinishingAfterExpirySendsNothing() async throws {
    let signer = TestSigner()
    signer.approvalDelay = 0.15
    var messages: [WireMessage] = []
    let model = SynModel(startServices: false, signer: signer) { message, _ in messages.append(message) }
    let item = request(expiresIn: 0.05)
    try model.enqueueVerified(item)
    await model.approve(item.id)
    #expect(messages.isEmpty)
    #expect(model.pending.isEmpty)
}

@Test @MainActor func denyDuringAuthenticationPreventsApprovalAndDuplicatePrompt() async throws {
    let signer = TestSigner()
    signer.approvalDelay = 0.3
    var messages: [WireMessage] = []
    let model = SynModel(startServices: false, signer: signer) { message, _ in messages.append(message) }
    let item = request()
    try model.enqueueVerified(item)
    let task = Task { await model.approve(item.id) }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !signer.approvalStarted, ContinuousClock.now < deadline { await Task.yield() }
    #expect(signer.approvalStarted)
    await model.approve(item.id)
    await model.deny(item.id)
    await task.value
    #expect(signer.approvalSigns == 1)
    #expect(messages.count == 1)
    #expect(try decisionAction(#require(messages.first), key: signer.denial.publicKey) == 2)
}

@Test @MainActor func transportFailureDoesNotClaimCommandWasDenied() async throws {
    let signer = TestSigner()
    let model = SynModel(startServices: false, signer: signer) { _, _ in throw URLError(.networkConnectionLost) }
    let item = request()
    try model.enqueueVerified(item)
    await model.approve(item.id)
    #expect(model.pending.isEmpty)
    #expect(signer.denialSigns == 0)
    #expect(model.lastError?.contains("could not be confirmed") == true)
}

@Test func notificationsExcludeCommandAndEnvironment() {
    let item = request()
    let content = SynNotificationCenter.content(request: item, targetName: "test-target")
    #expect(content.title == "Syn approval requested")
    #expect(content.body == "test-target · test-user · just now")
    #expect(content.userInfo.count == 1)
    #expect(content.userInfo["requestID"] as? String == item.id)
    #expect(!content.body.contains("unique-private-argument-marker"))
    #expect(!content.body.contains("/usr/bin/true"))
}

@Test @MainActor func reviewRequestsWindowOpeningAndTargetIDsDoNotCollide() {
    let model = SynModel(startServices: false)
    var opened = false
    model.openMainWindow = { opened = true }
    model.review("test")
    #expect(opened)
    #expect(model.selectedRequestID == "test")
    #expect(request(target: "first").id != request(target: "second").id)
}
