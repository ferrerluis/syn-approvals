import CryptoKit
import Foundation
import Testing
@testable import Syn

private func harnessRequest(
    target: String = "e2e-target", nonceByte: UInt8 = 3,
    workingDirectory: String = "/private/tmp/syn-e2e", expiresIn: TimeInterval = 90
) -> VerifiedApprovalRequest {
    let issuedAt = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970 * 1_000) / 1_000)
    return VerifiedApprovalRequest(
        signedBytes: Data([9]), payloadHash: Data(repeating: 1, count: 32),
        requestID: Data(repeating: 2, count: 16), nonce: Data(repeating: nonceByte, count: 32),
        targetID: target, issuedAt: issuedAt, expiresAt: issuedAt.addingTimeInterval(expiresIn),
        invokingUID: 501, invokingUser: "e2e-user", runAsUID: 0, runAsUser: "root",
        runAsGroup: "wheel", workingDirectory: Data(workingDirectory.utf8),
        executable: Data("/usr/bin/true".utf8), arguments: [Data("--version".utf8)],
        environmentNames: ["PATH"], environmentDigest: Data(repeating: 4, count: 32),
        riskMarkers: ["test-only"], releaseID: ReleaseIdentity.current.releaseID,
        releaseCommit: SynProtocol.developmentCommit
    )
}

private func withHarnessDirectory<T>(_ body: (URL) throws -> T) throws -> T {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("syn-e2e-harness-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    defer { try? FileManager.default.removeItem(at: root) }
    return try body(root)
}

private func writeGrant(_ grant: E2ETestRequestGrant, to url: URL) throws {
    let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
    try encoder.encode(grant).write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

private func signatureInput(request: VerifiedApprovalRequest, approve: Bool, publicKey: Data) throws -> Data {
    let keyID = Data(SHA256.hash(data: publicKey))
    let payload = try SynProtocol.decisionPayload(request: request, approve: approve, approverKeyID: keyID)
    return try SynProtocol.signatureStructure(
        protected: SynProtocol.protectedHeader(keyID: keyID), payload: payload
    )
}

@Test func scenarioGrantRoundTripsAsVersionedJSON() throws {
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.case-e03", decision: .approve,
        expiresAt: Date(timeIntervalSince1970: 2_000_000_000), request: harnessRequest()
    )
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    #expect(try decoder.decode(E2ETestRequestGrant.self, from: encoder.encode(grant)) == grant)
}

@Test func grantRejectsProductionProfileAndExpiredOrBroadConfiguration() throws {
    let request = harnessRequest()
    let expired = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.*", decision: .approve,
        expiresAt: Date(timeIntervalSince1970: 1), request: request
    )
    #expect(throws: E2ETestHarnessError.self) { try expired.validate() }

    let production = E2ETestRequestGrant(
        profileID: "org.syn-approvals.Syn", decision: .approve,
        expiresAt: Date().addingTimeInterval(30), request: request
    )
    #expect(throws: E2ETestHarnessError.self) { try production.validate() }
}

@Test func signerBindsFullVerifiedRequestAndRejectsContextMismatches() throws {
    let request = harnessRequest()
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.case-e09", decision: .approve,
        expiresAt: Date().addingTimeInterval(30), request: request
    )
    try withHarnessDirectory { directory in
        let keys = try E2EDisposableKeyStore(rootDirectory: directory, profileID: grant.profileID)
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EScenarioSigner(grant: grant, request: harnessRequest(nonceByte: 8), keys: keys)
        }
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EScenarioSigner(grant: grant, request: harnessRequest(target: "another-target"), keys: keys)
        }
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EScenarioSigner(
                grant: grant, request: harnessRequest(workingDirectory: "/private/tmp/other"), keys: keys
            )
        }
    }
}

@Test func grantExpiringAfterAuthorizationIsConsumedAndFailsClosed() throws {
    let request = harnessRequest()
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.case-expiry", decision: .approve,
        expiresAt: Date().addingTimeInterval(0.02), request: request
    )
    try withHarnessDirectory { directory in
        let keys = try E2EDisposableKeyStore(rootDirectory: directory, profileID: grant.profileID)
        let signer = try E2EScenarioSigner(grant: grant, request: request, keys: keys)
        Thread.sleep(forTimeInterval: 0.03)
        #expect(throws: E2ETestHarnessError.self) {
            _ = try signer.signApproval(payload: Data([1]), reason: "expired", cancellation: ApprovalCancellation())
        }
        #expect(throws: E2ETestHarnessError.grantConsumed) {
            _ = try signer.signApproval(payload: Data([1]), reason: "replay", cancellation: ApprovalCancellation())
        }
    }
}

@Test func requestExpiryCapsLongerGrantAtSigningTime() throws {
    let request = harnessRequest(expiresIn: 30)
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.case-request-expiry", decision: .approve,
        expiresAt: Date().addingTimeInterval(30), request: request
    )
    try withHarnessDirectory { root in
        let keys = try E2EDisposableKeyStore(rootDirectory: root, profileID: grant.profileID)
        let signer = try E2EScenarioSigner(
            grant: grant, request: request, keys: keys, now: request.issuedAt,
            currentDate: { request.expiresAt.addingTimeInterval(1) }
        )
        let input = try signatureInput(request: request, approve: true, publicKey: signer.approvalPublicKey())
        #expect(throws: E2ETestHarnessError.self) {
            _ = try signer.signApproval(payload: input, reason: "expired", cancellation: ApprovalCancellation())
        }
        #expect(throws: E2ETestHarnessError.grantConsumed) {
            _ = try signer.signApproval(payload: input, reason: "replay", cancellation: ApprovalCancellation())
        }
    }
}

@Test func oneUseApprovalSignsThenFailsClosedOnReplay() throws {
    let request = harnessRequest()
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.case-e08", decision: .approve,
        expiresAt: Date().addingTimeInterval(30), request: request
    )
    try withHarnessDirectory { directory in
        let keys = try E2EDisposableKeyStore(rootDirectory: directory, profileID: grant.profileID)
        let signer = try E2EScenarioSigner(grant: grant, request: request, keys: keys)
        let payload = try signatureInput(request: request, approve: true, publicKey: signer.approvalPublicKey())
        let signed = try signer.signApproval(payload: payload, reason: "test", cancellation: ApprovalCancellation())
        let publicKey = try P256.Signing.PublicKey(x963Representation: signer.approvalPublicKey())
        #expect(publicKey.isValidSignature(
            try P256.Signing.ECDSASignature(rawRepresentation: signed.signature), for: payload
        ))
        #expect(throws: E2ETestHarnessError.self) {
            _ = try signer.signApproval(payload: payload, reason: "replay", cancellation: ApprovalCancellation())
        }
    }
}


@Test func disposableStoreRejectsSymlinkRoot() throws {
    try withHarnessDirectory { root in
        let link = root.deletingLastPathComponent().appendingPathComponent("syn-e2e-link-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: link) }
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EDisposableKeyStore(
                rootDirectory: link, profileID: "org.syn-approvals.SynE2E.symlink-root"
            )
        }
    }
}

@Test func cleanupRefusesForeignOrReplacedFilesWithoutDeletingCallerRoot() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.foreign-file"
        let keys = try E2EDisposableKeyStore(rootDirectory: root, profileID: profile)
        let store = root.appendingPathComponent(profile)
        let foreign = store.appendingPathComponent("foreign")
        #expect(FileManager.default.createFile(atPath: foreign.path, contents: Data([1])))
        #expect(throws: E2ETestHarnessError.self) { try keys.cleanup() }
        #expect(FileManager.default.fileExists(atPath: root.path))
        #expect(FileManager.default.fileExists(atPath: foreign.path))
    }

    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.replaced-key"
        let keys = try E2EDisposableKeyStore(rootDirectory: root, profileID: profile)
        let key = root.appendingPathComponent(profile).appendingPathComponent("profile-record.json")
        try FileManager.default.removeItem(at: key)
        #expect(FileManager.default.createFile(atPath: key.path, contents: Data(repeating: 9, count: 32)))
        #expect(throws: E2ETestHarnessError.self) { try keys.cleanup() }
        #expect(try Data(contentsOf: key) == Data(repeating: 9, count: 32))
        #expect(FileManager.default.fileExists(atPath: root.path))
    }
}

@Test func partialKeyWriteFailureRemovesOnlyTheOwnedProfile() throws {
    try withHarnessDirectory { root in
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EDisposableKeyStore(
                rootDirectory: root, profileID: "org.syn-approvals.SynE2E.partial-write",
                failWriteAfterBytes: 7
            )
        }
        #expect(FileManager.default.fileExists(atPath: root.path))
        let remaining = try FileManager.default.contentsOfDirectory(atPath: root.path)
        #expect(remaining.isEmpty)
    }
}

@Test func initialIdentityFailureWritesNoKeyBytesAndRemovesOnlyOwnedProfile() throws {
    try withHarnessDirectory { root in
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EDisposableKeyStore(
                rootDirectory: root, profileID: "org.syn-approvals.SynE2E.initial-identity",
                failInitialIdentityCheck: true
            )
        }
        let remaining = try FileManager.default.contentsOfDirectory(atPath: root.path)
        #expect(remaining.isEmpty)
    }
}

@Test func wrongSignatureInputConsumesGrantAndFailsClosed() throws {
    let request = harnessRequest()
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.case-wrong-input", decision: .approve,
        expiresAt: Date().addingTimeInterval(30), request: request
    )
    try withHarnessDirectory { root in
        let keys = try E2EDisposableKeyStore(rootDirectory: root, profileID: grant.profileID)
        let signer = try E2EScenarioSigner(grant: grant, request: request, keys: keys)
        let wrong = try signatureInput(request: request, approve: false, publicKey: signer.denialPublicKey())
        #expect(throws: E2ETestHarnessError.requestMismatch) {
            _ = try signer.signApproval(payload: wrong, reason: "wrong", cancellation: ApprovalCancellation())
        }
        #expect(throws: E2ETestHarnessError.grantConsumed) {
            _ = try signer.signApproval(payload: wrong, reason: "replay", cancellation: ApprovalCancellation())
        }
    }
}

@Test func requestAwareProviderArmsOnlyTheExactVerifiedRequest() throws {
    let request = harnessRequest()
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.provider", decision: .approve,
        expiresAt: Date().addingTimeInterval(30), request: request
    )
    try withHarnessDirectory { root in
        let keys = try E2EDisposableKeyStore(rootDirectory: root, profileID: grant.profileID)
        let inbox = try E2EGrantInbox(directory: root, profileID: grant.profileID)
        try writeGrant(grant, to: inbox.grantURL)
        let provider = E2EScenarioSigningProvider(inbox: inbox, keys: keys)
        #expect(throws: E2ETestHarnessError.requestMismatch) {
            _ = try provider.signer(for: harnessRequest(target: "wrong-target"))
        }
        // A mismatched grant is spent. The mock authenticator must issue a new
        // exact grant after observing the real request.
        try writeGrant(grant, to: inbox.grantURL)
        let signer = try provider.signer(for: request)
        #expect(try provider.publicIdentities().approval == signer.approvalPublicKey())
        #expect(throws: E2ETestHarnessError.requestMismatch) {
            _ = try provider.signer(for: harnessRequest(nonceByte: 7))
        }
    }
}

@Test func inboxPublishesObservedRequestAndAtomicallySpendsExactGrant() throws {
    let request = harnessRequest(nonceByte: 44)
    let profile = "org.syn-approvals.SynE2E.dynamic-inbox"
    try withHarnessDirectory { root in
        let inbox = try E2EGrantInbox(directory: root, profileID: profile)
        try inbox.publish(request)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let offer = try decoder.decode(E2ETestRequestOffer.self, from: Data(contentsOf: inbox.offerURL))
        #expect(offer.profileID == profile)
        #expect(offer.request.matches(request))

        let grant = E2ETestRequestGrant(
            profileID: profile, decision: .approve,
            expiresAt: Date().addingTimeInterval(30), request: request
        )
        try writeGrant(grant, to: inbox.grantURL)
        let consumed = try inbox.consumeGrant(for: request)
        #expect(consumed.matches(request))
        #expect(consumed.decision == grant.decision)
        #expect(!FileManager.default.fileExists(atPath: inbox.grantURL.path))
        #expect(throws: Error.self) { _ = try inbox.consumeGrant(for: request) }
    }
}

@Test func inboxCleanupPreservesReplacedOfferAndForeignGrant() throws {
    let request = harnessRequest()
    let profile = "org.syn-approvals.SynE2E.inbox-cleanup"
    try withHarnessDirectory { root in
        let inbox = try E2EGrantInbox(directory: root, profileID: profile)
        try inbox.publish(request)
        try FileManager.default.removeItem(at: inbox.offerURL)
        let replacement = Data("foreign offer".utf8)
        try replacement.write(to: inbox.offerURL)
        let foreignGrant = Data("foreign grant".utf8)
        try foreignGrant.write(to: inbox.grantURL)
        try inbox.cleanupOwnedFiles()
        #expect(try Data(contentsOf: inbox.offerURL) == replacement)
        #expect(try Data(contentsOf: inbox.grantURL) == foreignGrant)
    }
}

@Test func inboxCleanupRemovesOwnedEmptyDirectoryWithNoOrConsumedOffer() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.no-offer"
        let inbox = try E2EGrantInbox(directory: root, profileID: profile)
        let directory = inbox.offerURL.deletingLastPathComponent()
        try inbox.cleanupOwnedFiles()
        #expect(!FileManager.default.fileExists(atPath: directory.path))
    }
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.consumed-offer"
        let inbox = try E2EGrantInbox(directory: root, profileID: profile)
        let directory = inbox.offerURL.deletingLastPathComponent()
        try inbox.publish(harnessRequest())
        try FileManager.default.removeItem(at: inbox.offerURL)
        try inbox.cleanupOwnedFiles()
        #expect(!FileManager.default.fileExists(atPath: directory.path))
    }
}

@Test func inboxRejectsPermissiveOrSymlinkedRootsAndUnsafeGrants() throws {
    try withHarnessDirectory { root in
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EGrantInbox(directory: root, profileID: "org.syn-approvals.SynE2E.bad-root-mode")
        }
    }
    try withHarnessDirectory { root in
        let link = root.deletingLastPathComponent().appendingPathComponent("inbox-root-link-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: link) }
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        #expect(throws: E2ETestHarnessError.self) {
            _ = try E2EGrantInbox(directory: link, profileID: "org.syn-approvals.SynE2E.symlink-root")
        }
    }
    try withHarnessDirectory { root in
        let request = harnessRequest()
        let profile = "org.syn-approvals.SynE2E.unsafe-grant"
        let inbox = try E2EGrantInbox(directory: root, profileID: profile)
        let external = root.appendingPathComponent("external-grant")
        let grant = E2ETestRequestGrant(
            profileID: profile, decision: .approve,
            expiresAt: Date().addingTimeInterval(30), request: request
        )
        try writeGrant(grant, to: external)
        try FileManager.default.createSymbolicLink(at: inbox.grantURL, withDestinationURL: external)
        #expect(throws: E2ETestHarnessError.self) { _ = try inbox.consumeGrant(for: request) }
        #expect(FileManager.default.fileExists(atPath: external.path))
        try FileManager.default.removeItem(at: inbox.grantURL)
        try writeGrant(grant, to: inbox.grantURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: inbox.grantURL.path)
        #expect(throws: E2ETestHarnessError.self) { _ = try inbox.consumeGrant(for: request) }
        #expect(FileManager.default.fileExists(atPath: inbox.grantURL.path))
    }
}

@Test func grantReplacementBetweenCheckAndClaimIsPreservedAndRejected() throws {
    let request = harnessRequest()
    let profile = "org.syn-approvals.SynE2E.grant-race"
    try withHarnessDirectory { root in
        let grantURL = root.appendingPathComponent(profile + ".inbox/grant.json")
        let replacement = Data("replacement".utf8)
        let inbox = try E2EGrantInbox(directory: root, profileID: profile) {
            try? FileManager.default.removeItem(at: grantURL)
            try? replacement.write(to: grantURL)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: grantURL.path)
        }
        let grant = E2ETestRequestGrant(
            profileID: profile, decision: .approve,
            expiresAt: Date().addingTimeInterval(30), request: request
        )
        try writeGrant(grant, to: inbox.grantURL)
        #expect(throws: E2ETestHarnessError.self) { _ = try inbox.consumeGrant(for: request) }
        #expect(try Data(contentsOf: inbox.grantURL) == replacement)
    }
}


@Test func cancellationConsumesGrantWithoutProducingSignature() throws {
    let request = harnessRequest()
    let grant = E2ETestRequestGrant(
        profileID: "org.syn-approvals.SynE2E.case-e06", decision: .cancelAuthentication,
        expiresAt: Date().addingTimeInterval(30), request: request
    )
    try withHarnessDirectory { directory in
        let keys = try E2EDisposableKeyStore(rootDirectory: directory, profileID: grant.profileID)
        let signer = try E2EScenarioSigner(grant: grant, request: request, keys: keys)
        let payload = try signatureInput(request: request, approve: true, publicKey: signer.approvalPublicKey())
        #expect(throws: E2ETestHarnessError.simulatedCancellation) {
            _ = try signer.signApproval(payload: payload, reason: "test", cancellation: ApprovalCancellation())
        }
        #expect(throws: E2ETestHarnessError.grantConsumed) {
            _ = try signer.signApproval(payload: payload, reason: "test", cancellation: ApprovalCancellation())
        }
    }
}

@Test func disposableStorePersistsExactKeysAcrossRelaunchAndCleansCrashResiduals() throws {
    try withHarnessDirectory { directory in
        let profile = "org.syn-approvals.SynE2E.case-e12"
        var keys: E2EDisposableKeyStore? = try E2EDisposableKeyStore(
            rootDirectory: directory, profileID: profile
        )
        let store = directory.appendingPathComponent(profile)
        let files = try FileManager.default.contentsOfDirectory(atPath: store.path)
        #expect(Set(files) == ["approval-private-key.raw", "denial-private-key.raw", "profile-record.json"])
        let first = try #require(keys).handoff
        keys = nil // Model an app exit or crash without deleting the run-owned profile.
        let relaunched = try E2EDisposableKeyStore(rootDirectory: directory, profileID: profile)
        #expect(relaunched.handoff == first)
        #expect(relaunched.handoff.approvalPublicKeyID == Data(SHA256.hash(data: first.approvalPublicKey)))
        #expect(relaunched.handoff.denialPublicKeyID == Data(SHA256.hash(data: first.denialPublicKey)))
        try relaunched.cleanup()
        #expect(FileManager.default.fileExists(atPath: directory.path))
        #expect(!FileManager.default.fileExists(atPath: store.path))
    }
}

@Test func appProfileCompositionReopensAndFinalCleanupRemovesExactCrashResiduals() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.composition-relaunch"
        var keys: E2EDisposableKeyStore? = try E2EDisposableKeyStore(rootDirectory: root, profileID: profile)
        var inbox: E2EGrantInbox? = try E2EGrantInbox(directory: root, profileID: profile)
        var state: E2EProfileState? = try E2EProfileState(rootDirectory: root, profileID: profile)
        let first = try #require(keys).handoff
        #expect(try #require(inbox).grantURL.lastPathComponent == "grant.json")
        try Data("host-key\n".utf8).write(to: try #require(state).directory.appendingPathComponent("known_hosts"))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: try #require(state).directory.appendingPathComponent("known_hosts").path
        )
        keys = nil; inbox = nil; state = nil

        let relaunchedKeys = try E2EDisposableKeyStore(rootDirectory: root, profileID: profile)
        let relaunchedInbox = try E2EGrantInbox(directory: root, profileID: profile)
        let relaunchedState = try E2EProfileState(rootDirectory: root, profileID: profile)
        #expect(relaunchedKeys.handoff == first)
        #expect(FileManager.default.fileExists(atPath: relaunchedState.directory.appendingPathComponent("known_hosts").path))

        try relaunchedState.cleanup()
        try relaunchedInbox.cleanupOwnedFiles()
        try relaunchedKeys.cleanup()
        for suffix in ["", ".inbox", ".state"] {
            #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent(profile + suffix).path))
        }
    }
}

@Test func finalCleanupRejectsRacingReplacementsAndPreservesTheirBytes() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.cleanup-race"
        let inboxDirectory = root.appendingPathComponent(profile + ".inbox")
        let offer = inboxDirectory.appendingPathComponent("offer.json")
        let replacement = Data("foreign replacement".utf8)
        let inbox = try E2EGrantInbox(directory: root, profileID: profile, beforeCleanupClaim: { name in
            guard name == "offer.json" else { return }
            try? FileManager.default.removeItem(at: offer)
            FileManager.default.createFile(atPath: offer.path, contents: replacement)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: offer.path)
        })
        try inbox.publish(harnessRequest())
        #expect(throws: E2ETestHarnessError.self) { try inbox.cleanupOwnedFiles(requireRemoval: true) }
        #expect(try Data(contentsOf: offer) == replacement)
    }

    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.state-cleanup-race"
        let stateDirectory = root.appendingPathComponent(profile + ".state")
        let knownHosts = stateDirectory.appendingPathComponent("known_hosts")
        let replacement = Data("foreign state replacement".utf8)
        let state = try E2EProfileState(rootDirectory: root, profileID: profile, beforeCleanupClaim: { name in
            guard name == "known_hosts" else { return }
            try? FileManager.default.removeItem(at: knownHosts)
            FileManager.default.createFile(atPath: knownHosts.path, contents: replacement)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: knownHosts.path)
        })
        FileManager.default.createFile(atPath: knownHosts.path, contents: Data("owned".utf8))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: knownHosts.path)
        #expect(throws: E2ETestHarnessError.self) { try state.cleanup() }
        #expect(try Data(contentsOf: knownHosts) == replacement)
    }
}

@Test func finalCleanupPreservesReopenedAndDirectoryReplacements() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.reopened-race"
        var writer: E2EGrantInbox? = try E2EGrantInbox(directory: root, profileID: profile)
        try writer?.publish(harnessRequest()); writer = nil
        let offer = root.appendingPathComponent(profile + ".inbox/offer.json")
        let replacement = Data("reopened replacement".utf8)
        let reopened = try E2EGrantInbox(directory: root, profileID: profile, beforeCleanupClaim: { name in
            guard name == "offer.json" else { return }
            try? FileManager.default.removeItem(at: offer)
            FileManager.default.createFile(atPath: offer.path, contents: replacement)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: offer.path)
        })
        #expect(throws: E2ETestHarnessError.self) { try reopened.cleanupOwnedFiles(requireRemoval: true) }
        #expect(try Data(contentsOf: offer) == replacement)
    }

    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.directory-race"
        let inboxURL = root.appendingPathComponent(profile + ".inbox")
        let displaced = root.appendingPathComponent("owned-inbox")
        let sentinel = inboxURL.appendingPathComponent("sentinel")
        let inbox = try E2EGrantInbox(directory: root, profileID: profile, beforeDirectoryCleanupClaim: {
            try? FileManager.default.moveItem(at: inboxURL, to: displaced)
            try? FileManager.default.createDirectory(at: inboxURL, withIntermediateDirectories: false)
            FileManager.default.createFile(atPath: sentinel.path, contents: Data("keep".utf8))
        })
        #expect(throws: E2ETestHarnessError.self) { try inbox.cleanupOwnedFiles(requireRemoval: true) }
        #expect(try Data(contentsOf: sentinel) == Data("keep".utf8))
    }

    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.state-directory-race"
        let stateURL = root.appendingPathComponent(profile + ".state")
        let displaced = root.appendingPathComponent("owned-state")
        let sentinel = stateURL.appendingPathComponent("sentinel")
        let state = try E2EProfileState(rootDirectory: root, profileID: profile, beforeDirectoryCleanupClaim: {
            try? FileManager.default.moveItem(at: stateURL, to: displaced)
            try? FileManager.default.createDirectory(at: stateURL, withIntermediateDirectories: false)
            FileManager.default.createFile(atPath: sentinel.path, contents: Data("keep".utf8))
        })
        #expect(throws: E2ETestHarnessError.self) { try state.cleanup() }
        #expect(try Data(contentsOf: sentinel) == Data("keep".utf8))
    }
}

@Test func failedReopenPreservesPreexistingInboxAndStateObjects() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.failed-reopen"
        for suffix in [".inbox", ".state"] {
            let path = root.appendingPathComponent(profile + suffix)
            let bytes = Data("foreign".utf8)
            FileManager.default.createFile(atPath: path.path, contents: bytes)
            if suffix == ".inbox" {
                #expect(throws: E2ETestHarnessError.self) { _ = try E2EGrantInbox(directory: root, profileID: profile) }
            } else {
                #expect(throws: E2ETestHarnessError.self) { _ = try E2EProfileState(rootDirectory: root, profileID: profile) }
            }
            #expect(try Data(contentsOf: path) == bytes)
            try FileManager.default.removeItem(at: path)
        }
    }
}

@Test func finalCleanupRejectsMetadataChangesBeforeStagedDeletion() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.file-mode-race"
        let offer = root.appendingPathComponent(profile + ".inbox/offer.json")
        let inbox = try E2EGrantInbox(directory: root, profileID: profile, beforeCleanupClaim: { name in
            if name == "offer.json" { try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: offer.path) }
        })
        try inbox.publish(harnessRequest())
        #expect(throws: E2ETestHarnessError.self) { try inbox.cleanupOwnedFiles(requireRemoval: true) }
        #expect(FileManager.default.fileExists(atPath: offer.path))
    }
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.directory-mode-race"
        let directory = root.appendingPathComponent(profile + ".state")
        let state = try E2EProfileState(rootDirectory: root, profileID: profile, beforeDirectoryCleanupClaim: {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
        })
        #expect(throws: E2ETestHarnessError.self) { try state.cleanup() }
        #expect(FileManager.default.fileExists(atPath: directory.path))
    }
}

@Test func persistedKeyStoreRejectsMalformedUnsafeAndForeignEntriesWithoutOverwriting() throws {
    for (profile, mutate) in [
        ("org.syn-approvals.SynE2E.malformed-key", { (store: URL) in
            let key = store.appendingPathComponent("approval-private-key.raw")
            try Data(repeating: 7, count: 31).write(to: key)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: key.path)
        }),
        ("org.syn-approvals.SynE2E.unsafe-mode", { (store: URL) in
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644], ofItemAtPath: store.appendingPathComponent("denial-private-key.raw").path
            )
        }),
        ("org.syn-approvals.SynE2E.unsafe-profile-mode", { (store: URL) in
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: store.path)
        }),
        ("org.syn-approvals.SynE2E.identity-mismatch", { (store: URL) in
            let record = store.appendingPathComponent("profile-record.json")
            var value = try #require(
                try JSONSerialization.jsonObject(with: Data(contentsOf: record)) as? [String: Any]
            )
            value["approvalPublicKeyID"] = Data(repeating: 0, count: 32).base64EncodedString()
            try JSONSerialization.data(withJSONObject: value).write(to: record)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: record.path)
        }),
        ("org.syn-approvals.SynE2E.foreign-entry", { (store: URL) in
            #expect(FileManager.default.createFile(
                atPath: store.appendingPathComponent("foreign").path, contents: Data([1])
            ))
        }),
    ] {
        try withHarnessDirectory { root in
            var initial: E2EDisposableKeyStore? = try E2EDisposableKeyStore(
                rootDirectory: root, profileID: profile
            )
            let store = root.appendingPathComponent(profile)
            initial = nil
            try mutate(store)
            #expect(throws: Error.self) {
                _ = try E2EDisposableKeyStore(rootDirectory: root, profileID: profile)
            }
            #expect(FileManager.default.fileExists(atPath: store.path))
            _ = initial
        }
    }
}

@Test func persistedKeyStoreRejectsSymlinkedKeyAndPreservesExternalTarget() throws {
    try withHarnessDirectory { root in
        let profile = "org.syn-approvals.SynE2E.symlink-key"
        var initial: E2EDisposableKeyStore? = try E2EDisposableKeyStore(
            rootDirectory: root, profileID: profile
        )
        let store = root.appendingPathComponent(profile)
        let key = store.appendingPathComponent("approval-private-key.raw")
        let external = root.appendingPathComponent("external-key")
        let sentinel = Data(repeating: 9, count: 32)
        try sentinel.write(to: external)
        try FileManager.default.removeItem(at: key)
        try FileManager.default.createSymbolicLink(at: key, withDestinationURL: external)
        initial = nil
        #expect(throws: Error.self) {
            _ = try E2EDisposableKeyStore(rootDirectory: root, profileID: profile)
        }
        #expect(try Data(contentsOf: external) == sentinel)
        _ = initial
    }
}
