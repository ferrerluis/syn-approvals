import Foundation
import Testing
@testable import Syn

private let clientAuthOID = Data([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])

@Test func transportIdentityReusesTheExactLabeledIdentity() throws {
    let label = "Syn kitchen_pi transport"
    let material = identityMaterial(label: label, certificate: Data(0...127))
    let backend = TestTransportIdentityBackend(existing: [material], generated: material)
    let store = TransportIdentityStore(backend: backend)

    let first = try store.identity(for: "kitchen_pi")
    let second = try store.identity(for: "kitchen_pi")

    #expect(first == second)
    #expect(first.label == label)
    #expect(first.certificatePEM == canonicalPEM(material.certificateDER))
    #expect(backend.createCalls == 0)
}

@Test func transportIdentityCreatesOnceThenReadsThroughTheConnectionLookupContract() throws {
    let label = "Syn target-1 transport"
    let material = identityMaterial(label: label, certificate: Data([1, 3, 3, 7]))
    let backend = TestTransportIdentityBackend(existing: [], generated: material)
    let store = TransportIdentityStore(backend: backend)

    let created = try store.identity(for: "target-1")
    let existing = try #require(try store.existingIdentity(for: "target-1"))

    #expect(created == existing)
    #expect(backend.createCalls == 1)
    #expect(backend.requestedLabels == [label, label, label])
}

@Test func transportIdentityRejectsInvalidTargetIDsBeforeUsingTheBackend() {
    let label = "Syn unused transport"
    let material = identityMaterial(label: label)
    let backend = TestTransportIdentityBackend(existing: [], generated: material)
    let store = TransportIdentityStore(backend: backend)

    for targetID in ["", "has space", "slash/name", String(repeating: "a", count: 129), "pí"] {
        #expect(throws: TransportIdentityStoreError.invalidTargetID) {
            _ = try store.identity(for: targetID)
        }
    }
    #expect(backend.requestedLabels.isEmpty)
    #expect(backend.createCalls == 0)
}

@Test func transportIdentityValidationFailsClosedForEveryBoundProperty() {
    let label = "Syn pi transport"
    let key = Data([4, 1, 2, 3])
    let valid = identityMaterial(label: label, publicKey: key)
    let invalid: [TransportIdentityMaterial] = [
        identityMaterial(label: "Syn other transport", publicKey: key),
        TransportIdentityMaterial(
            certificateDER: valid.certificateDER, commonName: label,
            extendedKeyUsageOIDs: [], certificatePublicKey: key,
            identityPublicKey: key, isP256: true,
            notBefore: valid.notBefore, notAfter: valid.notAfter
        ),
        TransportIdentityMaterial(
            certificateDER: valid.certificateDER, commonName: label,
            extendedKeyUsageOIDs: [clientAuthOID], certificatePublicKey: key,
            identityPublicKey: Data([4, 9, 9, 9]), isP256: true,
            notBefore: valid.notBefore, notAfter: valid.notAfter
        ),
        TransportIdentityMaterial(
            certificateDER: valid.certificateDER, commonName: label,
            extendedKeyUsageOIDs: [clientAuthOID], certificatePublicKey: key,
            identityPublicKey: key, isP256: false,
            notBefore: valid.notBefore, notAfter: valid.notAfter
        ),
        TransportIdentityMaterial(
            certificateDER: Data(), commonName: label,
            extendedKeyUsageOIDs: [clientAuthOID], certificatePublicKey: key,
            identityPublicKey: key, isP256: true,
            notBefore: valid.notBefore, notAfter: valid.notAfter
        ),
    ]

    #expect(TransportIdentityStore.valid(valid, label: label))
    for material in invalid {
        #expect(!TransportIdentityStore.valid(material, label: label))
        let backend = TestTransportIdentityBackend(existing: [material], generated: valid)
        #expect(throws: TransportIdentityStoreError.labelCollision(label)) {
            _ = try TransportIdentityStore(backend: backend).existingIdentity(for: "pi")
        }
        #expect(backend.createCalls == 0)
    }
}

@Test func transportIdentityRejectsDuplicateLabelsAndInvalidGeneratedMaterial() {
    let label = "Syn pi transport"
    let valid = identityMaterial(label: label)
    let duplicateBackend = TestTransportIdentityBackend(existing: [valid, valid], generated: valid)
    #expect(throws: TransportIdentityStoreError.labelCollision(label)) {
        _ = try TransportIdentityStore(backend: duplicateBackend).identity(for: "pi")
    }
    #expect(duplicateBackend.createCalls == 0)

    let invalid = TransportIdentityMaterial(
        certificateDER: valid.certificateDER, commonName: label,
        extendedKeyUsageOIDs: [clientAuthOID], certificatePublicKey: valid.certificatePublicKey,
        identityPublicKey: nil, isP256: true,
        notBefore: valid.notBefore, notAfter: valid.notAfter
    )
    let invalidBackend = TestTransportIdentityBackend(existing: [], generated: invalid)
    #expect(throws: TransportIdentityStoreError.invalidGeneratedIdentity) {
        _ = try TransportIdentityStore(backend: invalidBackend).identity(for: "pi")
    }
    #expect(invalidBackend.createCalls == 1)
    #expect(invalidBackend.deletedCertificates == [valid.certificateDER])
}

@Test func transportIdentityRequiresExplicitRenewalWithoutReplacingPinnedCertificate() {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let label = "Syn pi transport"
    let expiring = identityMaterial(
        label: label,
        notBefore: now.addingTimeInterval(-86_400),
        notAfter: now.addingTimeInterval(TransportIdentityStore.renewalMargin)
    )
    let backend = TestTransportIdentityBackend(existing: [expiring], generated: expiring)
    let store = TransportIdentityStore(backend: backend, now: { now })

    #expect(throws: TransportIdentityStoreError.renewalRequired(label)) {
        _ = try store.identity(for: "pi")
    }
    #expect(backend.createCalls == 0)
    #expect(backend.deletedCertificates.isEmpty)
}

@Test func failedPostImportValidationRollsBackOnlyTheCreatedCertificate() {
    let label = "Syn pi transport"
    let created = identityMaterial(label: label, certificate: Data([1, 2, 3]))
    let competing = identityMaterial(label: label, certificate: Data([4, 5, 6]))
    let backend = TestTransportIdentityBackend(
        existing: [], generated: created, additionsAfterCreate: [competing]
    )

    #expect(throws: TransportIdentityStoreError.labelCollision(label)) {
        _ = try TransportIdentityStore(backend: backend).identity(for: "pi")
    }
    #expect(backend.deletedCertificates == [created.certificateDER])
    #expect(backend.storedCertificates == [competing.certificateDER])
}

@Test func concurrentCreatorsForOneLabelCreateOnlyOnce() throws {
    let label = "Syn concurrent_target transport"
    let generated = identityMaterial(label: label)
    let backend = TestTransportIdentityBackend(existing: [], generated: generated, createDelay: 0.1)
    let firstStore = TransportIdentityStore(backend: backend)
    let secondStore = TransportIdentityStore(backend: backend)
    let results = LockedResults()
    let group = DispatchGroup()

    for store in [firstStore, secondStore] {
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            do { results.append(.success(try store.identity(for: "concurrent_target"))) }
            catch { results.append(.failure(error)) }
        }
    }
    #expect(group.wait(timeout: .now() + 5) == .success)
    let values = results.values
    #expect(values.count == 2)
    for value in values {
        #expect(try value.get().label == label)
    }
    #expect(backend.createCalls == 1)
    #expect(backend.storedCertificates == [generated.certificateDER])
}

@Test func opensslPipeGenerationProducesBoundP256ClientIdentityWithoutKeychain() throws {
    let label = "Syn pipe_test transport"
    let generated = try MacTransportIdentityBackend.generatedMaterialForTesting(label: label)
    #expect(TransportIdentityStore.valid(generated, label: label))
}

private func identityMaterial(
    label: String,
    certificate: Data = Data([0x30, 0x03, 0x02, 0x01, 0x01]),
    publicKey: Data = Data([4, 1, 2, 3]),
    notBefore: Date = Date(timeIntervalSince1970: 1_700_000_000),
    notAfter: Date = Date(timeIntervalSince1970: 2_000_000_000)
) -> TransportIdentityMaterial {
    TransportIdentityMaterial(
        certificateDER: certificate,
        commonName: label,
        extendedKeyUsageOIDs: [clientAuthOID],
        certificatePublicKey: publicKey,
        identityPublicKey: publicKey,
        isP256: true,
        notBefore: notBefore,
        notAfter: notAfter
    )
}

private func canonicalPEM(_ data: Data) -> Data {
    let body = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return Data("-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n".utf8)
}

private final class TestTransportIdentityBackend: TransportIdentityBackend, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [TransportIdentityMaterial]
    private let generated: TransportIdentityMaterial
    private let additionsAfterCreate: [TransportIdentityMaterial]
    private let createDelay: TimeInterval
    private var createCallCount = 0
    private var labels: [String] = []
    private var deletions: [Data] = []

    init(
        existing: [TransportIdentityMaterial],
        generated: TransportIdentityMaterial,
        additionsAfterCreate: [TransportIdentityMaterial] = [],
        createDelay: TimeInterval = 0
    ) {
        stored = existing
        self.generated = generated
        self.additionsAfterCreate = additionsAfterCreate
        self.createDelay = createDelay
    }

    func identities(label: String) throws -> [TransportIdentityMaterial] {
        lock.withLock {
            labels.append(label)
            return stored
        }
    }

    func createIdentity(label: String) throws -> TransportIdentityMaterial {
        if createDelay > 0 { Thread.sleep(forTimeInterval: createDelay) }
        return lock.withLock {
            createCallCount += 1
            stored.append(generated)
            stored.append(contentsOf: additionsAfterCreate)
            return generated
        }
    }

    func deleteIdentity(label: String, certificateDER: Data) throws {
        lock.withLock {
            deletions.append(certificateDER)
            stored.removeAll { $0.certificateDER == certificateDER }
        }
    }

    var createCalls: Int { lock.withLock { createCallCount } }
    var requestedLabels: [String] { lock.withLock { labels } }
    var deletedCertificates: [Data] { lock.withLock { deletions } }
    var storedCertificates: [Data] { lock.withLock { stored.map(\.certificateDER) } }
}

private final class LockedResults: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [Result<TransportIdentity, Error>] = []

    func append(_ result: Result<TransportIdentity, Error>) {
        lock.withLock { storage.append(result) }
    }

    var values: [Result<TransportIdentity, Error>] { lock.withLock { storage } }
}
