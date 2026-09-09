import CryptoKit
import Darwin
import Foundation
import Testing
@testable import Syn

private let releaseID = "20260905123456"
private let commit = String(repeating: "a", count: 40)

@Test func remoteSourceErrorsOfferSafeRetryGuidance() {
    let error = RemoteSourceArtifactError.fileOperationFailed(operation: "untrusted diagnostic", code: 123)
    #expect(!error.localizedDescription.contains("untrusted diagnostic"))
    #expect(error.localizedDescription.contains("retry"))
    #expect(RemoteSourceArtifactError.artifactHashMismatch.localizedDescription.contains("Download it again"))
}

@Test func remoteSourceDescriptorParsesAndVerifiesAStreamedArtifact() throws {
    try withTemporaryDirectory { directory in
        let data = Data((0..<(192 * 1024 + 17)).map { UInt8($0 % 251) })
        let name = "syn-remote-source-" + releaseID + ".tar.gz"
        let artifactURL = directory.appendingPathComponent(name)
        try data.write(to: artifactURL)
        let descriptor = try parseDescriptor(name: name, data: data)

        let verified = try descriptor.verifyArtifact(at: artifactURL)
        #expect(verified.descriptor == descriptor)
        let readBack = try verified.withFileDescriptor(readAll)
        #expect(readBack == data)
    }
}

@Test func remoteSourceDescriptorRejectsUnknownFieldsAndNonIntegerNumbers() {
    let hash = String(repeating: "0", count: 64)
    let artifact = "\"artifact\":{\"kind\":\"remote_source\",\"name\":\"source.tar.gz\",\"sha256\":\"" + hash + "\",\"size_bytes\":1}"
    let invalidValues = [
        "{\"schema_version\":1,\"release_id\":\"" + releaseID + "\",\"commit\":\"" + commit + "\",\"extra\":0," + artifact + "}",
        "{\"schema_version\":1,\"release_id\":\"" + releaseID + "\",\"commit\":\"" + commit + "\",\"artifact\":{\"kind\":\"remote_source\",\"name\":\"source.tar.gz\",\"sha256\":\"" + hash + "\",\"size_bytes\":1,\"extra\":0}}",
        "{\"schema_version\":true,\"release_id\":\"" + releaseID + "\",\"commit\":\"" + commit + "\"," + artifact + "}",
        "{\"schema_version\":1,\"release_id\":\"" + releaseID + "\",\"commit\":\"" + commit + "\",\"artifact\":{\"kind\":\"remote_source\",\"name\":\"source.tar.gz\",\"sha256\":\"" + hash + "\",\"size_bytes\":true}}",
        "{\"schema_version\":1.0,\"release_id\":\"" + releaseID + "\",\"commit\":\"" + commit + "\"," + artifact + "}",
        "{\"schema_version\":1,\"release_id\":\"" + releaseID + "\",\"commit\":\"" + commit + "\",\"artifact\":{\"kind\":\"remote_source\",\"name\":\"source.tar.gz\",\"sha256\":\"" + hash + "\",\"size_bytes\":1e0}}",
    ]
    for value in invalidValues {
        expectRemoteSourceError(.invalidMetadata) {
            try RemoteSourceArtifactDescriptor.parse(
                Data(value.utf8),
                expectedReleaseID: releaseID,
                expectedCommit: commit,
                expectedArtifactName: "source.tar.gz"
            )
        }
    }
}

@Test func remoteSourceDescriptorEnforcesBoundsIdentityAndExpectedName() {
    expectRemoteSourceError(.metadataTooLarge) {
        try RemoteSourceArtifactDescriptor.parse(
            Data(repeating: 0x20, count: RemoteSourceArtifactDescriptor.maximumMetadataBytes + 1),
            expectedReleaseID: releaseID,
            expectedCommit: commit,
            expectedArtifactName: "source.tar.gz"
        )
    }

    let oversized = descriptorData(
        name: "source.tar.gz", sha256: String(repeating: "0", count: 64),
        sizeBytes: RemoteSourceArtifactDescriptor.maximumArtifactBytes + 1
    )
    expectRemoteSourceError(.artifactTooLarge) {
        try RemoteSourceArtifactDescriptor.parse(
            oversized, expectedReleaseID: releaseID, expectedCommit: commit,
            expectedArtifactName: "source.tar.gz"
        )
    }

    let valid = descriptorData(name: "source.tar.gz", sha256: String(repeating: "0", count: 64), sizeBytes: 1)
    expectRemoteSourceError(.identityMismatch) {
        try RemoteSourceArtifactDescriptor.parse(
            valid, expectedReleaseID: "20260905123457", expectedCommit: commit,
            expectedArtifactName: "source.tar.gz"
        )
    }
    expectRemoteSourceError(.identityMismatch) {
        try RemoteSourceArtifactDescriptor.parse(
            valid, expectedReleaseID: releaseID, expectedCommit: String(repeating: "b", count: 40),
            expectedArtifactName: "source.tar.gz"
        )
    }
    expectRemoteSourceError(.unexpectedArtifactName) {
        try RemoteSourceArtifactDescriptor.parse(
            valid, expectedReleaseID: releaseID, expectedCommit: commit,
            expectedArtifactName: "different.tar.gz"
        )
    }
}

@Test func remoteSourceDescriptorRejectsMalformedIdentityAndArtifactFields() {
    let hash = String(repeating: "0", count: 64)
    let invalidValues = [
        descriptorData(releaseID: "20260230120000", name: "source.tar.gz", sha256: hash, sizeBytes: 1),
        descriptorData(releaseID: "20250905120000", name: "source.tar.gz", sha256: hash, sizeBytes: 1),
        descriptorData(commit: String(repeating: "A", count: 40), name: "source.tar.gz", sha256: hash, sizeBytes: 1),
        descriptorData(name: "../source.tar.gz", sha256: hash, sizeBytes: 1),
        descriptorData(name: "source.tar.gz", sha256: String(repeating: "A", count: 64), sizeBytes: 1),
        descriptorData(name: "source.tar.gz", sha256: hash, sizeBytes: 0),
    ]
    for value in invalidValues {
        expectRemoteSourceError(.invalidMetadata) {
            try RemoteSourceArtifactDescriptor.parse(
                value, expectedReleaseID: releaseID, expectedCommit: commit,
                expectedArtifactName: "source.tar.gz"
            )
        }
    }
}

@Test func remoteSourceVerificationRejectsSizeAndHashMismatches() throws {
    try withTemporaryDirectory { directory in
        let data = Data("trusted source".utf8)
        let name = "source.tar.gz"
        let url = directory.appendingPathComponent(name)
        try data.write(to: url)

        let wrongSize = try RemoteSourceArtifactDescriptor.parse(
            descriptorData(name: name, sha256: sha256(data), sizeBytes: UInt64(data.count + 1)),
            expectedReleaseID: releaseID, expectedCommit: commit, expectedArtifactName: name
        )
        expectRemoteSourceError(.artifactSizeMismatch) { try wrongSize.verifyArtifact(at: url) }

        let wrongHash = try RemoteSourceArtifactDescriptor.parse(
            descriptorData(name: name, sha256: String(repeating: "0", count: 64), sizeBytes: UInt64(data.count)),
            expectedReleaseID: releaseID, expectedCommit: commit, expectedArtifactName: name
        )
        expectRemoteSourceError(.artifactHashMismatch) { try wrongHash.verifyArtifact(at: url) }
    }
}

@Test func remoteSourceVerificationRejectsSymlinksDirectoriesFIFOsAndWrongPaths() throws {
    try withTemporaryDirectory { directory in
        let data = Data("source".utf8)
        let descriptor = try parseDescriptor(name: "source.tar.gz", data: data)
        let regular = directory.appendingPathComponent("regular.tar.gz")
        let symlink = directory.appendingPathComponent("source.tar.gz")
        try data.write(to: regular)
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: regular)
        expectRemoteSourceError(.unsafeArtifact) { try descriptor.verifyArtifact(at: symlink) }

        try FileManager.default.removeItem(at: symlink)
        try FileManager.default.createDirectory(at: symlink, withIntermediateDirectories: false)
        expectRemoteSourceError(.unsafeArtifact) { try descriptor.verifyArtifact(at: symlink) }

        try FileManager.default.removeItem(at: symlink)
        let fifoResult = symlink.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return Darwin.mkfifo(path, 0o600)
        }
        #expect(fifoResult == 0)
        expectRemoteSourceError(.unsafeArtifact) { try descriptor.verifyArtifact(at: symlink) }

        expectRemoteSourceError(.unexpectedArtifactName) { try descriptor.verifyArtifact(at: regular) }
    }
}

@Test func verifiedRemoteSourceKeepsTheHashedFileDescriptorAfterPathSubstitution() throws {
    try withTemporaryDirectory { directory in
        let original = Data("verified original".utf8)
        let replacement = Data("unverified replacement".utf8)
        let name = "source.tar.gz"
        let url = directory.appendingPathComponent(name)
        let moved = directory.appendingPathComponent("moved.tar.gz")
        try original.write(to: url)
        let descriptor = try parseDescriptor(name: name, data: original)
        let verified = try descriptor.verifyArtifact(at: url)

        try FileManager.default.moveItem(at: url, to: moved)
        try replacement.write(to: url)

        #expect(try verified.withFileDescriptor(readAll) == original)
        #expect(try Data(contentsOf: url) == replacement)
    }
}

private func parseDescriptor(name: String, data: Data) throws -> RemoteSourceArtifactDescriptor {
    try RemoteSourceArtifactDescriptor.parse(
        descriptorData(name: name, sha256: sha256(data), sizeBytes: UInt64(data.count)),
        expectedReleaseID: releaseID, expectedCommit: commit, expectedArtifactName: name
    )
}

@Test func bundledRemoteSourceUsesTheMacsExactReleaseIdentity() throws {
    try withTemporaryDirectory { directory in
        let identity = ReleaseIdentity(
            schemaVersion: 1, releaseID: "20260906160000",
            commit: String(repeating: "a", count: 40)
        )
        let archive = directory.appendingPathComponent("syn-remote-source-\(identity.releaseID).tar.gz")
        let bytes = Data("verified bundled source".utf8)
        try bytes.write(to: archive)
        let digest = Data(SHA256.hash(data: bytes)).map { String(format: "%02x", $0) }.joined()
        let metadata = try JSONSerialization.data(withJSONObject: [
            "schema_version": 1,
            "release_id": identity.releaseID,
            "commit": identity.commit,
            "artifact": [
                "kind": "remote_source", "name": archive.lastPathComponent,
                "sha256": digest, "size_bytes": bytes.count,
            ],
        ])
        let verified = try BundledRemoteSource.verify(metadata: metadata, archive: archive, identity: identity)
        #expect(verified.descriptor.releaseID == identity.releaseID)
        #expect(throws: RemoteSourceArtifactError.identityMismatch) {
            try BundledRemoteSource.verify(
                metadata: metadata, archive: archive,
                identity: .init(schemaVersion: 1, releaseID: identity.releaseID,
                                commit: String(repeating: "b", count: 40))
            )
        }
    }
}

@Test func verifiedSourceCreatesAnExactPrivateTransferCopyAndCleansIt() throws {
    try withTemporaryDirectory { directory in
        let name = "syn-remote-source-20260906160000.tar.gz"
        let source = directory.appendingPathComponent(name)
        let bytes = Data((0..<100_000).map { UInt8($0 % 251) })
        try bytes.write(to: source)
        let descriptor = try parseDescriptor(name: name, data: bytes)
        let staged = try descriptor.verifyArtifact(at: source).makePrivateTransferCopy()
        #expect(try Data(contentsOf: staged.url) == bytes)
        let attributes = try FileManager.default.attributesOfItem(atPath: staged.url.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.uint16Value == 0o600)
        let stagedURL = staged.url
        staged.remove()
        #expect(!FileManager.default.fileExists(atPath: stagedURL.path))
        staged.remove()
    }
}

private func descriptorData(
    releaseID descriptorReleaseID: String = releaseID,
    commit descriptorCommit: String = commit,
    name: String,
    sha256: String,
    sizeBytes: UInt64
) -> Data {
    Data("""
    {"schema_version":1,"release_id":"\(descriptorReleaseID)","commit":"\(descriptorCommit)","artifact":{"kind":"remote_source","name":"\(name)","sha256":"\(sha256)","size_bytes":\(sizeBytes)}}
    """.utf8)
}

private func sha256(_ data: Data) -> String {
    Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
}

private func readAll(_ descriptor: Int32) throws -> Data {
    var value = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        if count < 0 {
            if errno == EINTR { continue }
            throw RemoteSourceArtifactError.fileOperationFailed(operation: "test read", code: errno)
        }
        if count == 0 { return value }
        value.append(contentsOf: buffer.prefix(Int(count)))
    }
}

private func expectRemoteSourceError<T>(
    _ expected: RemoteSourceArtifactError,
    _ operation: () throws -> T
) {
    do {
        _ = try operation()
        Issue.record("Expected \(expected)")
    } catch let error as RemoteSourceArtifactError {
        #expect(error == expected)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

private func withTemporaryDirectory(_ operation: (URL) throws -> Void) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("syn-remote-source-test-\(UUID())")
    try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: directory) }
    try operation(directory)
}
