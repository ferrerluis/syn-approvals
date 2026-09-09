import CryptoKit
import Foundation
import Testing
@testable import Syn

@Test func bundledRemoteHelperBindsIdentityKindAndExactBytes() throws {
    try withHelperDirectory { directory in
        let identity = ReleaseIdentity(
            schemaVersion: 1,
            releaseID: "20260908190000",
            commit: String(repeating: "a", count: 40)
        )
        let name = "synctl-arm64-\(identity.releaseID)"
        let binary = directory.appendingPathComponent(name)
        let bytes = Data("ARM64 helper fixture".utf8)
        try bytes.write(to: binary)
        let digest = Data(SHA256.hash(data: bytes)).map { String(format: "%02x", $0) }.joined()
        let metadata = try JSONSerialization.data(withJSONObject: [
            "schema_version": 1,
            "release_id": identity.releaseID,
            "commit": identity.commit,
            "artifact": [
                "kind": "remote_helper",
                "name": name,
                "sha256": digest,
                "size_bytes": bytes.count,
            ],
        ])

        let verified = try BundledRemoteHelper.verify(
            metadata: metadata, binary: binary, identity: identity
        )
        #expect(verified.descriptor.artifact.sha256 == digest)
        let staged = try verified.makePrivateTransferCopy()
        defer { staged.remove() }
        #expect(try Data(contentsOf: staged.url) == bytes)
        #expect((try FileManager.default.attributesOfItem(atPath: staged.url.path)[.posixPermissions]
            as? NSNumber)?.uint16Value == 0o600)

        var wrongKind = try #require(JSONSerialization.jsonObject(with: metadata) as? [String: Any])
        var artifact = try #require(wrongKind["artifact"] as? [String: Any])
        artifact["kind"] = "remote_source"
        wrongKind["artifact"] = artifact
        #expect(throws: RemoteSourceArtifactError.invalidMetadata) {
            try BundledRemoteHelper.verify(
                metadata: JSONSerialization.data(withJSONObject: wrongKind),
                binary: binary,
                identity: identity
            )
        }
    }
}

@Test func remoteHelperRejectsOversizeWrongReleaseAndTampering() throws {
    let releaseID = "20260908190000"
    let commit = String(repeating: "b", count: 40)
    let name = "synctl-arm64-\(releaseID)"
    let hash = String(repeating: "0", count: 64)
    let oversized = Data("""
    {"schema_version":1,"release_id":"\(releaseID)","commit":"\(commit)","artifact":{"kind":"remote_helper","name":"\(name)","sha256":"\(hash)","size_bytes":\(RemoteHelperArtifactDescriptor.maximumArtifactBytes + 1)}}
    """.utf8)
    #expect(throws: RemoteSourceArtifactError.artifactTooLarge) {
        try RemoteHelperArtifactDescriptor.parse(
            oversized,
            expectedReleaseID: releaseID,
            expectedCommit: commit,
            expectedArtifactName: name
        )
    }

    try withHelperDirectory { directory in
        let binary = directory.appendingPathComponent(name)
        try Data("different".utf8).write(to: binary)
        let descriptor = RemoteHelperArtifactDescriptor(
            releaseID: releaseID,
            commit: commit,
            artifact: .init(name: name, sha256: hash, sizeBytes: 9)
        )
        #expect(throws: RemoteSourceArtifactError.artifactHashMismatch) {
            try descriptor.verifyArtifact(at: binary)
        }
    }
}

private func withHelperDirectory(_ operation: (URL) throws -> Void) throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("syn-remote-helper-test-\(UUID())", isDirectory: true)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: directory) }
    try operation(directory)
}
