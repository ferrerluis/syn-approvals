import Foundation

/// Release builds carry the exact source archive they are allowed to install.
/// Setup borrows the verified descriptor rather than reopening a user-selected path.
enum BundledRemoteSource {
    static func current(bundle: Bundle = .main) throws -> VerifiedRemoteSourceArtifact {
        let identity = ReleaseIdentity.current
        guard ReleaseIdentity.validID(identity.releaseID),
              identity.commit.utf8.count == 40 else {
            throw RemoteSourceArtifactError.invalidMetadata
        }
        let name = "syn-remote-source-\(identity.releaseID).tar.gz"
        guard let metadataURL = bundle.url(forResource: "remote-source", withExtension: "json"),
              let archiveURL = bundle.url(forResource: name, withExtension: nil) else {
            throw RemoteSourceArtifactError.invalidMetadata
        }
        return try verify(
            metadata: Data(contentsOf: metadataURL, options: [.mappedIfSafe]),
            archive: archiveURL,
            identity: identity
        )
    }

    static func verify(
        metadata: Data,
        archive: URL,
        identity: ReleaseIdentity
    ) throws -> VerifiedRemoteSourceArtifact {
        let name = "syn-remote-source-\(identity.releaseID).tar.gz"
        let descriptor = try RemoteSourceArtifactDescriptor.parse(
            metadata,
            expectedReleaseID: identity.releaseID,
            expectedCommit: identity.commit,
            expectedArtifactName: name
        )
        return try descriptor.verifyArtifact(at: archive)
    }
}
