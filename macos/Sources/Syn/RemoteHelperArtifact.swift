import Foundation

struct RemoteHelperArtifactDescriptor: Equatable, Sendable {
    static let maximumMetadataBytes = 16 * 1024
    static let maximumArtifactBytes: UInt64 = 128 * 1024 * 1024

    struct Artifact: Equatable, Sendable {
        let name: String
        let sha256: String
        let sizeBytes: UInt64
    }

    let releaseID: String
    let commit: String
    let artifact: Artifact

    static func parse(
        _ data: Data,
        expectedReleaseID: String,
        expectedCommit: String,
        expectedArtifactName: String
    ) throws -> Self {
        guard !data.isEmpty, data.count <= maximumMetadataBytes else {
            throw RemoteSourceArtifactError.metadataTooLarge
        }
        guard ReleaseIdentity.validID(expectedReleaseID), validCommit(expectedCommit),
              validArtifactName(expectedArtifactName) else {
            throw RemoteSourceArtifactError.invalidMetadata
        }
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw RemoteSourceArtifactError.invalidMetadata
        }
        guard
            let object = value as? [String: Any],
            Set(object.keys) == ["schema_version", "release_id", "commit", "artifact"],
            let schema = object["schema_version"] as? NSNumber,
            integer(schema), schema.intValue == 1,
            let releaseID = object["release_id"] as? String, ReleaseIdentity.validID(releaseID),
            let commit = object["commit"] as? String, validCommit(commit),
            let artifact = object["artifact"] as? [String: Any],
            Set(artifact.keys) == ["kind", "name", "sha256", "size_bytes"],
            artifact["kind"] as? String == "remote_helper",
            let name = artifact["name"] as? String, validArtifactName(name),
            let sha256 = artifact["sha256"] as? String, validSHA256(sha256),
            let size = artifact["size_bytes"] as? NSNumber, integer(size),
            let sizeBytes = UInt64(size.stringValue), sizeBytes > 0
        else {
            throw RemoteSourceArtifactError.invalidMetadata
        }
        guard sizeBytes <= maximumArtifactBytes else {
            throw RemoteSourceArtifactError.artifactTooLarge
        }
        guard releaseID == expectedReleaseID, commit == expectedCommit else {
            throw RemoteSourceArtifactError.identityMismatch
        }
        guard name == expectedArtifactName else {
            throw RemoteSourceArtifactError.unexpectedArtifactName
        }
        return Self(
            releaseID: releaseID,
            commit: commit,
            artifact: .init(name: name, sha256: sha256, sizeBytes: sizeBytes)
        )
    }

    func verifyArtifact(at url: URL) throws -> VerifiedRemoteHelperArtifact {
        let sourceDescriptor = RemoteSourceArtifactDescriptor(
            releaseID: releaseID,
            commit: commit,
            artifact: .init(
                name: artifact.name,
                sha256: artifact.sha256,
                sizeBytes: artifact.sizeBytes
            )
        )
        return VerifiedRemoteHelperArtifact(
            descriptor: self,
            verifiedBytes: try sourceDescriptor.verifyArtifact(at: url)
        )
    }

    private static func integer(_ number: NSNumber) -> Bool {
        CFGetTypeID(number) != CFBooleanGetTypeID()
            && !["f", "d"].contains(String(cString: number.objCType))
    }

    private static func validCommit(_ value: String) -> Bool {
        value.utf8.count == 40 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    private static func validSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    private static func validArtifactName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard value.count == bytes.count, let first = bytes.first,
              asciiAlphaNumeric(first) else { return false }
        return bytes.dropFirst().allSatisfy {
            asciiAlphaNumeric($0) || $0 == 46 || $0 == 95 || $0 == 45
        }
    }

    private static func asciiAlphaNumeric(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
    }
}

final class VerifiedRemoteHelperArtifact: @unchecked Sendable {
    let descriptor: RemoteHelperArtifactDescriptor
    private let verifiedBytes: VerifiedRemoteSourceArtifact

    fileprivate init(
        descriptor: RemoteHelperArtifactDescriptor,
        verifiedBytes: VerifiedRemoteSourceArtifact
    ) {
        self.descriptor = descriptor
        self.verifiedBytes = verifiedBytes
    }

    func makePrivateTransferCopy() throws -> StagedRemoteHelperArtifact {
        StagedRemoteHelperArtifact(
            descriptor: descriptor,
            stagedBytes: try verifiedBytes.makePrivateTransferCopy()
        )
    }
}

final class StagedRemoteHelperArtifact: @unchecked Sendable {
    let descriptor: RemoteHelperArtifactDescriptor
    private let stagedBytes: StagedRemoteSourceArtifact
    var url: URL { stagedBytes.url }

    fileprivate init(
        descriptor: RemoteHelperArtifactDescriptor,
        stagedBytes: StagedRemoteSourceArtifact
    ) {
        self.descriptor = descriptor
        self.stagedBytes = stagedBytes
    }

    func remove() { stagedBytes.remove() }
}

enum BundledRemoteHelper {
    static func current(bundle: Bundle = .main) throws -> VerifiedRemoteHelperArtifact {
        let identity = ReleaseIdentity.current
        guard ReleaseIdentity.validID(identity.releaseID), identity.commit.utf8.count == 40 else {
            throw RemoteSourceArtifactError.invalidMetadata
        }
        let name = "synctl-arm64-\(identity.releaseID)"
        guard let metadataURL = bundle.url(forResource: "remote-helper", withExtension: "json"),
              let binaryURL = bundle.url(forResource: name, withExtension: nil) else {
            throw RemoteSourceArtifactError.invalidMetadata
        }
        return try verify(
            metadata: Data(contentsOf: metadataURL, options: [.mappedIfSafe]),
            binary: binaryURL,
            identity: identity
        )
    }

    static func verify(
        metadata: Data,
        binary: URL,
        identity: ReleaseIdentity
    ) throws -> VerifiedRemoteHelperArtifact {
        let name = "synctl-arm64-\(identity.releaseID)"
        let descriptor = try RemoteHelperArtifactDescriptor.parse(
            metadata,
            expectedReleaseID: identity.releaseID,
            expectedCommit: identity.commit,
            expectedArtifactName: name
        )
        return try descriptor.verifyArtifact(at: binary)
    }
}
