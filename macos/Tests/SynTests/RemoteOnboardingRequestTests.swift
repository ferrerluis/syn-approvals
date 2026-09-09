import CryptoKit
import Foundation
import Testing
@testable import Syn

@Test func onboardingRequestBindsReleaseMachineIdentitiesAndSource() throws {
    let source = RemoteSourceArtifactDescriptor(
        releaseID: "20260906190000",
        commit: String(repeating: "a", count: 40),
        artifact: .init(
            name: "source.tar.gz", sha256: String(repeating: "b", count: 64), sizeBytes: 123
        )
    )
    let helper = helperDescriptor(releaseID: source.releaseID, commit: source.commit)
    let request = try RemoteOnboardingRequest.make(
        settings: .init(hostname: "ssh-alias", username: "developer", port: 2222),
        resolvedHostname: "remote.example", listenIP: "192.168.2.10",
        displayName: "Build machine", targetID: "remote_machine",
        approvalPublicKey: Data([4] + Array(repeating: 1, count: 64)),
        denialPublicKey: Data([4] + Array(repeating: 2, count: 64)),
        clientCertificatePEM: Data("certificate".utf8), source: source, helper: helper,
        randomBytes: { Data(0..<16) }
    )
    #expect(request.operationID == "000102030405060708090a0b0c0d0e0f")
    #expect(request.hostname == "remote.example")
    #expect(request.managedUser == "developer")
    #expect(request.sourceSHA256 == source.artifact.sha256)
    #expect(request.helperSHA256 == helper.artifact.sha256)
    #expect(request.clientIdentityLabel == "Syn remote_machine transport")
    let encoded = try request.encoded()
    #expect(encoded.count < 64 * 1024)
    #expect(try JSONDecoder().decode(RemoteOnboardingRequest.self, from: encoded) == request)

    let staged = try StagedOnboardingRequest(request)
    let path = staged.url
    #expect(staged.sha256 == Data(SHA256.hash(data: encoded)).hex)
    #expect(try Data(contentsOf: path) == encoded)
    staged.remove()
    #expect(!FileManager.default.fileExists(atPath: path.path))
}

@Test func onboardingRequestRejectsShellFieldsNonIPAndWeakIdentityData() {
    let source = RemoteSourceArtifactDescriptor(
        releaseID: "20260906190000", commit: String(repeating: "a", count: 40),
        artifact: .init(
            name: "source.tar.gz", sha256: String(repeating: "b", count: 64), sizeBytes: 1
        )
    )
    for hostname in ["bad;command", "bad host", "$(bad)"] {
        #expect(throws: SynProtocolError.self) {
            try makeRequest(source: source, resolvedHostname: hostname, listenIP: "192.168.2.10")
        }
    }
    #expect(throws: SynProtocolError.self) {
        try makeRequest(source: source, resolvedHostname: "pi", listenIP: "not-an-ip")
    }
}

private func makeRequest(
    source: RemoteSourceArtifactDescriptor,
    resolvedHostname: String,
    listenIP: String
) throws -> RemoteOnboardingRequest {
    try RemoteOnboardingRequest.make(
        settings: .init(hostname: "pi", username: "developer", port: nil),
        resolvedHostname: resolvedHostname, listenIP: listenIP,
        displayName: "Remote", targetID: "remote",
        approvalPublicKey: Data(repeating: 1, count: 65),
        denialPublicKey: Data(repeating: 2, count: 65),
        clientCertificatePEM: Data([1]), source: source,
        helper: helperDescriptor(releaseID: source.releaseID, commit: source.commit)
    )
}

private func helperDescriptor(releaseID: String, commit: String) -> RemoteHelperArtifactDescriptor {
    RemoteHelperArtifactDescriptor(
        releaseID: releaseID,
        commit: commit,
        artifact: .init(
            name: "synctl-arm64-\(releaseID)",
            sha256: String(repeating: "c", count: 64),
            sizeBytes: 456
        )
    )
}
