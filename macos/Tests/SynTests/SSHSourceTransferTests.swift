import CryptoKit
import Foundation
import Testing
@testable import Syn

private actor TransferSSHFixture: SSHSetupRunning {
    var operations: [SSHSetupOperation] = []
    let digest: String
    let helperDigest: String
    let requestDigest: String
    init(digest: String, helperDigest: String, requestDigest: String) {
        self.digest = digest
        self.helperDigest = helperDigest
        self.requestDigest = requestDigest
    }
    func run(settings: SSHConnectionSettings, operation: SSHSetupOperation) async throws -> SSHProbeOutput {
        operations.append(operation)
        switch operation {
        case .prepareSourceTransfer: return .init(status: 0, stdout: Data())
        case .sourceDigest:
            return .init(status: 0, stdout: Data("\(digest)  .cache/syn-setup/source.incoming\n".utf8))
        case .helperDigest:
            return .init(status: 0, stdout: Data("\(helperDigest)  .cache/syn-setup/synctl-bootstrap.incoming\n".utf8))
        case .requestDigest:
            return .init(status: 0, stdout: Data("\(requestDigest)  .cache/syn-setup/request.incoming\n".utf8))
        }
    }
}

private actor TransferSCPFixture: SCPProcessRunning {
    var arguments: [[String]] = []
    func copy(arguments: [String]) async throws -> SSHProbeOutput {
        self.arguments.append(arguments)
        return .init(status: 0, stdout: Data())
    }
}

@Test func sourceTransferUsesFixedOperationsAndChecksRemoteBytes() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("syn-transfer-fixture-\(UUID())")
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    let releaseID = "20260906160000"
    let name = "syn-remote-source-\(releaseID).tar.gz"
    let data = Data("source bytes".utf8)
    let sourceURL = directory.appendingPathComponent(name)
    try data.write(to: sourceURL)
    let digest = Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
    let metadata = try JSONSerialization.data(withJSONObject: [
        "schema_version": 1, "release_id": releaseID, "commit": String(repeating: "a", count: 40),
        "artifact": ["kind": "remote_source", "name": name, "sha256": digest, "size_bytes": data.count],
    ])
    let descriptor = try RemoteSourceArtifactDescriptor.parse(
        metadata, expectedReleaseID: releaseID, expectedCommit: String(repeating: "a", count: 40),
        expectedArtifactName: name
    )
    let staged = try descriptor.verifyArtifact(at: sourceURL).makePrivateTransferCopy()
    defer { staged.remove() }
    let helperData = Data("helper bytes".utf8)
    let helperName = "synctl-arm64-\(releaseID)"
    let helperURL = directory.appendingPathComponent(helperName)
    try helperData.write(to: helperURL)
    let helperDigest = Data(SHA256.hash(data: helperData)).hex
    let helperDescriptor = RemoteHelperArtifactDescriptor(
        releaseID: releaseID,
        commit: String(repeating: "a", count: 40),
        artifact: .init(name: helperName, sha256: helperDigest, sizeBytes: UInt64(helperData.count))
    )
    let stagedHelper = try helperDescriptor.verifyArtifact(at: helperURL).makePrivateTransferCopy()
    defer { stagedHelper.remove() }
    let request = try StagedOnboardingRequest(
        try onboardingRequest(source: descriptor, helper: helperDescriptor)
    )
    defer { request.remove() }
    let ssh = TransferSSHFixture(
        digest: digest, helperDigest: helperDigest, requestDigest: request.sha256
    )
    let scp = TransferSCPFixture()
    try await SSHSourceTransfer(ssh: ssh, scp: scp).transfer(
        staged, helper: stagedHelper, request: request,
        to: .init(hostname: "pi", username: "developer", port: nil)
    )
    #expect(await ssh.operations == [
        .prepareSourceTransfer, .sourceDigest, .helperDigest, .requestDigest,
    ])
    let calls = await scp.arguments
    #expect(calls.count == 3)
    #expect(calls[0].last == "developer@pi:.cache/syn-setup/source.incoming")
    #expect(calls[1].last == "developer@pi:.cache/syn-setup/synctl-bootstrap.incoming")
    #expect(calls[2].last == "developer@pi:.cache/syn-setup/request.incoming")

    let wrong = TransferSSHFixture(
        digest: String(repeating: "0", count: 64),
        helperDigest: helperDigest, requestDigest: request.sha256
    )
    await #expect(throws: RemoteSourceArtifactError.artifactHashMismatch) {
        try await SSHSourceTransfer(ssh: wrong, scp: TransferSCPFixture()).transfer(
            staged, helper: stagedHelper, request: request,
            to: .init(hostname: "pi", username: "developer", port: nil)
        )
    }
}

private func onboardingRequest(
    source: RemoteSourceArtifactDescriptor,
    helper: RemoteHelperArtifactDescriptor
) throws -> RemoteOnboardingRequest {
    try RemoteOnboardingRequest.make(
        settings: .init(hostname: "pi", username: "developer", port: nil),
        resolvedHostname: "pi.local", listenIP: "192.168.2.10",
        displayName: "Remote machine", targetID: "remote_machine",
        approvalPublicKey: Data([4] + Array(repeating: 1, count: 64)),
        denialPublicKey: Data([4] + Array(repeating: 2, count: 64)),
        clientCertificatePEM: Data("certificate".utf8), source: source, helper: helper,
        randomBytes: { Data(repeating: 3, count: 16) }
    )
}
