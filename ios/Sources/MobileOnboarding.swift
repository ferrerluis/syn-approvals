import CryptoKit
import Foundation

struct MobileSetupProbe: Decodable, Sendable {
    let protocolVersion: Int
    let managedUser: String
    let deviceID: String
    let allowDevelopment: Bool
    let listenIPs: [String]
    let targetID: String?
    let installedReleaseID: String?
    let installedReleaseCommit: String?
    let installationArmed: Bool?
    func matchesArmedRelease(_ release: ReleaseIdentity) -> Bool {
        installationArmed == true && installedReleaseID == release.releaseID && installedReleaseCommit == release.commit
    }
    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version", managedUser = "managed_user", deviceID = "device_id"
        case allowDevelopment = "allow_development", listenIPs = "listen_ips", targetID = "target_id"
        case installedReleaseID = "installed_release_id", installedReleaseCommit = "installed_release_commit", installationArmed = "installation_armed"
    }
}
private struct MobileEnvelope<T: Decodable>: Decodable { let ok: Bool; let data: T }
private struct MobilePairing: Decodable { let operationID: String; let releaseID: String; let target: TargetRecord
    enum CodingKeys: String, CodingKey { case operationID = "operation_id", releaseID = "release_id", target }
}
private struct MobileTransition: Decodable {
    let operationID: String; let releaseID: String; let approved: Bool; let recoveryArmed: Bool; let phase: String
    enum CodingKeys: String, CodingKey { case operationID = "operation_id", releaseID = "release_id", approved, recoveryArmed = "recovery_armed", phase }
}

/// Native setup consumes only the app's verified matching-release resources.
/// Callers cannot provide a source archive, helper, signing bytes or remote command.
@MainActor
enum MobileOnboarding {
    static func run(client: MobileSSH, host: String, port: Int, user: String, device: String,
                    development: Bool, enrollment: IOSEnrollment,
                    configure: (TargetRecord) throws -> Void, waitForConnection: (String) async throws -> Void, progress: (String) -> Void) async throws {
        let probe = try decode(MobileSetupProbe.self, from: await client.probe())
        guard probe.protocolVersion == 1, probe.managedUser == user, probe.deviceID == device,
              !development || probe.allowDevelopment else { throw SynProtocolError.invalid("Setup authorization does not match this phone and Linux account.") }
        let release = ReleaseIdentity.current
        if probe.matchesArmedRelease(release) {
            progress("Pairing this phone")
            var target = try JSONDecoder().decode(TargetRecord.self, from: await client.enroll(JSONEncoder().encode(enrollment)))
            target.webSocketURL = try directURL(target.webSocketURL, host: host)
            try configure(target)
            try await waitForConnection(target.id)
            progress("Connected to the matching Syn release")
            return
        }
        progress("Verifying bundled release")
        let verifiedSource = try BundledRemoteSource.current()
        let verifiedHelper = try BundledRemoteHelper.current()
        let source = try verifiedSource.makePrivateTransferCopy()
        let helper = try verifiedHelper.makePrivateTransferCopy()
        defer { source.remove(); helper.remove() }
        guard let listen = probe.listenIPs.first(where: { $0.hasPrefix("100.") }) ?? probe.listenIPs.first,
              !listen.contains("%"), !listen.isEmpty else { throw SynProtocolError.invalid("No direct machine address is available.") }
        let targetID = probe.targetID ?? "target_" + UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
        let request = RemoteOnboardingRequest(schemaVersion: 1, approverDeviceID: device, developmentSigner: development,
            operationID: UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: ""),
            releaseID: release.releaseID, releaseCommit: release.commit, managedUser: user,
            targetID: targetID, displayName: host, hostname: host, listenIP: listen,
            clientIdentityLabel: "Syn iOS \(device) transport",
            approvalPublicX963Base64: enrollment.approvalPublicX963Base64,
            denialPublicX963Base64: enrollment.denialPublicX963Base64,
            clientCertificatePEMBase64: Data(enrollment.clientCertificatePEM.utf8).base64EncodedString(),
            sourceSHA256: source.descriptor.artifact.sha256, sourceSizeBytes: source.descriptor.artifact.sizeBytes,
            helperSHA256: helper.descriptor.artifact.sha256, helperSizeBytes: helper.descriptor.artifact.sizeBytes)
        let staged = try StagedOnboardingRequest(request)
        defer { staged.remove() }
        var transitionStarted = false
        do {
            progress("Restoring password sudo before setup")
            _ = try await client.recover()
            progress("Copying verified release")
            try await client.upload(.source, file: source.url, hash: request.sourceSHA256, size: request.sourceSizeBytes)
            try await client.upload(.helper, file: helper.url, hash: request.helperSHA256, size: request.helperSizeBytes)
            let requestSize = UInt64(try request.encoded().count)
            try await client.upload(.request, file: staged.url, hash: staged.sha256, size: requestSize)
            try await client.retain(operation: request.operationID, hash: request.helperSHA256, size: request.helperSizeBytes)
            try await client.prepare(operation: request.operationID, requestHash: staged.sha256, sourceHash: request.sourceSHA256)
            transitionStarted = true
            _ = try await client.phase(.cleanup, operation: request.operationID)
            progress("Building the matching release on the machine")
            _ = try await client.phase(.build, operation: request.operationID)
            progress("Configuring the direct approval connection")
            let pairing = try decode(MobilePairing.self, from: await client.phase(.configure, operation: request.operationID))
            guard pairing.operationID == request.operationID, pairing.releaseID == release.releaseID else {
                throw SynProtocolError.invalid("The machine configured a different release.")
            }
            var target = pairing.target
            target.webSocketURL = try directURL(target.webSocketURL, host: host)
            target.installedReleaseID = release.releaseID; target.installedReleaseCommit = release.commit
            target.ssh = SSHConnectionSettings(hostname: host, username: user, port: UInt16(port), hostTrustSource: nil)
            try configure(target)
            progress("Connecting before the setup approval test")
            try await waitForConnection(target.id)
            progress("Approve the setup test request in Syn")
            let activated = try decode(MobileTransition.self, from: await client.phase(.activate, operation: request.operationID))
            try verify(activated, operation: request.operationID, release: release.releaseID, phase: "armed_pending_final_approval", armed: true)
            progress("Approve the final verification request in Syn")
            let completed = try decode(MobileTransition.self, from: await client.phase(.complete, operation: request.operationID))
            try verify(completed, operation: request.operationID, release: release.releaseID, phase: "complete", armed: false)
            progress("Setup complete")
        } catch {
            if transitionStarted {
                progress("Restoring local sudo after incomplete setup")
                do { _ = try await client.recover() }
                catch { throw SynProtocolError.invalid("Recovery could not be confirmed. Use the machine’s independent recovery access before retrying.") }
            }
            throw error
        }
    }
    private static func directURL(_ original: URL, host: String) throws -> URL {
        var parts = URLComponents(url: original, resolvingAgainstBaseURL: false)
        guard parts?.scheme == "wss", parts?.user == nil, parts?.password == nil,
              parts?.query == nil, parts?.fragment == nil else { throw SynProtocolError.invalid("Invalid machine connection profile.") }
        parts?.host = host; parts?.port = 41781
        guard let url = parts?.url else { throw SynProtocolError.invalid("Invalid direct machine address.") }
        return url
    }
    private static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let response = try JSONDecoder().decode(MobileEnvelope<T>.self, from: data)
        guard response.ok else { throw SynProtocolError.invalid("Machine setup failed.") }
        return response.data
    }
    private static func verify(_ value: MobileTransition, operation: String, release: String, phase: String, armed: Bool) throws {
        guard value.operationID == operation, value.releaseID == release, value.approved,
              value.phase == phase, value.recoveryArmed == armed else { throw SynProtocolError.invalid("Setup verification did not complete.") }
    }
}
