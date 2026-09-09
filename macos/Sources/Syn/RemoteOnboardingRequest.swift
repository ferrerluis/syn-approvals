import CryptoKit
import Darwin
import Foundation
import Security

struct RemoteOnboardingRequest: Codable, Equatable, Sendable {
    let schemaVersion: UInt16
    let operationID: String
    let releaseID: String
    let releaseCommit: String
    let managedUser: String
    let targetID: String
    let displayName: String
    let hostname: String
    let listenIP: String
    let clientIdentityLabel: String
    let approvalPublicX963Base64: String
    let denialPublicX963Base64: String
    let clientCertificatePEMBase64: String
    let sourceSHA256: String
    let sourceSizeBytes: UInt64
    let helperSHA256: String
    let helperSizeBytes: UInt64

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case operationID = "operation_id"
        case releaseID = "release_id"
        case releaseCommit = "release_commit"
        case managedUser = "managed_user"
        case targetID = "target_id"
        case displayName = "display_name"
        case hostname
        case listenIP = "listen_ip"
        case clientIdentityLabel = "client_identity_label"
        case approvalPublicX963Base64 = "approval_public_x963_base64"
        case denialPublicX963Base64 = "denial_public_x963_base64"
        case clientCertificatePEMBase64 = "client_certificate_pem_base64"
        case sourceSHA256 = "source_sha256"
        case sourceSizeBytes = "source_size_bytes"
        case helperSHA256 = "helper_sha256"
        case helperSizeBytes = "helper_size_bytes"
    }

    static func make(
        settings: SSHConnectionSettings,
        resolvedHostname: String,
        listenIP: String,
        displayName: String,
        targetID: String,
        approvalPublicKey: Data,
        denialPublicKey: Data,
        clientCertificatePEM: Data,
        source: RemoteSourceArtifactDescriptor,
        helper: RemoteHelperArtifactDescriptor,
        randomBytes: () throws -> Data = { try secureRandom(count: 16) }
    ) throws -> Self {
        try settings.validate()
        guard validHostname(resolvedHostname), validIPAddress(listenIP), validIdentifier(targetID),
              validDisplayName(displayName), approvalPublicKey.count == 65,
              denialPublicKey.count == 65, approvalPublicKey != denialPublicKey,
              !clientCertificatePEM.isEmpty, clientCertificatePEM.count <= 16 * 1024,
              helper.releaseID == source.releaseID, helper.commit == source.commit else {
            throw SynProtocolError.invalid("The setup identities or network address are invalid.")
        }
        let operation = try randomBytes()
        guard operation.count == 16 else {
            throw SynProtocolError.invalid("Syn could not create a setup operation.")
        }
        return Self(
            schemaVersion: 1,
            operationID: operation.hex,
            releaseID: source.releaseID,
            releaseCommit: source.commit,
            managedUser: settings.username,
            targetID: targetID,
            displayName: displayName,
            hostname: resolvedHostname,
            listenIP: listenIP,
            clientIdentityLabel: "Syn \(targetID) transport",
            approvalPublicX963Base64: approvalPublicKey.base64EncodedString(),
            denialPublicX963Base64: denialPublicKey.base64EncodedString(),
            clientCertificatePEMBase64: clientCertificatePEM.base64EncodedString(),
            sourceSHA256: source.artifact.sha256,
            sourceSizeBytes: source.artifact.sizeBytes,
            helperSHA256: helper.artifact.sha256,
            helperSizeBytes: helper.artifact.sizeBytes
        )
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        guard !data.isEmpty, data.count <= 64 * 1024 else {
            throw SynProtocolError.invalid("The setup request is too large.")
        }
        return data
    }

    private static func secureRandom(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw SynProtocolError.invalid("Syn could not create a setup operation.")
        }
        return bytes
    }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            $0.isASCIIAlphaNumeric || $0 == 45 || $0 == 95
        }
    }

    private static func validDisplayName(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && !value.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
    }

    private static func validHostname(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253, value.first != "-" else { return false }
        return value.utf8.allSatisfy {
            $0.isASCIIAlphaNumeric || [45, 46, 58, 91, 93, 95].contains($0)
        }
    }

    private static func validIPAddress(_ value: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return value.withCString {
            inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1
        }
    }
}

private extension UInt8 {
    var isASCIIAlphaNumeric: Bool {
        (48...57).contains(self) || (65...90).contains(self) || (97...122).contains(self)
    }
}

final class StagedOnboardingRequest: @unchecked Sendable {
    let url: URL
    let sha256: String
    private let directory: URL
    private let lock = NSLock()
    private var removed = false

    init(_ request: RemoteOnboardingRequest) throws {
        let bytes = try request.encoded()
        sha256 = Data(SHA256.hash(data: bytes)).hex
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("syn-request-\(UUID().uuidString)", isDirectory: true)
        url = directory.appendingPathComponent("request.incoming")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            let descriptor = url.withUnsafeFileSystemRepresentation { path -> Int32 in
                guard let path else { return -1 }
                return Darwin.open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            }
            guard descriptor >= 0 else { throw SynProtocolError.invalid("Syn could not stage setup.") }
            defer { Darwin.close(descriptor) }
            try bytes.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(
                        descriptor, buffer.baseAddress!.advanced(by: offset), buffer.count - offset
                    )
                    if count < 0 {
                        if errno == EINTR { continue }
                        throw SynProtocolError.invalid("Syn could not stage setup.")
                    }
                    offset += count
                }
            }
            guard Darwin.fsync(descriptor) == 0 else {
                throw SynProtocolError.invalid("Syn could not stage setup.")
            }
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    deinit { remove() }

    func remove() {
        lock.lock()
        defer { lock.unlock() }
        guard !removed else { return }
        try? FileManager.default.removeItem(at: directory)
        removed = true
    }
}
