import CryptoKit
import Darwin
import Foundation
#if canImport(Syn)
@testable import Syn
#endif

/// Test-target-only groundwork for the hybrid E2E harness. This file is not a
/// dependency of the shipping `Syn` executable.
enum E2ETestHarnessError: Error, Equatable {
    case invalidConfiguration(String)
    case requestMismatch
    case grantConsumed
    case simulatedCancellation
}

enum E2ETestDecision: String, Codable, Sendable {
    case approve
    case deny
    case cancelAuthentication
}

struct E2ETestRequestGrant: Codable, Equatable, Sendable {
    static let schemaVersion = 1

    let schemaVersion: Int
    let scenarioID: String
    let profileID: String
    let decision: E2ETestDecision
    let expiresAt: Date
    let requestIssuedAtMilliseconds: Int64
    let requestExpiresAtMilliseconds: Int64
    let maxUses: Int
    let payloadHash: Data
    let requestID: Data
    let nonce: Data
    let targetID: String
    let releaseID: String
    let releaseCommit: String
    let invokingUID: UInt32
    let invokingUser: String
    let runAsUID: UInt32
    let runAsUser: String
    let runAsGroup: String
    let workingDirectory: Data
    let executable: Data
    let arguments: [Data]
    let environmentNames: [String]
    let environmentDigest: Data
    let riskMarkers: [String]

    init(
        profileID: String,
        scenarioID: String = "local-unit-scenario",
        decision: E2ETestDecision,
        expiresAt: Date,
        request: VerifiedApprovalRequest
    ) {
        self.schemaVersion = Self.schemaVersion
        self.scenarioID = scenarioID
        self.profileID = profileID
        self.decision = decision
        self.expiresAt = expiresAt
        requestIssuedAtMilliseconds = Int64(request.issuedAt.timeIntervalSince1970 * 1_000)
        requestExpiresAtMilliseconds = Int64(request.expiresAt.timeIntervalSince1970 * 1_000)
        maxUses = 1
        payloadHash = request.payloadHash
        requestID = request.requestID
        nonce = request.nonce
        targetID = request.targetID
        releaseID = request.releaseID
        releaseCommit = request.releaseCommit
        invokingUID = request.invokingUID
        invokingUser = request.invokingUser
        runAsUID = request.runAsUID
        runAsUser = request.runAsUser
        runAsGroup = request.runAsGroup
        workingDirectory = request.workingDirectory
        executable = request.executable
        arguments = request.arguments
        environmentNames = request.environmentNames
        environmentDigest = request.environmentDigest
        riskMarkers = request.riskMarkers
    }

    func validate(now: Date = .now) throws {
        guard schemaVersion == Self.schemaVersion else {
            throw E2ETestHarnessError.invalidConfiguration("unsupported schema")
        }
        guard profileID.hasPrefix("org.syn-approvals.SynE2E."),
              profileID != "org.syn-approvals.Syn",
              !profileID.contains("*"), !profileID.contains("?") else {
            throw E2ETestHarnessError.invalidConfiguration("profile is not isolated")
        }
        guard !scenarioID.isEmpty, !scenarioID.contains("*"), !scenarioID.contains("?") else {
            throw E2ETestHarnessError.invalidConfiguration("scenario identifier is not exact")
        }
        guard maxUses == 1 else {
            throw E2ETestHarnessError.invalidConfiguration("grant must be one-use")
        }
        guard expiresAt > now else { throw E2ETestHarnessError.invalidConfiguration("grant expired") }
        guard Date(timeIntervalSince1970: Double(requestExpiresAtMilliseconds) / 1_000) > now,
              requestIssuedAtMilliseconds < requestExpiresAtMilliseconds else {
            throw E2ETestHarnessError.invalidConfiguration("request expired")
        }
        guard payloadHash.count == 32, requestID.count == 16, nonce.count == 32,
              environmentDigest.count == 32, !targetID.isEmpty,
              !executable.isEmpty, !releaseID.isEmpty, !releaseCommit.isEmpty else {
            throw E2ETestHarnessError.invalidConfiguration("grant is incomplete")
        }
    }

    func matches(_ request: VerifiedApprovalRequest) -> Bool {
        payloadHash == request.payloadHash && requestID == request.requestID && nonce == request.nonce
            && requestIssuedAtMilliseconds == Int64(request.issuedAt.timeIntervalSince1970 * 1_000)
            && requestExpiresAtMilliseconds == Int64(request.expiresAt.timeIntervalSince1970 * 1_000)
            && targetID == request.targetID && releaseID == request.releaseID
            && releaseCommit == request.releaseCommit && invokingUID == request.invokingUID
            && invokingUser == request.invokingUser && runAsUID == request.runAsUID
            && runAsUser == request.runAsUser && runAsGroup == request.runAsGroup
            && workingDirectory == request.workingDirectory && executable == request.executable
            && arguments == request.arguments && environmentNames == request.environmentNames
            && environmentDigest == request.environmentDigest && riskMarkers == request.riskMarkers
    }
}

/// The Mac app emits this only after production verification has accepted the
/// signed target request. A separate mock-auth process may turn this exact
/// offer into a one-use grant; the offer itself grants no signing authority.
struct E2ETestRequestOffer: Codable, Equatable, Sendable {
    static let schemaVersion = 1
    let schemaVersion: Int
    let profileID: String
    let observedAt: Date
    let request: E2ETestRequestGrant

    init(profileID: String, request: VerifiedApprovalRequest, now: Date = .now) {
        schemaVersion = Self.schemaVersion
        self.profileID = profileID
        observedAt = now
        self.request = E2ETestRequestGrant(
            profileID: profileID, decision: .deny,
            expiresAt: min(request.expiresAt, now.addingTimeInterval(90)), request: request
        )
    }
}

final class E2EGrantInbox: @unchecked Sendable {
    private struct FileIdentity: Equatable { let device: dev_t; let inode: ino_t }
    private let directory: URL
    private let rootDescriptor: Int32
    private let directoryDescriptor: Int32
    private let directoryIdentity: FileIdentity
    private let beforeGrantClaim: (@Sendable () -> Void)?
    private let profileID: String
    private let lock = NSLock()
    private var offerIdentity: FileIdentity?

    init(directory: URL, profileID: String, beforeGrantClaim: (@Sendable () -> Void)? = nil) throws {
        guard profileID.hasPrefix("org.syn-approvals.SynE2E."),
              profileID != "org.syn-approvals.Syn", !profileID.contains("/") else {
            throw E2ETestHarnessError.invalidConfiguration("profile is not isolated")
        }
        let rootFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard rootFD >= 0 else { throw Self.posixError("could not open inbox root") }
        var rootStatus = stat()
        guard fstat(rootFD, &rootStatus) == 0, rootStatus.st_uid == getuid(),
              rootStatus.st_mode & S_IFMT == S_IFDIR, rootStatus.st_mode & 0o777 == 0o700 else {
            close(rootFD)
            throw E2ETestHarnessError.invalidConfiguration("inbox root must be owned and private")
        }
        let name = profileID + ".inbox"
        guard mkdirat(rootFD, name, 0o700) == 0 else {
            close(rootFD); throw Self.posixError("inbox already exists or cannot be created")
        }
        let inboxFD = openat(rootFD, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard inboxFD >= 0 else {
            _ = unlinkat(rootFD, name, AT_REMOVEDIR); close(rootFD)
            throw Self.posixError("could not open private inbox")
        }
        var inboxStatus = stat()
        guard fstat(inboxFD, &inboxStatus) == 0, inboxStatus.st_uid == getuid(),
              inboxStatus.st_mode & S_IFMT == S_IFDIR, inboxStatus.st_mode & 0o777 == 0o700 else {
            close(inboxFD); _ = unlinkat(rootFD, name, AT_REMOVEDIR); close(rootFD)
            throw E2ETestHarnessError.invalidConfiguration("inbox must be owned and private")
        }
        self.directory = directory.appendingPathComponent(name, isDirectory: true)
        rootDescriptor = rootFD
        directoryDescriptor = inboxFD
        directoryIdentity = FileIdentity(device: inboxStatus.st_dev, inode: inboxStatus.st_ino)
        self.beforeGrantClaim = beforeGrantClaim
        self.profileID = profileID
    }

    deinit { close(directoryDescriptor); close(rootDescriptor) }

    var offerURL: URL { directory.appendingPathComponent("offer.json") }
    var grantURL: URL { directory.appendingPathComponent("grant.json") }

    func publish(_ request: VerifiedApprovalRequest) throws {
        try lock.withLock {
            let offer = E2ETestRequestOffer(profileID: profileID, request: request)
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(offer)
            let fd = openat(directoryDescriptor, "offer.json", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw Self.posixError("could not create request offer") }
            defer { close(fd) }
            try Self.writeAll(data, to: fd)
            guard fsync(fd) == 0 else { throw Self.posixError("could not sync request offer") }
            var status = stat()
            guard fstat(fd, &status) == 0, status.st_uid == getuid(),
                  status.st_mode & S_IFMT == S_IFREG, status.st_mode & 0o777 == 0o600 else {
                throw E2ETestHarnessError.invalidConfiguration("offer is not an owned regular file")
            }
            offerIdentity = FileIdentity(device: status.st_dev, inode: status.st_ino)
        }
    }

    func consumeGrant(for request: VerifiedApprovalRequest, now: Date = .now) throws -> E2ETestRequestGrant {
        try lock.withLock {
            let fd = openat(directoryDescriptor, "grant.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            guard fd >= 0 else { throw Self.posixError("could not open grant") }
            defer { close(fd) }
            var original = stat()
            guard fstat(fd, &original) == 0, original.st_uid == getuid(),
                  original.st_mode & S_IFMT == S_IFREG, original.st_mode & 0o777 == 0o600,
                  original.st_size >= 0, original.st_size <= 64 * 1024 else {
                throw E2ETestHarnessError.invalidConfiguration("grant must be an owned private regular file")
            }
            let identity = FileIdentity(device: original.st_dev, inode: original.st_ino)
            let spentName = ".spent-\(UUID().uuidString)"
            beforeGrantClaim?()
            guard renameatx_np(directoryDescriptor, "grant.json", directoryDescriptor, spentName, UInt32(RENAME_EXCL)) == 0 else {
                throw Self.posixError("could not atomically claim grant")
            }
            var claimed = stat()
            guard fstatat(directoryDescriptor, spentName, &claimed, AT_SYMLINK_NOFOLLOW) == 0,
                  FileIdentity(device: claimed.st_dev, inode: claimed.st_ino) == identity else {
                _ = renameatx_np(directoryDescriptor, spentName, directoryDescriptor, "grant.json", UInt32(RENAME_EXCL))
                throw E2ETestHarnessError.invalidConfiguration("claimed grant was replaced")
            }
            defer { _ = unlinkat(directoryDescriptor, spentName, 0) }
            let data = try Self.readAll(from: fd, limit: 64 * 1024)
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            let grant = try decoder.decode(E2ETestRequestGrant.self, from: data)
            try grant.validate(now: now)
            guard grant.profileID == profileID, grant.matches(request) else {
                throw E2ETestHarnessError.requestMismatch
            }
            return grant
        }
    }

    func cleanupOwnedFiles() {
        lock.withLock {
            if let offerIdentity {
                var status = stat()
                if fstatat(directoryDescriptor, "offer.json", &status, AT_SYMLINK_NOFOLLOW) == 0,
                   FileIdentity(device: status.st_dev, inode: status.st_ino) == offerIdentity,
                   status.st_uid == getuid(), status.st_mode & S_IFMT == S_IFREG,
                   status.st_mode & 0o777 == 0o600,
                   unlinkat(directoryDescriptor, "offer.json", 0) == 0 {
                    self.offerIdentity = nil
                }
            }
            var current = stat()
            guard fstatat(rootDescriptor, profileID + ".inbox", &current, AT_SYMLINK_NOFOLLOW) == 0,
                  FileIdentity(device: current.st_dev, inode: current.st_ino) == directoryIdentity else { return }
            // rmdir succeeds only when the coordinator left no grant or foreign
            // entry, so unexpected data is preserved without enumerating it.
            _ = unlinkat(rootDescriptor, profileID + ".inbox", AT_REMOVEDIR)
        }
    }

    private static func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw posixError("could not write request offer") }
                offset += count
            }
        }
    }

    private static func readAll(from fd: Int32, limit: Int) throws -> Data {
        var result = Data(); var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw posixError("could not read grant") }
            if count == 0 { return result }
            guard result.count + count <= limit else {
                throw E2ETestHarnessError.invalidConfiguration("grant is too large")
            }
            result.append(contentsOf: buffer.prefix(count))
        }
    }

    private static func posixError(_ message: String) -> E2ETestHarnessError {
        .invalidConfiguration("\(message) (errno \(errno))")
    }
}

final class E2EDisposableKeyStore: @unchecked Sendable {
    private struct ResidualRecord: Codable {
        let schemaVersion: Int
        let profileID: String
        let approvalPublicKeyID: Data
        let denialPublicKeyID: Data
    }
    struct PublicIdentities: Codable, Equatable, Sendable {
        let profileID: String
        let approvalPublicKey: Data
        let approvalPublicKeyID: Data
        let denialPublicKey: Data
        let denialPublicKeyID: Data
    }

    private struct ObjectIdentity: Equatable {
        let device: dev_t
        let inode: ino_t
        init(_ value: stat) { device = value.st_dev; inode = value.st_ino }
    }

    private let rootDescriptor: Int32
    private let directoryDescriptor: Int32
    private let directoryIdentity: ObjectIdentity
    private let keyIdentities: [String: ObjectIdentity]
    private let profileID: String
    private let approval: P256.Signing.PrivateKey
    private let denial: P256.Signing.PrivateKey

    init(
        rootDirectory: URL, profileID: String, failWriteAfterBytes: Int? = nil,
        failInitialIdentityCheck: Bool = false
    ) throws {
        guard profileID.hasPrefix("org.syn-approvals.SynE2E."), profileID != "org.syn-approvals.Syn",
              !profileID.contains("/"), profileID != ".", profileID != ".." else {
            throw E2ETestHarnessError.invalidConfiguration("profile is not isolated")
        }
        let rootFD = open(rootDirectory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard rootFD >= 0 else { throw Self.posixError("could not open harness root") }
        var rootStatus = stat()
        guard fstat(rootFD, &rootStatus) == 0, rootStatus.st_uid == getuid() else {
            close(rootFD)
            throw E2ETestHarnessError.invalidConfiguration("harness root has the wrong owner")
        }
        guard mkdirat(rootFD, profileID, 0o700) == 0 else {
            close(rootFD)
            throw Self.posixError("profile store already exists or cannot be created")
        }
        let directoryFD = openat(rootFD, profileID, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else {
            _ = unlinkat(rootFD, profileID, AT_REMOVEDIR)
            close(rootFD)
            throw Self.posixError("could not open profile store")
        }
        var directoryStatus = stat()
        guard fstat(directoryFD, &directoryStatus) == 0, directoryStatus.st_uid == getuid(),
              directoryStatus.st_mode & S_IFMT == S_IFDIR else {
            close(directoryFD); _ = unlinkat(rootFD, profileID, AT_REMOVEDIR); close(rootFD)
            throw E2ETestHarnessError.invalidConfiguration("profile store is not owned")
        }
        rootDescriptor = rootFD
        directoryDescriptor = directoryFD
        directoryIdentity = ObjectIdentity(directoryStatus)
        self.profileID = profileID
        approval = P256.Signing.PrivateKey()
        denial = P256.Signing.PrivateKey()
        var created: [String: ObjectIdentity] = [:]
        do {
            let record = ResidualRecord(
                schemaVersion: 1, profileID: profileID,
                approvalPublicKeyID: Data(SHA256.hash(data: approval.publicKey.x963Representation)),
                denialPublicKeyID: Data(SHA256.hash(data: denial.publicKey.x963Representation))
            )
            created["profile-record.json"] = try Self.writeNew(
                JSONEncoder().encode(record), named: "profile-record.json", in: directoryFD,
                failAfterBytes: failWriteAfterBytes, failInitialIdentityCheck: failInitialIdentityCheck
            )
        } catch {
            for (name, identity) in created { try? Self.removeExact(name: name, identity: identity, in: directoryFD) }
            close(directoryFD); _ = unlinkat(rootFD, profileID, AT_REMOVEDIR); close(rootFD)
            throw error
        }
        keyIdentities = created
    }

    deinit { close(directoryDescriptor); close(rootDescriptor) }

    var publicIdentities: (approval: Data, denial: Data) {
        (approval.publicKey.x963Representation, denial.publicKey.x963Representation)
    }

    var handoff: PublicIdentities {
        let identities = publicIdentities
        return PublicIdentities(
            profileID: profileID,
            approvalPublicKey: identities.approval,
            approvalPublicKeyID: Data(SHA256.hash(data: identities.approval)),
            denialPublicKey: identities.denial,
            denialPublicKeyID: Data(SHA256.hash(data: identities.denial))
        )
    }

    func approvalSignature(for payload: Data) throws -> Data {
        try approval.signature(for: payload).rawRepresentation
    }

    func denialSignature(for payload: Data) throws -> Data {
        try denial.signature(for: payload).rawRepresentation
    }

    func cleanup() throws {
        var currentDirectory = stat()
        guard fstatat(rootDescriptor, profileID, &currentDirectory, AT_SYMLINK_NOFOLLOW) == 0,
              ObjectIdentity(currentDirectory) == directoryIdentity,
              currentDirectory.st_mode & S_IFMT == S_IFDIR else {
            throw E2ETestHarnessError.invalidConfiguration("profile store was replaced")
        }
        let names = try entryNames()
        guard Set(names) == Set(keyIdentities.keys) else {
            throw E2ETestHarnessError.invalidConfiguration("profile store contains foreign files")
        }
        for (name, identity) in keyIdentities {
            var current = stat()
            guard fstatat(directoryDescriptor, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                  ObjectIdentity(current) == identity, current.st_uid == getuid(),
                  current.st_mode & S_IFMT == S_IFREG else {
                throw E2ETestHarnessError.invalidConfiguration("disposable key was replaced")
            }
        }
        for (name, identity) in keyIdentities {
            try Self.removeExact(name: name, identity: identity, in: directoryDescriptor)
        }
        guard unlinkat(rootDescriptor, profileID, AT_REMOVEDIR) == 0 else {
            throw Self.posixError("profile cleanup failed")
        }
    }

    private func entryNames() throws -> [String] {
        guard let stream = fdopendir(dup(directoryDescriptor)) else { throw Self.posixError("profile scan failed") }
        defer { closedir(stream) }
        var names: [String] = []
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { names.append(name) }
        }
        return names
    }

    private static func removeExact(name: String, identity: ObjectIdentity, in directoryFD: Int32) throws {
        let staged = ".cleanup-\(UUID().uuidString)"
        guard renameatx_np(directoryFD, name, directoryFD, staged, UInt32(RENAME_EXCL)) == 0 else {
            throw posixError("key staging failed")
        }
        var stagedStatus = stat()
        guard fstatat(directoryFD, staged, &stagedStatus, AT_SYMLINK_NOFOLLOW) == 0,
              ObjectIdentity(stagedStatus) == identity else {
            let restoreResult = renameatx_np(directoryFD, staged, directoryFD, name, UInt32(RENAME_EXCL))
            if restoreResult != 0 {
                throw E2ETestHarnessError.invalidConfiguration("staged replacement could not be restored")
            }
            throw E2ETestHarnessError.invalidConfiguration("disposable key changed during cleanup")
        }
        guard unlinkat(directoryFD, staged, 0) == 0 else { throw posixError("key cleanup failed") }
    }

    private static func writeNew(
        _ data: Data, named name: String, in directoryFD: Int32, failAfterBytes: Int? = nil,
        failInitialIdentityCheck: Bool = false
    ) throws -> ObjectIdentity {
        let fd = openat(directoryFD, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw posixError("could not create disposable key") }
        defer { close(fd) }
        var identity: ObjectIdentity?
        do {
            if failInitialIdentityCheck {
                throw E2ETestHarnessError.invalidConfiguration("injected initial identity failure")
            }
            var createdStatus = stat()
            guard fstat(fd, &createdStatus) == 0 else { throw posixError("could not identify disposable key") }
            identity = ObjectIdentity(createdStatus)
            var written = 0
            try data.withUnsafeBytes { bytes in
                while written < bytes.count {
                    let remainingBeforeFailure = failAfterBytes.map { max(0, $0 - written) } ?? (bytes.count - written)
                    if remainingBeforeFailure == 0 {
                        throw E2ETestHarnessError.invalidConfiguration("injected partial key write failure")
                    }
                    let count = min(bytes.count - written, remainingBeforeFailure)
                    let result = Darwin.write(fd, bytes.baseAddress!.advanced(by: written), count)
                    guard result > 0 else { throw posixError("could not write disposable key") }
                    written += result
                }
            }
            var status = stat()
            guard fstat(fd, &status) == 0, status.st_uid == getuid(), status.st_mode & S_IFMT == S_IFREG,
                  ObjectIdentity(status) == identity else {
                throw E2ETestHarnessError.invalidConfiguration("disposable key is not owned")
            }
            return identity!
        } catch {
            if let identity {
                try? removeExact(name: name, identity: identity, in: directoryFD)
            } else {
                // No identity was obtainable. Preserve anything unexpected;
                // remove only the regular, owned entry just created in this
                // exclusive profile directory.
                var current = stat()
                if fstatat(directoryFD, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
                   current.st_uid == getuid(), current.st_mode & S_IFMT == S_IFREG {
                    try? removeExact(name: name, identity: ObjectIdentity(current), in: directoryFD)
                }
            }
            throw error
        }
    }

    private static func posixError(_ message: String) -> E2ETestHarnessError {
        .invalidConfiguration("\(message) (errno \(errno))")
    }
}

final class E2EScenarioSigner: DecisionSigning, @unchecked Sendable {
    private let grant: E2ETestRequestGrant
    private let request: VerifiedApprovalRequest
    private let keys: E2EDisposableKeyStore
    private let effectiveExpiry: Date
    private let lock = NSLock()
    private var consumed = false

    init(grant: E2ETestRequestGrant, request: VerifiedApprovalRequest, keys: E2EDisposableKeyStore, now: Date = .now) throws {
        try grant.validate(now: now)
        guard grant.matches(request) else { throw E2ETestHarnessError.requestMismatch }
        let expiry = min(grant.expiresAt, request.expiresAt)
        guard expiry > now else { throw E2ETestHarnessError.invalidConfiguration("request expired") }
        self.grant = grant
        self.request = request
        self.keys = keys
        effectiveExpiry = expiry
    }

    func approvalPublicKey() throws -> Data { keys.publicIdentities.approval }
    func denialPublicKey() throws -> Data { keys.publicIdentities.denial }
    func accepts(_ candidate: VerifiedApprovalRequest) -> Bool { grant.matches(candidate) }

    func signApproval(payload: Data, reason: String, cancellation: ApprovalCancellation) throws -> (keyID: Data, signature: Data) {
        let publicKey = keys.publicIdentities.approval
        try consume(expected: .approve, payload: payload, publicKey: publicKey)
        if grant.decision == .cancelAuthentication { throw E2ETestHarnessError.simulatedCancellation }
        try cancellation.check()
        return (Data(SHA256.hash(data: publicKey)), try keys.approvalSignature(for: payload))
    }

    func signDenial(payload: Data) throws -> (keyID: Data, signature: Data) {
        let publicKey = keys.publicIdentities.denial
        try consume(expected: .deny, payload: payload, publicKey: publicKey)
        return (Data(SHA256.hash(data: publicKey)), try keys.denialSignature(for: payload))
    }

    private func consume(expected: E2ETestDecision, payload: Data, publicKey: Data) throws {
        try lock.withLock {
            guard !consumed else { throw E2ETestHarnessError.grantConsumed }
            consumed = true
            guard effectiveExpiry > .now else {
                throw E2ETestHarnessError.invalidConfiguration("grant expired")
            }
            guard grant.decision == expected || (expected == .approve && grant.decision == .cancelAuthentication) else {
                throw E2ETestHarnessError.requestMismatch
            }
            let keyID = Data(SHA256.hash(data: publicKey))
            try validateSignatureInput(payload, approve: expected == .approve, keyID: keyID)
        }
    }

    private func validateSignatureInput(_ input: Data, approve: Bool, keyID: Data) throws {
        guard let structure = try CBORCodec.decodeCanonical(input).arrayValue, structure.count == 4,
              structure[0].textValue == "Signature1",
              let protected = structure[1].bytesValue,
              structure[2].bytesValue == Data(),
              let payload = structure[3].bytesValue,
              protected == (try SynProtocol.protectedHeader(keyID: keyID)),
              try SynProtocol.signatureStructure(protected: protected, payload: payload) == input else {
            throw E2ETestHarnessError.requestMismatch
        }
        let decision = try CBORCodec.decodeCanonical(payload).integerKeyedMap()
        let action: UInt64 = approve ? 1 : 2
        guard decision.count == 10,
              decision[0]?.unsignedValue == SynProtocol.version,
              decision[1]?.bytesValue == request.requestID,
              decision[2]?.bytesValue == request.payloadHash,
              decision[3]?.textValue == request.targetID,
              decision[4]?.unsignedValue == action,
              let decisionMilliseconds = Self.signedInteger(decision[5]),
              decision[6]?.bytesValue == keyID,
              decision[7]?.unsignedValue == action,
              decision[8]?.textValue == request.releaseID,
              decision[9]?.textValue == request.releaseCommit else {
            throw E2ETestHarnessError.requestMismatch
        }
        let decisionTime = Date(timeIntervalSince1970: Double(decisionMilliseconds) / 1_000)
        guard decisionMilliseconds >= grant.requestIssuedAtMilliseconds,
              decisionTime <= .now, decisionTime < effectiveExpiry else {
            throw E2ETestHarnessError.requestMismatch
        }
    }

    private static func signedInteger(_ value: CBOR?) -> Int64? {
        if let positive = value?.unsignedValue, positive <= UInt64(Int64.max) { return Int64(positive) }
        return value?.negativeValue
    }
}

final class E2EScenarioSigningProvider: DecisionSignerProviding, @unchecked Sendable {
    private let inbox: E2EGrantInbox
    private let keys: E2EDisposableKeyStore
    private let lock = NSLock()
    private var armed: E2EScenarioSigner?

    init(inbox: E2EGrantInbox, keys: E2EDisposableKeyStore) {
        self.inbox = inbox
        self.keys = keys
    }

    func publicIdentities() throws -> (approval: Data, denial: Data) { keys.publicIdentities }

    func signer(for request: VerifiedApprovalRequest) throws -> any DecisionSigning {
        try lock.withLock {
            if let armed {
                guard armed.accepts(request) else { throw E2ETestHarnessError.requestMismatch }
                return armed
            }
            let grant = try inbox.consumeGrant(for: request)
            let signer = try E2EScenarioSigner(grant: grant, request: request, keys: keys)
            armed = signer
            return signer
        }
    }
}
