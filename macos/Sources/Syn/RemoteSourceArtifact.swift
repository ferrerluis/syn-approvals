import CryptoKit
import Darwin
import Foundation

enum RemoteSourceArtifactError: Error, Equatable, LocalizedError {
    case metadataTooLarge
    case invalidMetadata
    case identityMismatch
    case unexpectedArtifactName
    case unsafeArtifact
    case artifactTooLarge
    case artifactSizeMismatch
    case artifactHashMismatch
    case artifactChangedDuringVerification
    case fileOperationFailed(operation: String, code: Int32)

    var errorDescription: String? {
        switch self {
        case .metadataTooLarge, .invalidMetadata:
            "Syn's release information is invalid. Download the Mac app again from its trusted release."
        case .identityMismatch, .unexpectedArtifactName:
            "This download does not match this version of Syn. Download its matching remote component again."
        case .unsafeArtifact:
            "The remote component is not a regular download file. Download it again."
        case .artifactTooLarge:
            "The remote component exceeds Syn's download limit."
        case .artifactSizeMismatch, .artifactHashMismatch, .artifactChangedDuringVerification:
            "The remote component is incomplete or has changed. Download it again before installing."
        case .fileOperationFailed:
            "Syn could not read the downloaded remote component. Check access to the download and retry."
        }
    }
}

struct RemoteSourceArtifactDescriptor: Equatable, Sendable {
    static let maximumMetadataBytes = 16 * 1024
    static let maximumArtifactBytes: UInt64 = 2 * 1024 * 1024 * 1024

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
        guard isReleaseID(expectedReleaseID), isCommit(expectedCommit), isArtifactName(expectedArtifactName) else {
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
            let schemaVersion = object["schema_version"] as? NSNumber,
            isInteger(schemaVersion), schemaVersion.intValue == 1,
            let releaseID = object["release_id"] as? String, isReleaseID(releaseID),
            let commit = object["commit"] as? String, isCommit(commit),
            let artifact = object["artifact"] as? [String: Any],
            Set(artifact.keys) == ["kind", "name", "sha256", "size_bytes"],
            artifact["kind"] as? String == "remote_source",
            let name = artifact["name"] as? String, isArtifactName(name),
            let sha256 = artifact["sha256"] as? String, isSHA256(sha256),
            let sizeNumber = artifact["size_bytes"] as? NSNumber,
            isInteger(sizeNumber),
            let sizeBytes = UInt64(sizeNumber.stringValue),
            sizeBytes > 0
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
            artifact: Artifact(name: name, sha256: sha256, sizeBytes: sizeBytes)
        )
    }

    func verifyArtifact(at url: URL) throws -> VerifiedRemoteSourceArtifact {
        guard url.lastPathComponent == artifact.name else {
            throw RemoteSourceArtifactError.unexpectedArtifactName
        }

        let descriptor = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            // Nonblocking is essential until fstat proves this is a regular file: opening
            // an attacker-supplied FIFO for reading must not hang the verifier.
            return Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        }
        guard descriptor >= 0 else {
            if errno == ELOOP {
                throw RemoteSourceArtifactError.unsafeArtifact
            }
            throw RemoteSourceArtifactError.fileOperationFailed(operation: "open", code: errno)
        }

        do {
            var before = Darwin.stat()
            guard Darwin.fstat(descriptor, &before) == 0 else {
                throw RemoteSourceArtifactError.fileOperationFailed(operation: "fstat", code: errno)
            }
            guard before.st_mode & S_IFMT == S_IFREG, before.st_size >= 0 else {
                throw RemoteSourceArtifactError.unsafeArtifact
            }
            let statedSize = UInt64(before.st_size)
            guard statedSize <= Self.maximumArtifactBytes else {
                throw RemoteSourceArtifactError.artifactTooLarge
            }
            guard statedSize == artifact.sizeBytes else {
                throw RemoteSourceArtifactError.artifactSizeMismatch
            }

            var hasher = SHA256()
            var totalBytes: UInt64 = 0
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let result = buffer.withUnsafeMutableBytes { bytes in
                    Darwin.read(descriptor, bytes.baseAddress, bytes.count)
                }
                if result < 0 {
                    if errno == EINTR { continue }
                    throw RemoteSourceArtifactError.fileOperationFailed(operation: "read", code: errno)
                }
                if result == 0 { break }
                let count = UInt64(result)
                guard count <= Self.maximumArtifactBytes - totalBytes else {
                    throw RemoteSourceArtifactError.artifactTooLarge
                }
                totalBytes += count
                hasher.update(data: Data(buffer.prefix(Int(result))))
            }
            guard totalBytes == artifact.sizeBytes else {
                throw RemoteSourceArtifactError.artifactSizeMismatch
            }

            var after = Darwin.stat()
            guard Darwin.fstat(descriptor, &after) == 0 else {
                throw RemoteSourceArtifactError.fileOperationFailed(operation: "fstat", code: errno)
            }
            guard sameFileState(before, after) else {
                throw RemoteSourceArtifactError.artifactChangedDuringVerification
            }
            let actualHash = Data(hasher.finalize()).map { String(format: "%02x", $0) }.joined()
            guard actualHash == artifact.sha256 else {
                throw RemoteSourceArtifactError.artifactHashMismatch
            }

            return VerifiedRemoteSourceArtifact(descriptor: self, fileDescriptor: descriptor)
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private static func isInteger(_ number: NSNumber) -> Bool {
        CFGetTypeID(number) != CFBooleanGetTypeID()
            && !["f", "d"].contains(String(cString: number.objCType))
    }

    private static func isReleaseID(_ value: String) -> Bool {
        let digits = Array(value.utf8)
        guard digits.count == 14, digits.allSatisfy({ (48...57).contains($0) }) else { return false }
        func component(_ offset: Int, _ count: Int) -> Int {
            digits[offset..<(offset + count)].reduce(0) { $0 * 10 + Int($1 - 48) }
        }
        let expected = DateComponents(
            timeZone: TimeZone(secondsFromGMT: 0),
            year: component(0, 4), month: component(4, 2), day: component(6, 2),
            hour: component(8, 2), minute: component(10, 2), second: component(12, 2)
        )
        guard expected.year! >= 2026 else { return false }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        guard let date = calendar.date(from: expected) else { return false }
        let actual = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return actual.year == expected.year && actual.month == expected.month && actual.day == expected.day
            && actual.hour == expected.hour && actual.minute == expected.minute && actual.second == expected.second
    }

    private static func isCommit(_ value: String) -> Bool {
        value.utf8.count == 40 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func isArtifactName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard value.count == bytes.count, let first = bytes.first, isASCIIAlphaNumeric(first) else { return false }
        return bytes.dropFirst().allSatisfy { isASCIIAlphaNumeric($0) || $0 == 46 || $0 == 95 || $0 == 45 }
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
    }

    private func sameFileState(_ lhs: Darwin.stat, _ rhs: Darwin.stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }
}

/// Owns the exact regular-file descriptor that was hashed, so replacing its path cannot
/// redirect a caller. The underlying inode is not immutable: callers must consume it only
/// inside `withFileDescriptor` and verify the bytes they copy or transfer against
/// `descriptor.artifact.sha256` immediately before use. Reopening its path discards this check.
final class VerifiedRemoteSourceArtifact: @unchecked Sendable {
    let descriptor: RemoteSourceArtifactDescriptor

    private let lock = NSLock()
    private var fileDescriptor: Int32

    fileprivate init(descriptor: RemoteSourceArtifactDescriptor, fileDescriptor: Int32) {
        self.descriptor = descriptor
        self.fileDescriptor = fileDescriptor
    }

    deinit {
        if fileDescriptor >= 0 { Darwin.close(fileDescriptor) }
    }

    /// The descriptor is borrowed only for this closure and must not be stored or closed.
    /// This pins the opened inode, not its contents against a concurrent same-inode writer.
    func withFileDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard fileDescriptor >= 0 else {
            throw RemoteSourceArtifactError.fileOperationFailed(operation: "verified file", code: EBADF)
        }
        guard Darwin.lseek(fileDescriptor, 0, SEEK_SET) == 0 else {
            throw RemoteSourceArtifactError.fileOperationFailed(operation: "lseek", code: errno)
        }
        return try body(fileDescriptor)
    }

    func makePrivateTransferCopy() throws -> StagedRemoteSourceArtifact {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("syn-transfer-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            let outputURL = directory.appendingPathComponent(descriptor.artifact.name)
            let output = outputURL.withUnsafeFileSystemRepresentation { path -> Int32 in
                guard let path else { return -1 }
                return Darwin.open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            }
            guard output >= 0 else {
                throw RemoteSourceArtifactError.fileOperationFailed(operation: "transfer copy", code: errno)
            }
            do {
                try withFileDescriptor { input in
                    var hasher = SHA256()
                    var total: UInt64 = 0
                    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
                    while true {
                        let count = buffer.withUnsafeMutableBytes { Darwin.read(input, $0.baseAddress, $0.count) }
                        if count < 0 {
                            if errno == EINTR { continue }
                            throw RemoteSourceArtifactError.fileOperationFailed(operation: "transfer read", code: errno)
                        }
                        if count == 0 { break }
                        var offset = 0
                        while offset < count {
                            let written = buffer.withUnsafeBytes {
                                Darwin.write(output, $0.baseAddress!.advanced(by: offset), count - offset)
                            }
                            if written < 0 {
                                if errno == EINTR { continue }
                                throw RemoteSourceArtifactError.fileOperationFailed(operation: "transfer write", code: errno)
                            }
                            offset += written
                        }
                        total += UInt64(count)
                        guard total <= RemoteSourceArtifactDescriptor.maximumArtifactBytes else {
                            throw RemoteSourceArtifactError.artifactTooLarge
                        }
                        hasher.update(data: Data(buffer.prefix(count)))
                    }
                    let digest = Data(hasher.finalize()).map { String(format: "%02x", $0) }.joined()
                    guard total == descriptor.artifact.sizeBytes else {
                        throw RemoteSourceArtifactError.artifactSizeMismatch
                    }
                    guard digest == descriptor.artifact.sha256 else {
                        throw RemoteSourceArtifactError.artifactChangedDuringVerification
                    }
                }
                guard Darwin.fsync(output) == 0 else {
                    throw RemoteSourceArtifactError.fileOperationFailed(operation: "transfer fsync", code: errno)
                }
            } catch {
                Darwin.close(output)
                throw error
            }
            guard Darwin.close(output) == 0 else {
                throw RemoteSourceArtifactError.fileOperationFailed(operation: "transfer close", code: errno)
            }
            return StagedRemoteSourceArtifact(directory: directory, url: outputURL, descriptor: descriptor)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }
}

final class StagedRemoteSourceArtifact: @unchecked Sendable {
    let url: URL
    let descriptor: RemoteSourceArtifactDescriptor
    private let directory: URL
    private let lock = NSLock()
    private var removed = false

    fileprivate init(directory: URL, url: URL, descriptor: RemoteSourceArtifactDescriptor) {
        self.directory = directory
        self.url = url
        self.descriptor = descriptor
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
