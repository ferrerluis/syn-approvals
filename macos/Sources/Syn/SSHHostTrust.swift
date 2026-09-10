import Darwin
import Foundation

@_silgen_name("flock")
private func synKnownHostsFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

enum SSHHostTrustSource: String, Codable, Sendable {
    case existingOpenSSH
    case synKnownHosts
}

/// Syn never rewrites the user's OpenSSH known_hosts files. Keys confirmed in
/// the Add-machine flow are owned separately and can be forgotten explicitly.
struct SynKnownHostsStore: Sendable {
    let fileURL: URL

    init(fileURL: URL? = nil) throws {
        if let fileURL { self.fileURL = fileURL; return }
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        self.fileURL = base
            .appendingPathComponent("Syn", isDirectory: true)
            .appendingPathComponent("SSH", isDirectory: true)
            .appendingPathComponent("known_hosts", isDirectory: false)
    }

    func prepare() throws -> URL {
        let directory = fileURL.deletingLastPathComponent()
        try ensureDirectory(directory)
        if lstatExists(fileURL.path) {
            try verify(fileURL.path, regular: true, requiredMode: 0o600)
        } else {
            let descriptor = Darwin.open(fileURL.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
            guard descriptor >= 0 else { throw SSHProbeFailure.unavailable }
            guard Darwin.close(descriptor) == 0 else { throw SSHProbeFailure.unavailable }
            try verify(fileURL.path, regular: true, requiredMode: 0o600)
        }
        return fileURL
    }

    func trust(_ candidate: SSHHostTrustCandidate) throws -> URL {
        try candidate.settings.validate()
        let expectedHost = candidate.port == 22
            ? candidate.settings.hostname
            : "[\(candidate.settings.hostname)]:\(candidate.port)"
        guard let first = candidate.records.first, candidate.records.count <= 4,
              first.hostField == expectedHost,
              candidate.records.allSatisfy({
                  $0.hostField == first.hostField
                      && ($0.algorithm == "ssh-ed25519" || $0.algorithm == "ecdsa-sha2-nistp256")
                      && Data(base64Encoded: $0.keyBase64)?.isEmpty == false
              }) else { throw SSHProbeFailure.invalidOutput }
        let url = try prepare()
        let descriptor = Darwin.open(url.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw SSHProbeFailure.unavailable }
        defer { Darwin.close(descriptor) }
        guard synKnownHostsFlock(descriptor, LOCK_EX) == 0 else { throw SSHProbeFailure.unavailable }
        defer { _ = synKnownHostsFlock(descriptor, LOCK_UN) }
        var information = stat()
        guard fstat(descriptor, &information) == 0,
              information.st_uid == geteuid(), information.st_mode & S_IFMT == S_IFREG,
              information.st_mode & 0o777 == 0o600, information.st_size >= 0,
              information.st_size <= 256 * 1024 else { throw SSHProbeFailure.unavailable }
        guard lseek(descriptor, 0, SEEK_SET) == 0 else { throw SSHProbeFailure.unavailable }
        var bytes = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw SSHProbeFailure.unavailable
            }
            guard bytes.count + count <= 256 * 1024 else { throw SSHProbeFailure.unavailable }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        guard let existing = String(data: bytes, encoding: .utf8), !existing.utf8.contains(0) else {
            throw SSHProbeFailure.unavailable
        }
        let host = first.hostField
        let existingHostLines = existing.split(separator: "\n").map(String.init).filter {
            $0.split(separator: " ", maxSplits: 1).first == Substring(host)
        }
        let proposed = candidate.records.map(\.line)
        if !existingHostLines.isEmpty {
            guard Set(existingHostLines) == Set(proposed) else { throw SSHProbeFailure.changedHostKey }
            return url
        }
        var addition = existing.isEmpty || existing.hasSuffix("\n") ? "" : "\n"
        addition += proposed.joined(separator: "\n") + "\n"
        guard lseek(descriptor, 0, SEEK_END) >= 0 else { throw SSHProbeFailure.unavailable }
        let writeData = Data(addition.utf8)
        try writeData.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(
                    descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw SSHProbeFailure.unavailable
                }
                offset += count
            }
        }
        guard Darwin.fsync(descriptor) == 0 else { throw SSHProbeFailure.unavailable }
        return url
    }

    private func ensureDirectory(_ directory: URL) throws {
        let parent = directory.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parent.path) {
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        }
        if !lstatExists(directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }
        try verify(directory.path, regular: false, requiredMode: 0o700)
    }

    private func verify(_ path: String, regular: Bool, requiredMode: mode_t) throws {
        var information = stat()
        guard lstat(path, &information) == 0,
              information.st_uid == geteuid(),
              information.st_mode & 0o777 == requiredMode,
              regular ? information.st_mode & S_IFMT == S_IFREG : information.st_mode & S_IFMT == S_IFDIR else {
            throw SSHProbeFailure.unavailable
        }
    }

    private func lstatExists(_ path: String) -> Bool {
        var information = stat()
        return lstat(path, &information) == 0
    }
}
