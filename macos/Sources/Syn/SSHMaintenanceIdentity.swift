import CryptoKit
import Darwin
import Foundation

/// A separate per-machine SSH identity. The remote authorized_keys restriction
/// binds it to Syn's fixed maintenance dispatcher, including during recovery.
struct SSHMaintenanceIdentity: Sendable {
    let privateKeyURL: URL
    let publicKey: String

    static func prepare(for settings: SSHConnectionSettings, directory: URL? = nil) throws -> Self {
        try settings.validate()
        let base = try directory ?? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("Syn/Maintenance", isDirectory: true)
        try FileManager.default.createDirectory(
            at: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        try validatePath(base, directory: true, mode: 0o700)
        let label = "\(settings.username)@\(settings.hostname):\(settings.port ?? 22)"
        let identifier = SHA256.hash(data: Data(label.utf8)).map { String(format: "%02x", $0) }.joined()
        let folder = base.appendingPathComponent(identifier, isDirectory: true)
        if !FileManager.default.fileExists(atPath: folder.path) {
            try FileManager.default.createDirectory(
                at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
            )
        }
        try validatePath(folder, directory: true, mode: 0o700)
        let key = folder.appendingPathComponent("id_ed25519")
        let publicURL = folder.appendingPathComponent("id_ed25519.pub")
        if !FileManager.default.fileExists(atPath: key.path) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
            process.arguments = ["-q", "-t", "ed25519", "-N", "", "-C", "syn-maintenance", "-f", key.path]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                throw SynProtocolError.invalid("Could not create Syn's maintenance key.")
            }
        }
        try validatePath(key, directory: false, mode: 0o600)
        try validatePath(publicURL, directory: false, mode: 0o644)
        let publicText = try String(contentsOf: publicURL, encoding: .utf8)
        let fields = publicText.split(whereSeparator: { $0.isWhitespace })
        guard fields.count == 3, fields[0] == "ssh-ed25519",
              let bytes = Data(base64Encoded: String(fields[1])), bytes.count == 51,
              bytes.prefix(19) == Data([0, 0, 0, 11] + Array("ssh-ed25519".utf8) + [0, 0, 0, 32]) else {
            throw SynProtocolError.invalid("Syn's maintenance public key is invalid.")
        }
        return Self(privateKeyURL: key, publicKey: "ssh-ed25519 \(fields[1])")
    }

    private static func validatePath(_ url: URL, directory: Bool, mode: mode_t) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0, info.st_uid == getuid(),
              info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o7777 == mode,
              directory || (info.st_nlink == 1 && info.st_size > 0 && info.st_size <= 16_384) else {
            throw SynProtocolError.invalid("Syn's maintenance key storage has unsafe permissions. Repair it before continuing.")
        }
    }
}

enum SSHMaintenanceBootstrap {
    /// Shown for the user to run in a trusted administrator terminal, never
    /// submitted by Syn through the ordinary user's SSH shell.
    static func command(settings: SSHConnectionSettings, identity: SSHMaintenanceIdentity,
                        helper: RemoteHelperArtifactDescriptor) throws -> String {
        try settings.validate()
        _ = try settings.maintenanceArguments(
            for: .retainHelper(operationID: String(repeating: "0", count: 32),
                               sha256: helper.artifact.sha256, size: helper.artifact.sizeBytes),
            identityFile: identity.privateKeyURL,
            synKnownHosts: settings.hostTrustSource == .synKnownHosts
                ? URL(fileURLWithPath: "/tmp/syn-known-hosts") : nil
        )
        let fields = identity.publicKey.split(separator: " ")
        guard fields.count == 2, fields[0] == "ssh-ed25519",
              let bytes = Data(base64Encoded: String(fields[1])), bytes.count == 51 else {
            throw SynProtocolError.invalid("Syn's maintenance public key is invalid.")
        }
        let script = """
        set -eu
        bootstrap_home=$(/usr/bin/getent passwd \(settings.username) | /usr/bin/cut -d: -f6)
        test -n "$bootstrap_home"
        bootstrap_dir=$(/usr/bin/mktemp -d /var/tmp/syn-bootstrap.XXXXXXXX)
        trap '/bin/rm -f -- "$bootstrap_dir/synctl"; /bin/rmdir -- "$bootstrap_dir"' EXIT
        /usr/bin/install -o root -g root -m 0500 -- "$bootstrap_home/.cache/syn-setup/synctl-bootstrap.incoming" "$bootstrap_dir/synctl"
        test "$(/usr/bin/stat --format=%s -- "$bootstrap_dir/synctl")" = '\(helper.artifact.sizeBytes)'
        /usr/bin/printf '%s  %s\\n' '\(helper.artifact.sha256)' "$bootstrap_dir/synctl" | /usr/bin/sha256sum --check --status
        "$bootstrap_dir/synctl" --json maintenance install --user '\(settings.username)' --public-key '\(identity.publicKey)' --apply
        """
        return "sudo /bin/sh -c " + shellQuote(script)
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
