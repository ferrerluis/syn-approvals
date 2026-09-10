import Foundation

/// Persist connection metadata only. Passwords, agent keys and approvals are
/// never properties of a target profile.
struct SSHConnectionSettings: Codable, Hashable, Sendable {
    let hostname: String
    let username: String
    let port: UInt16?
    let hostTrustSource: SSHHostTrustSource

    init(hostname: String, username: String, port: UInt16?,
         hostTrustSource: SSHHostTrustSource = .existingOpenSSH) {
        self.hostname = hostname
        self.username = username
        self.port = port
        self.hostTrustSource = hostTrustSource
    }

    private enum CodingKeys: String, CodingKey { case hostname, username, port, hostTrustSource }

    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        hostname = try values.decode(String.self, forKey: .hostname)
        username = try values.decode(String.self, forKey: .username)
        port = try values.decodeIfPresent(UInt16.self, forKey: .port)
        hostTrustSource = try values.decodeIfPresent(SSHHostTrustSource.self, forKey: .hostTrustSource)
            ?? .existingOpenSSH
    }

    func validate() throws {
        let hostBytes = hostname.utf8
        let userBytes = username.utf8
        let hostAllowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]".utf8)
        let userAllowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-".utf8)
        guard !hostBytes.isEmpty, hostBytes.count <= 253, hostname.first != "-",
              hostBytes.allSatisfy({ hostAllowed.contains($0) }),
              !userBytes.isEmpty, userBytes.count <= 64, username.first != "-", username != "root",
              userBytes.allSatisfy({ userAllowed.contains($0) }), port != 0 else {
            throw SynProtocolError.invalid("Enter a hostname, non-root SSH username and valid port.")
        }
    }

    /// System OpenSSH retains existing user configuration/IdentityAgent, while
    /// disabling incidental forwarding and shared control sessions for Syn.
    func arguments(for operation: SSHReadOnlyOperation, synKnownHosts: URL? = nil) throws -> [String] {
        try validate()
        var arguments = ["-T", "-a"]
        arguments += try sharedOpenSSHOptions(synKnownHosts: synKnownHosts)
        arguments += ["-l", username]
        if let port { arguments += ["-p", String(port)] }
        arguments += ["--", hostname, operation.command]
        return arguments
    }

    func arguments(for operation: SSHSetupOperation, synKnownHosts: URL? = nil) throws -> [String] {
        try validate()
        var arguments = ["-T", "-a"]
        arguments += try sharedOpenSSHOptions(synKnownHosts: synKnownHosts)
        arguments += ["-l", username]
        if let port { arguments += ["-p", String(port)] }
        arguments += ["--", hostname, operation.command]
        return arguments
    }

    func maintenanceArguments(for operation: SSHPrivilegedOperation, identityFile: URL,
                              synKnownHosts: URL? = nil,
                              route: SSHMaintenanceRoute? = nil) throws -> [String] {
        try validate()
        guard identityFile.isFileURL, identityFile.path.hasPrefix("/"),
              !identityFile.path.contains("\u{0}") else {
            throw SynProtocolError.invalid("Syn's maintenance identity is unavailable.")
        }
        // -i/IdentitiesOnly still permit IdentityFile entries from ssh_config.
        // Ignore that configuration and carry over only resolved routing/trust.
        var arguments = ["-F", "/dev/null", "-T", "-a"]
        arguments += try sharedOpenSSHOptions(synKnownHosts: synKnownHosts)
        arguments += route?.arguments ?? []
        arguments += ["-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
                      "-o", "CertificateFile=none", "-o", "PKCS11Provider=none",
                      "-o", "PubkeyAcceptedAlgorithms=ssh-ed25519",
                      "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                      "-o", "KbdInteractiveAuthentication=no", "-i", identityFile.path, "-l", "root"]
        if let port { arguments += ["-p", String(port)] }
        arguments += ["--", hostname, try operation.command]
        return arguments
    }

    func resolvedMaintenanceRoute() async throws -> SSHMaintenanceRoute {
        try validate()
        var args = ["-G", "-T", "-o", "PermitLocalCommand=no", "-l", username]
        if let port { args += ["-p", String(port)] }
        args += ["--", hostname]
        let output = try await SSHProbeProcess().run(arguments: args)
        guard output.status == 0 else { throw SSHProbeFailure.classify(output) }
        return try SSHMaintenanceRoute.parse(output.stdout)
    }

    enum TransferDestination: String, Sendable {
        case source = "source.incoming"
        case helper = "synctl-bootstrap.incoming"
        case request = "request.incoming"
    }

    func scpArguments(
        localFile: URL,
        destination: TransferDestination,
        synKnownHosts: URL? = nil
    ) throws -> [String] {
        try validate()
        guard localFile.isFileURL, localFile.path.hasPrefix("/"),
              !localFile.path.contains("\u{0}") else {
            throw SynProtocolError.invalid("The staged remote component is unavailable.")
        }
        // Do not reuse ssh's -T, -a, or -l flags here: scp assigns different
        // meanings to some of them. In particular, scp -T weakens destination
        // filename checking and scp -l is a bandwidth limit.
        // The currently tested remote image does not expose an SFTP subsystem. Legacy
        // SCP still uses the same authenticated SSH connection; the remote
        // path is a fixed literal and strict host verification remains on.
        var arguments = ["-O"]
        arguments += try sharedOpenSSHOptions(synKnownHosts: synKnownHosts)
        if let port { arguments += ["-P", String(port)] }
        let destinationHost: String
        if hostname.contains(":"), !(hostname.hasPrefix("[") && hostname.hasSuffix("]")) {
            destinationHost = "[\(hostname)]"
        } else {
            destinationHost = hostname
        }
        arguments += [
            "--", localFile.path,
            "\(username)@\(destinationHost):.cache/syn-setup/\(destination.rawValue)",
        ]
        return arguments
    }

    private func sharedOpenSSHOptions(synKnownHosts: URL?) throws -> [String] {
        var arguments = [
            "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
            "-o", "UpdateHostKeys=no", "-o", "AddKeysToAgent=no",
            "-o", "ConnectTimeout=10",
        ]
        switch hostTrustSource {
        case .existingOpenSSH:
            break
        case .synKnownHosts:
            guard let synKnownHosts, synKnownHosts.isFileURL,
                  synKnownHosts.path.hasPrefix("/"), !synKnownHosts.path.contains("\"") else {
                throw SynProtocolError.invalid("Syn's saved SSH identity store is unavailable.")
            }
            arguments += ["-o", "UserKnownHostsFile=\"\(synKnownHosts.path)\""]
        }
        return arguments
    }

    func preparedSynKnownHostsURL() throws -> URL? {
        switch hostTrustSource {
        case .existingOpenSSH: nil
        case .synKnownHosts: try SynKnownHostsStore().prepare()
        }
    }
}

/// Only connection routing and host verification survive ssh -G. Credential,
/// forwarding, startup, and command settings cannot enter maintenance SSH.
struct SSHMaintenanceRoute: Sendable {
    let arguments: [String]

    static func parse(_ data: Data) throws -> Self {
        guard data.count <= 65_536, let text = String(data: data, encoding: .utf8),
              !text.contains("\u{0}"), !text.contains("\r") else {
            throw SSHProbeFailure.invalidOutput
        }
        let allowed: Set<String> = [
            "hostname", "port", "proxyjump", "proxycommand", "hostkeyalias",
            "userknownhostsfile", "globalknownhostsfile", "bindaddress", "bindinterface", "addressfamily",
        ]
        var values: [String: String] = [:]
        for line in text.split(separator: "\n") {
            guard let separator = line.firstIndex(of: " ") else { continue }
            let name = String(line[..<separator])
            guard allowed.contains(name) else { continue }
            let value = String(line[line.index(after: separator)...])
            guard values[name] == nil, !value.isEmpty else { throw SSHProbeFailure.invalidOutput }
            values[name] = value
        }
        guard let hostname = values["hostname"], let port = values["port"],
              let number = UInt16(port), number > 0 else { throw SSHProbeFailure.invalidOutput }
        try SSHConnectionSettings(hostname: hostname, username: "syn", port: number).validate()
        return Self(arguments: values.keys.sorted().flatMap { name in
            ["-o", "\(name)=\(values[name]!)"]
        })
    }
}

/// The complete privileged remote-command surface. Associated values are
/// validated before any shell text is produced; callers cannot supply paths or
/// command fragments.
enum SSHPrivilegedOperation: Sendable, Equatable {
    case probe
    case retainHelper(operationID: String, sha256: String, size: UInt64)
    case prepare(operationID: String, requestSHA256: String, sourceSHA256: String)
    case cleanup(operationID: String)
    case build(operationID: String)
    case configure(operationID: String)
    case activate(operationID: String)
    case complete(operationID: String)
    case recover

    var timeout: Duration {
        switch self {
        case .build: .seconds(1_800)
        case .complete: .seconds(150)
        case .activate: .seconds(120)
        case .configure: .seconds(300)
        case .probe, .retainHelper, .prepare, .cleanup, .recover: .seconds(60)
        }
    }

    fileprivate var command: String {
        get throws {
            switch self {
            case .probe:
                return "syn-maintenance-v1 probe"
            case let .retainHelper(operationID, sha256, size):
                try Self.requireOperationID(operationID)
                try Self.requireSHA256(sha256)
                guard size > 0, size <= RemoteHelperArtifactDescriptor.maximumArtifactBytes else {
                    throw SynProtocolError.invalid("The maintenance helper size is invalid.")
                }
                return "syn-maintenance-v1 retain \(operationID) \(sha256) \(size)"
            case let .prepare(operationID, requestSHA256, sourceSHA256):
                try Self.requireOperationID(operationID)
                try Self.requireSHA256(requestSHA256)
                try Self.requireSHA256(sourceSHA256)
                return "syn-maintenance-v1 prepare \(operationID) \(requestSHA256) \(sourceSHA256)"
            case let .cleanup(operationID):
                return try protected(operationID, phase: "cleanup")
            case let .build(operationID):
                return try protected(operationID, phase: "build")
            case let .configure(operationID):
                return try protected(operationID, phase: "configure")
            case let .activate(operationID):
                return try protected(operationID, phase: "activate")
            case let .complete(operationID):
                return try protected(operationID, phase: "complete")
            case .recover:
                return "syn-maintenance-v1 recover"
            }
        }
    }

    private func protected(_ operationID: String, phase: String) throws -> String {
        try Self.requireOperationID(operationID)
        return "syn-maintenance-v1 \(phase) \(operationID)"
    }

    private static func requireOperationID(_ value: String) throws {
        guard value.utf8.count == 32, value.utf8.allSatisfy({
            (48...57).contains($0) || (97...102).contains($0)
        }) else { throw SynProtocolError.invalid("The setup operation identifier is invalid.") }
    }

    private static func requireSHA256(_ value: String) throws {
        guard value.utf8.count == 64, value.utf8.allSatisfy({
            (48...57).contains($0) || (97...102).contains($0)
        }) else { throw SynProtocolError.invalid("The staged component digest is invalid.") }
    }
}

/// No caller-supplied remote command strings. Privileged setup operations are
/// added separately only after the credential/maintenance contract is reviewed.
enum SSHReadOnlyOperation: Sendable, Equatable {
    case platform
    case operatingSystem
    case connection
    case status

    fileprivate var command: String {
        switch self {
        case .platform: "/usr/bin/uname -sm"
        case .operatingSystem: "/usr/bin/cat /etc/os-release"
        case .connection: "/usr/bin/printenv SSH_CONNECTION"
        case .status: "/usr/bin/synctl --json status"
        }
    }
}

/// Fixed ordinary-user setup operations. Callers cannot supply shell text.
enum SSHSetupOperation: Sendable, Equatable {
    case prepareSourceTransfer
    case sourceDigest
    case helperDigest
    case requestDigest

    fileprivate var command: String {
        switch self {
        case .prepareSourceTransfer: "/usr/bin/install -d -m 0700 .cache/syn-setup"
        case .sourceDigest: "/usr/bin/sha256sum .cache/syn-setup/source.incoming"
        case .helperDigest: "/usr/bin/sha256sum .cache/syn-setup/synctl-bootstrap.incoming"
        case .requestDigest: "/usr/bin/sha256sum .cache/syn-setup/request.incoming"
        }
    }
}
