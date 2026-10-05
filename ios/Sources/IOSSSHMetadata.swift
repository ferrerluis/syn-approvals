import Foundation

// Same persisted profile shape as macOS; iOS does not read OpenSSH configuration.
struct SSHConnectionSettings: Codable, Hashable, Sendable {
    let hostname: String
    let username: String
    let port: UInt16?
    let hostTrustSource: String?
    func validate() throws {
        _ = try MobileSSH(host: hostname, port: Int(port ?? 22), hostKey: nil)
        guard !username.isEmpty, username.utf8.count <= 64, username.first != "-",
              username.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45,46,95].contains($0) }) else {
            throw SynProtocolError.invalid("Enter the machine’s Linux account name.")
        }
    }
}
