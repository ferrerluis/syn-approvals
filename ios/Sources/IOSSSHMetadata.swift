import Foundation

// Same persisted profile shape as macOS; iOS does not read OpenSSH configuration.
struct SSHConnectionSettings: Codable, Hashable, Sendable {
    let hostname: String
    let username: String
    let port: UInt16?
    let hostTrustSource: String?
}
