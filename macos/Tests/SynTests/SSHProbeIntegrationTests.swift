import Foundation
import Testing
@testable import Syn

/// Opt-in read-only check: uses a pretrusted SSH destination and never installs,
/// pairs, opens UI or authenticates sudo. Not an E2E acceptance substitute.
@Test(.enabled(if: ProcessInfo.processInfo.environment["SYN_TEST_SSH_HOST"] != nil))
func realSSHPlatformProbeReadsSupportedRemoteWithoutMutations() async throws {
    let environment = ProcessInfo.processInfo.environment
    let hostname = try #require(environment["SYN_TEST_SSH_HOST"])
    let username = try #require(environment["SYN_TEST_SSH_USER"])
    let settings = SSHConnectionSettings(hostname: hostname, username: username, port: nil)
    let checker = SSHMachineSetupChecker()
    let result = try await checker.check(settings)
    #expect(result.settings == settings)
}
