import Foundation
import Testing
@testable import Syn

private func statusOutput(_ overrides: [String: Any] = [:], status: Int32 = 0) throws -> SSHProbeOutput {
    var report: [String: Any] = [
        "schema_version": 1, "configured": true, "configuration_state": "configured",
        "release_id": "20260906160000", "release_commit": String(repeating: "a", count: 40),
        "target_id": "test-machine", "managed_uid": 1000,
    ]
    report.merge(overrides) { _, replacement in replacement }
    return SSHProbeOutput(status: status, stdout: try JSONSerialization.data(
        withJSONObject: ["ok": true, "data": report]
    ))
}

@Test func remoteStatusRetainsExactReleaseWithoutClaimingApprovalHealth() throws {
    let report = try RemoteInstallationStatus.parse(statusOutput())
    #expect(report.configuration == .configured)
    #expect(report.release.releaseID == "20260906160000")
    #expect(report.release.commit == String(repeating: "a", count: 40))
    #expect(report.targetID == "test-machine")
    #expect(report.managedUID == 1000)
}

@Test func remoteStatusDistinguishesUnreadableFromAbsentAndInvalid() throws {
    let unreadable = try RemoteInstallationStatus.parse(statusOutput([
        "configuration_state": "unreadable", "configured": NSNull(),
    ]))
    #expect(unreadable.configuration == .unreadable)
    let absent = try RemoteInstallationStatus.parse(statusOutput([
        "configuration_state": "absent", "configured": false,
        "target_id": NSNull(), "managed_uid": NSNull(),
    ]))
    #expect(absent.configuration == .absent)
    for state in ["incomplete", "invalid"] {
        let report = try RemoteInstallationStatus.parse(statusOutput([
            "configuration_state": state, "configured": false,
        ]))
        #expect(report.configuration.rawValue == state)
    }
}

@Test func remoteStatusRejectsContradictionsVersionsAndInvalidIdentities() throws {
    for fields: [String: Any] in [
        ["schema_version": 2], ["schema_version": 1.5],
        ["configuration_state": "unknown"], ["configured": false],
        ["configuration_state": "unreadable"], ["configuration_state": "absent", "configured": false],
        ["managed_uid": -1], ["managed_uid": 4_294_967_296 as UInt64],
        ["target_id": ""], ["target_id": NSNull()],
        ["release_id": "latest"], ["release_commit": "development"],
        ["release_commit": String(repeating: "A", count: 40)],
    ] {
        let output = try statusOutput(fields)
        #expect(throws: SSHProbeFailure.invalidOutput) { try RemoteInstallationStatus.parse(output) }
    }
}

@Test func remoteStatusNeverTreatsSSHFailureOrMalformedOutputAsFreshInstall() throws {
    for code: Int32 in [1, 127, 255] {
        let output = try statusOutput(status: code)
        #expect(throws: SSHProbeFailure.unavailable) { try RemoteInstallationStatus.parse(output) }
    }
    for bytes in [Data(), Data([0xff]), Data("{}".utf8),
                  Data("{\"ok\":false,\"error\":\"fixture\"}".utf8),
                  Data(repeating: 32, count: 16_385)] {
        #expect(throws: SSHProbeFailure.invalidOutput) {
            try RemoteInstallationStatus.parse(SSHProbeOutput(status: 0, stdout: bytes))
        }
    }
}
