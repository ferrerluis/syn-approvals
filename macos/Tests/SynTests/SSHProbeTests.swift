import Darwin
import Foundation
import Testing
@testable import Syn

private actor ProbeFixture: SSHProbeRunning {
    private var replies: [SSHProbeOutput]
    private(set) var calls = 0

    init(_ replies: [SSHProbeOutput]) { self.replies = replies }

    func run(settings: SSHConnectionSettings, operation: SSHReadOnlyOperation) async throws -> SSHProbeOutput {
        calls += 1
        guard !replies.isEmpty else { throw SSHProbeFailure.invalidOutput }
        return replies.removeFirst()
    }
}

private let probeSettings = SSHConnectionSettings(hostname: "machine.example", username: "developer", port: nil)

@Test func sshPlatformProbeRequiresSupportedOSAndArchitecture() async throws {
    let fixture = ProbeFixture([
        SSHProbeOutput(status: 0, stdout: Data("Linux aarch64\n".utf8)),
        SSHProbeOutput(status: 0, stdout: Data("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"26.04\"\n".utf8)),
    ])
    try await SSHSetupProbe(runner: fixture).checkPlatform(probeSettings)
    #expect(await fixture.calls == 2)
}

@Test func sshPlatformProbeStopsAfterFailedFirstCheck() async {
    for reply in [
        SSHProbeOutput(status: 255, stdout: Data("remote banner".utf8)),
        SSHProbeOutput(status: 0, stdout: Data("Linux x86_64\n".utf8)),
        SSHProbeOutput(status: 0, stdout: Data("Darwin arm64\n".utf8)),
    ] {
        let fixture = ProbeFixture([reply])
        await #expect(throws: SSHProbeFailure.self) {
            try await SSHSetupProbe(runner: fixture).checkPlatform(probeSettings)
        }
        #expect(await fixture.calls == 1)
    }
}

@Test func sshPlatformProbeRejectsInvalidDestinationBeforeConnection() async {
    let fixture = ProbeFixture([])
    await #expect(throws: SynProtocolError.self) {
        try await SSHSetupProbe(runner: fixture).checkPlatform(
            SSHConnectionSettings(hostname: "bad;hostname", username: "developer", port: nil)
        )
    }
    #expect(await fixture.calls == 0)
}

@Test func osReleaseIsParsedAsDataNeverShellInput() throws {
    try SSHSetupProbe.validateOperatingSystem(Data("ID=\"ubuntu\"\nVERSION_ID=26.04\n".utf8))
    for value in [
        "ID=ubuntu\nVERSION_ID=26.04\nID=debian\n",
        "ID=ubuntu\nVERSION_ID=24.04\n",
        "ID=$(echo ubuntu)\nVERSION_ID=26.04\n",
        "ID=ubuntu\nVERSION_ID=26.04\u{0}",
        "VERSION_ID=26.04\n",
        String(repeating: "a", count: 16_385),
    ] {
        #expect(throws: SSHProbeFailure.self) {
            try SSHSetupProbe.validateOperatingSystem(Data(value.utf8))
        }
    }
    #expect(throws: SSHProbeFailure.self) {
        try SSHSetupProbe.validateOperatingSystem(Data([0xff]))
    }
}

@Test func probeProcessBoundsStandardOutputAndDiagnostics() async throws {
    let process = SSHProbeProcess(testExecutable: "/bin/sh", timeout: .seconds(2))
    let exact = try await process.run(arguments: [
        "-c", "/usr/bin/head -c 65536 /dev/zero", "probe-fixture",
    ])
    #expect(exact.status == 0)
    #expect(exact.stdout.count == 65_536)

    for command in [
        "/usr/bin/head -c 65537 /dev/zero",
        "/usr/bin/head -c 16385 /dev/zero >&2",
    ] {
        do {
            _ = try await process.run(arguments: ["-c", command, "probe-fixture"])
            Issue.record("oversized probe output was accepted")
        } catch let failure as SSHProbeFailure {
            #expect(failure == .tooMuchOutput)
        } catch {
            Issue.record("unexpected output-limit error: \(error)")
        }
    }
}

@Test func privateStandardInputIsBoundedAndNeverAppearsInArgumentsOrEnvironment() async throws {
    let process = SSHProbeProcess(testExecutable: "/bin/sh", timeout: .seconds(2))
    let secret = Data("private-admin-value\n".utf8)
    let output = try await process.run(
        arguments: [
            "-c",
            "IFS= read -r value; case \"$0 $* $(env)\" in *private-admin-value*) exit 91;; esac; printf '%s' \"${#value}\"",
            "probe-fixture",
        ],
        privateStandardInput: secret
    )
    #expect(output.status == 0)
    #expect(output.stdout == Data("19".utf8))
    await #expect(throws: SSHProbeFailure.invalidOutput) {
        try await process.run(arguments: [], privateStandardInput: Data(repeating: 1, count: 4_097))
    }
}

@Test func sshFailuresAreClassifiedWithoutExposingRemoteText() {
    let cases: [(String, SSHProbeFailure)] = [
        ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", .changedHostKey),
        ("No ED25519 host key is known for pi and you have requested strict checking.", .unknownHost),
        ("Host key verification failed.", .unknownHost),
        ("user@pi: Permission denied (publickey).", .authenticationNeeded),
        ("connect to host pi port 22: Operation timed out", .unavailable),
    ]
    for (diagnostic, expected) in cases {
        let output = SSHProbeOutput(status: 255, stdout: Data(), diagnostics: Data(diagnostic.utf8))
        #expect(SSHProbeFailure.classify(output) == expected)
        #expect(expected.localizedDescription != diagnostic)
    }
}

@Test func cancelStopsAndReapsOwnedProbeProcessGroup() async throws {
    let marker = temporaryPIDMarker()
    defer { try? FileManager.default.removeItem(at: marker) }
    let process = SSHProbeProcess(testExecutable: "/bin/sh", timeout: .seconds(5))
    let task = Task {
        try await process.run(arguments: [
            "-c",
            "trap '' TERM; (trap '' TERM; /bin/sleep 30) & echo \"$$ $!\" > \"$1\"; wait",
            "probe-fixture",
            marker.path,
        ])
    }
    let processIDs = try await recordedProcessIDs(at: marker)
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    try await requireProcessesGone(processIDs)
}

@Test func timeoutStopsAndReapsOwnedProbeProcessGroup() async throws {
    let marker = temporaryPIDMarker()
    defer { try? FileManager.default.removeItem(at: marker) }
    let process = SSHProbeProcess(testExecutable: "/bin/sh", timeout: .milliseconds(100))
    let task = Task {
        try await process.run(arguments: [
            "-c",
            "trap '' TERM; (trap '' TERM; /bin/sleep 30) & echo \"$$ $!\" > \"$1\"; wait",
            "probe-fixture",
            marker.path,
        ])
    }
    let processIDs = try await recordedProcessIDs(at: marker)
    do {
        _ = try await task.value
        Issue.record("hung probe did not time out")
    } catch let failure as SSHProbeFailure {
        #expect(failure == .timedOut)
    } catch {
        Issue.record("unexpected timeout error: \(error)")
    }
    try await requireProcessesGone(processIDs)
}

private func temporaryPIDMarker() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("syn-ssh-probe-\(UUID().uuidString).pids")
}

private func recordedProcessIDs(at marker: URL) async throws -> [pid_t] {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while ContinuousClock.now < deadline {
        if let text = try? String(contentsOf: marker, encoding: .utf8) {
            let processIDs = text.split(whereSeparator: \.isWhitespace).compactMap {
                pid_t(String($0))
            }
            if processIDs.count == 2 { return processIDs }
        }
        try await Task.sleep(for: .milliseconds(10))
    }
    throw SSHProbeFailure.invalidOutput
}

private func requireProcessesGone(_ processIDs: [pid_t]) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while ContinuousClock.now < deadline {
        if processIDs.allSatisfy({ !processExists($0) }) { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(processIDs.allSatisfy({ !processExists($0) }))
}

private func processExists(_ processID: pid_t) -> Bool {
    if kill(processID, 0) == 0 { return true }
    return errno == EPERM
}
