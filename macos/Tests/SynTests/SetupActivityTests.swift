import Foundation
import Testing
@testable import Syn

@Test func updateDiagnosticsAcceptOnlyExactAllowlistedCompleteLines() {
    var parser = SetupDiagnosticParser()
    #expect(parser.consume(Data("SYN_SETUP_EVENT_V1 compiling_".utf8)).isEmpty)
    #expect(parser.consume(Data("package\n".utf8)) == [.compilingPackage])
    for unsafe in [
        "password=private\n", "SYN_SETUP_EVENT_V1 compiling_package password=private\n",
        "SYN_SETUP_EVENT_V1 unknown\n", "SYN_SETUP_EVENT_V1 package_ready\r\n",
        String(repeating: "x", count: 20_000) + "SYN_SETUP_EVENT_V1 package_ready\n",
    ] { #expect(parser.consume(Data(unsafe.utf8)).isEmpty) }
    for event in SetupDiagnosticEvent.allCases {
        #expect(parser.consume(Data("SYN_SETUP_EVENT_V1 \(event.rawValue)\n".utf8)) == [event])
    }
    #expect(parser.consume(Data([0xff, 0, 10])).isEmpty)
}

@Test func updateActivityResetsBoundsHistoryAndFreezesTerminalTime() {
    let start = Date(timeIntervalSince1970: 1_000)
    var activity = SetupActivity(now: start)
    activity.record(.staging, now: start)
    activity.record(.staging, now: start)
    #expect(activity.entries.count == 1)
    #expect(activity.elapsed(at: start.addingTimeInterval(75)) == "1:15")
    for _ in 0..<100 {
        activity.record(.extractingSource, now: start)
        activity.record(.compilingPackage, now: start)
    }
    #expect(activity.entries.count == 64)
    #expect(Set(activity.entries.map(\.id)).count == 64)
    activity.finish(.completed, now: start.addingTimeInterval(125))
    activity.record(.packageReady)
    #expect(activity.entries.last?.message == "Update completed and verified")
    #expect(activity.elapsed(at: start.addingTimeInterval(999)) == "2:05")
    let fresh = SetupActivity(now: start.addingTimeInterval(130))
    #expect(fresh.entries.isEmpty)
    #expect(fresh.finishedAt == nil)
    for outcome in [SetupActivity.Outcome.failed, .cancelled, .needsMaintenance] {
        var failed = SetupActivity(now: start)
        failed.finish(outcome, now: start.addingTimeInterval(5))
        #expect(failed.elapsed(at: start.addingTimeInterval(999)) == "0:05")
        #expect(failed.entries.count == 1)
    }
}

private actor UpdateEventRecorder {
    var events: [SetupDiagnosticEvent] = []
    func record(_ event: SetupDiagnosticEvent) { events.append(event) }
}

@Test func updateProcessStreamsBeforeExitAndPreservesFinalReply() async throws {
    let events = UpdateEventRecorder()
    let process = SSHProbeProcess(testExecutable: "/bin/sh", timeout: .seconds(5))
    let task = Task {
        try await process.run(arguments: ["-c", "printf 'private diagnostic\\nSYN_SETUP_EVENT_V1 compiling_package\\n' >&2; sleep 1; printf '{\"ok\":true}'; printf 'SYN_SETUP_EVENT_V1 package_ready\\n' >&2"], setupProgress: { await events.record($0) })
    }
    try await Task.sleep(for: .milliseconds(400))
    #expect(await events.events == [.compilingPackage])
    let output = try await task.value
    #expect(output.status == 0)
    #expect(String(decoding: output.stdout, as: UTF8.self) == #"{"ok":true}"#)
    #expect(await events.events == [.compilingPackage, .packageReady])
}
