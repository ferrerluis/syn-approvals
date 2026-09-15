import Foundation
import Testing
@testable import Syn

private actor ConnectionRecorder {
    private(set) var sentBodies: [Data] = []

    func send(_ message: WireMessage) {
        sentBodies.append(message.body)
    }
}

@Test func updateApprovalsUseVerifiedProvisionalConnectionInsteadOfStoppedSavedConnection() async throws {
    let saved = ConnectionRecorder()
    let provisional = ConnectionRecorder()
    let approvalBodies = [Data("activation".utf8), Data("completion".utf8)]

    for body in approvalBodies {
        let selected = try SynModel.connectionForSend(
            saved: saved,
            provisional: provisional,
            hasProvisionalTarget: true,
            provisionalIsVerified: true
        )
        await selected.send(.init(kind: .decision, body: body))
    }

    #expect(await saved.sentBodies.isEmpty)
    #expect(await provisional.sentBodies == approvalBodies)
}

@Test func postCommitApprovalUsesSavedConnectionAfterProvisionalRemoval() throws {
    let selected = try SynModel.connectionForSend(
        saved: "committed saved release B",
        provisional: Optional<String>.none,
        hasProvisionalTarget: false,
        provisionalIsVerified: false
    )
    #expect(selected == "committed saved release B")
}

@Test func activeProvisionalApprovalFailsClosedWithoutVerifiedConnection() {
    #expect(throws: URLError.self) {
        try SynModel.connectionForSend(
            saved: "stopped saved release A",
            provisional: "unverified provisional release B",
            hasProvisionalTarget: true,
            provisionalIsVerified: false
        )
    }
    #expect(throws: URLError.self) {
        try SynModel.connectionForSend(
            saved: "stopped saved release A",
            provisional: Optional<String>.none,
            hasProvisionalTarget: true,
            provisionalIsVerified: true
        )
    }
    #expect(throws: URLError.self) {
        try SynModel.connectionForSend(
            saved: Optional<String>.none,
            provisional: Optional<String>.none,
            hasProvisionalTarget: false,
            provisionalIsVerified: false
        )
    }
}
