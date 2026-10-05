import CryptoKit
import Foundation

/// Display-only data from a request already verified by the native core.
/// It cannot be converted back into a signing payload or command.
struct MobileReview: Encodable {
    let id: String
    let targetID: String
    let targetName: String
    let targetKeyFingerprint: String?
    let executable: String
    let arguments: [MobileArgument]
    let workingDirectory: String
    let invokingUID: UInt32
    let invokingUser: String
    let runAsUID: UInt32
    let runAsUser: String
    let runAsGroup: String
    let environmentNames: [String]
    let environmentDigest: String
    let riskMarkers: [String]
    let expiresAt: Double
    let authenticating: Bool

    init(request: VerifiedApprovalRequest, target: TargetRecord?, revealed: Set<Int>, authenticating: Bool) {
        id = request.id
        targetID = request.targetID
        let matchedTarget = target.flatMap { $0.id == request.targetID ? $0 : nil }
        targetName = matchedTarget?.displayName ?? request.targetID
        targetKeyFingerprint = matchedTarget?.publicKey.map { Data(SHA256.hash(data: $0.x963Representation)).hex }
        executable = SafeDisplay.render(request.executable)
        arguments = request.arguments.enumerated().map { index, data in
            MobileArgument(index: index,
                value: SafeDisplay.likelyContainsSecret(data) && !revealed.contains(index)
                    ? nil : SafeDisplay.render(data))
        }
        workingDirectory = SafeDisplay.render(request.workingDirectory)
        invokingUID = request.invokingUID
        invokingUser = SafeDisplay.render(Data(request.invokingUser.utf8))
        runAsUID = request.runAsUID
        runAsUser = SafeDisplay.render(Data(request.runAsUser.utf8))
        runAsGroup = SafeDisplay.render(Data(request.runAsGroup.utf8))
        environmentNames = request.environmentNames.map { SafeDisplay.render(Data($0.utf8)) }
        environmentDigest = request.environmentDigest.hex
        riskMarkers = request.riskMarkers.map { SafeDisplay.render(Data($0.utf8)) }
        expiresAt = request.expiresAt.timeIntervalSince1970 * 1000
        self.authenticating = authenticating
    }
}
struct MobileArgument: Encodable { let index: Int; let value: String? }
