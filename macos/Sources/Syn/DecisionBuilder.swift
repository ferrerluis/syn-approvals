import CryptoKit
import Foundation

enum DecisionBuilder {
    // Keychain and system authentication may block. Never block the main actor:
    // expiry, cancellation, and Deny must continue to be processed meanwhile.
    static func sign(
        request: VerifiedApprovalRequest,
        approve: Bool,
        reason: String,
        signer: any DecisionSigning,
        cancellation: ApprovalCancellation = ApprovalCancellation()
    ) async throws -> Data {
        try await Task.detached {
            let publicKey = try approve ? signer.approvalPublicKey() : signer.denialPublicKey()
            let keyID = Data(SHA256.hash(data: publicKey))
            let payload = try SynProtocol.decisionPayload(request: request, approve: approve, approverKeyID: keyID)
            let header = try SynProtocol.protectedHeader(keyID: keyID)
            let input = try SynProtocol.signatureStructure(protected: header, payload: payload)
            let signed = try approve
                ? signer.signApproval(payload: input, reason: reason, cancellation: cancellation)
                : signer.signDenial(payload: input)
            guard signed.keyID == keyID else { throw SynProtocolError.invalid("decision key changed unexpectedly") }
            return try SynProtocol.coseSign1(payload: payload, keyID: keyID, signature: signed.signature)
        }.value
    }
}
