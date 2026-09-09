import Foundation
import Testing
@testable import Syn

@Test func releaseMetadataRejectsMalformedIdentifiers() throws {
    let valid = "{\"schema_version\":1,\"release_id\":\"20260905123000\",\"commit\":\"" + String(repeating: "a", count: 40) + "\"}"
    #expect(try ReleaseIdentity.load(Data(valid.utf8)).releaseID == "20260905123000")
    for malformed in [valid.replacingOccurrences(of: "20260905123000", with: "20260905"),
                      valid.replacingOccurrences(of: "20260905123000", with: "２０２６０９０５１２３０００"),
                      valid.replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":2"),
                      valid.replacingOccurrences(of: String(repeating: "a", count: 40), with: "unknown")] {
        #expect(throws: (any Error).self) { _ = try ReleaseIdentity.load(Data(malformed.utf8)) }
    }
}

@Test func releaseIdentityRequiresARealUtcTimestamp() {
    for value in ["00000000000000", "20260228235959", "20280229000000"] {
        #expect(ReleaseIdentity.validID(value))
    }
    for value in ["20250901000000", "20260229000000", "20261301000000",
                  "20260931235959", "20260901240000", "20260901235960"] {
        #expect(!ReleaseIdentity.validID(value))
    }
}
