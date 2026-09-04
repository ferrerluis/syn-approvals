import CryptoKit
import Foundation
import Security
import Testing
@testable import Syn

@Test func pinnedTrustRejectsWrongPinWrongHostAndExpiredCertificate() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("syn-tls-test-\(UUID())")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let key = directory.appendingPathComponent("test-key.pem")
    let certificate = directory.appendingPathComponent("test-cert.pem")
    let der = directory.appendingPathComponent("test-cert.der")
    try openssl([
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-pkeyopt", "ec_param_enc:named_curve",
        "-sha256", "-days", "1", "-nodes", "-subj", "/CN=syn-test.example",
        "-addext", "subjectAltName=DNS:syn-test.example",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature",
        "-addext", "extendedKeyUsage=serverAuth",
        "-keyout", key.path, "-out", certificate.path,
    ])
    try openssl(["x509", "-in", certificate.path, "-outform", "der", "-out", der.path])
    let data = try Data(contentsOf: der)
    let pin = Data(SHA256.hash(data: data)).hex
    let cert = try #require(SecCertificateCreateWithData(nil, data as CFData))
    func trust() throws -> SecTrust {
        var value: SecTrust?
        #expect(SecTrustCreateWithCertificates(cert, SecPolicyCreateSSL(true, "syn-test.example" as CFString), &value) == errSecSuccess)
        return try #require(value)
    }
    let valid = try trust()
    let accepted = TargetConnection.verifyTrust(valid, hostname: "syn-test.example", pin: pin)
    var trustError: CFError?
    _ = SecTrustEvaluateWithError(valid, &trustError)
    #expect(accepted, "Trust failure: \(String(describing: trustError))")
    #expect(!TargetConnection.verifyTrust(try trust(), hostname: "syn-test.example", pin: String(repeating: "0", count: 64)))
    #expect(!TargetConnection.verifyTrust(try trust(), hostname: "wrong.example", pin: pin))
    let expired = try trust()
    #expect(SecTrustSetVerifyDate(expired, Date.now.addingTimeInterval(172_800) as CFDate) == errSecSuccess)
    #expect(!TargetConnection.verifyTrust(expired, hostname: "syn-test.example", pin: pin))
}

private func openssl(_ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    process.arguments = arguments
    // Generated key material and OpenSSL output are never test snapshots/logs.
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    #expect(process.terminationStatus == 0)
}
