// Imports a single transport identity with access restricted to Syn.app.
// The one-use wrapping password is read from stdin, never process arguments.
import Foundation
import Security

func check(_ status: OSStatus) throws {
    guard status == errSecSuccess else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
}

do {
    guard CommandLine.arguments.count == 4 else {
        throw NSError(domain: "SynImport", code: 1)
    }
    let container = URL(fileURLWithPath: CommandLine.arguments[1])
    let app = CommandLine.arguments[2]
    let keychainPath = CommandLine.arguments[3]
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count == 64, let password = String(data: input, encoding: .utf8) else {
        throw NSError(domain: "SynImport", code: 2)
    }
    var trusted: SecTrustedApplication?
    try check(SecTrustedApplicationCreateFromPath(app, &trusted))
    guard let trusted else { throw NSError(domain: "SynImport", code: 3) }
    var access: SecAccess?
    try check(SecAccessCreate("Syn transport identity" as CFString, [trusted] as CFArray, &access))
    guard let access else { throw NSError(domain: "SynImport", code: 4) }
    var keychain: SecKeychain?
    try check(SecKeychainOpen(keychainPath, &keychain))
    var format = SecExternalFormat.formatPKCS12
    var type = SecExternalItemType.itemTypeAggregate
    var parameters = SecItemImportExportKeyParameters()
    parameters.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
    let passphrase = password as CFString
    let attributes = [kSecAttrIsPermanent, kSecAttrIsSensitive] as CFArray
    parameters.passphrase = Unmanaged.passUnretained(passphrase)
    parameters.accessRef = Unmanaged.passUnretained(access)
    parameters.keyAttributes = Unmanaged.passUnretained(attributes)
    try withExtendedLifetime((passphrase, access, attributes)) {
        try check(SecItemImport(
            try Data(contentsOf: container) as CFData, "p12" as CFString,
            &format, &type, [], &parameters, keychain, nil
        ))
    }
    print("Syn transport identity imported into Keychain")
} catch {
    // Do not print paths, input, or NSError userInfo: only a stable category/code.
    let code = (error as NSError).code
    FileHandle.standardError.write(Data("Syn identity import failed (\(code))\n".utf8))
    exit(1)
}
