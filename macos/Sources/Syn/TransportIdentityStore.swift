import Darwin
import Foundation
import Security

@_silgen_name("flock")
private func synFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

struct TransportIdentity: Equatable, Sendable {
    let label: String
    let certificatePEM: Data
}

enum TransportIdentityStoreError: Error, LocalizedError, Equatable {
    case invalidTargetID
    case labelCollision(String)
    case invalidGeneratedIdentity
    case renewalRequired(String)
    case rollbackFailed
    case opensslFailed
    case keychain(OSStatus)
    case localSetupFailed

    var errorDescription: String? {
        switch self {
        case .invalidTargetID:
            "The target identifier is invalid."
        case let .labelCollision(label):
            "Keychain already contains a different identity named \(label)."
        case .invalidGeneratedIdentity:
            "Syn could not create a valid client identity."
        case let .renewalRequired(label):
            "The client identity \(label) has expired or needs renewal before this target can reconnect."
        case .rollbackFailed:
            "Syn could not remove an incomplete client identity from Keychain."
        case .opensslFailed:
            "Syn could not create the client certificate."
        case let .keychain(status):
            "Keychain operation failed (\(status))."
        case .localSetupFailed:
            "Syn could not prepare the client identity."
        }
    }
}

struct TransportIdentityMaterial: Equatable, Sendable {
    let certificateDER: Data
    let commonName: String?
    let extendedKeyUsageOIDs: [Data]
    let certificatePublicKey: Data?
    let identityPublicKey: Data?
    let isP256: Bool
    let notBefore: Date?
    let notAfter: Date?
}

protocol TransportIdentityBackend: AnyObject, Sendable {
    func identities(label: String) throws -> [TransportIdentityMaterial]
    func createIdentity(label: String) throws -> TransportIdentityMaterial
    func deleteIdentity(label: String, certificateDER: Data) throws
}

final class TransportIdentityStore: Sendable {
    static let renewalMargin: TimeInterval = 30 * 24 * 60 * 60
    private let backend: any TransportIdentityBackend
    private let now: @Sendable () -> Date

    init(
        backend: any TransportIdentityBackend = MacTransportIdentityBackend(),
        now: @escaping @Sendable () -> Date = { .now }
    ) {
        self.backend = backend
        self.now = now
    }

    func existingIdentity(for targetID: String) throws -> TransportIdentity? {
        let label = try Self.label(for: targetID)
        return try existingIdentity(label: label)
    }

    private func existingIdentity(label: String) throws -> TransportIdentity? {
        let matches = try backend.identities(label: label)
        guard matches.count <= 1 else {
            throw TransportIdentityStoreError.labelCollision(label)
        }
        guard let material = matches.first else { return nil }
        guard Self.validBinding(material, label: label) else {
            throw TransportIdentityStoreError.labelCollision(label)
        }
        guard Self.validDates(material, now: now()) else {
            throw TransportIdentityStoreError.renewalRequired(label)
        }
        return TransportIdentity(label: label, certificatePEM: Self.pem(for: material.certificateDER))
    }

    func identity(for targetID: String) throws -> TransportIdentity {
        let label = try Self.label(for: targetID)
        return try Self.withCreationLock(targetID: targetID) {
            if let existing = try existingIdentity(label: label) { return existing }
            let created = try backend.createIdentity(label: label)
            do {
                guard Self.valid(created, label: label, now: now()) else {
                    throw TransportIdentityStoreError.invalidGeneratedIdentity
                }
                let installed = try backend.identities(label: label)
                guard installed.count == 1, let material = installed.first,
                      Self.valid(material, label: label, now: now()),
                      material.certificateDER == created.certificateDER else {
                    throw TransportIdentityStoreError.labelCollision(label)
                }
                return TransportIdentity(label: label, certificatePEM: Self.pem(for: material.certificateDER))
            } catch {
                do { try backend.deleteIdentity(label: label, certificateDER: created.certificateDER) }
                catch { throw TransportIdentityStoreError.rollbackFailed }
                throw error
            }
        }
    }

    static func valid(_ material: TransportIdentityMaterial, label: String, now: Date = .now) -> Bool {
        validBinding(material, label: label) && validDates(material, now: now)
    }

    static func validBinding(_ material: TransportIdentityMaterial, label: String) -> Bool {
        let clientAuthOID = Data([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])
        guard let notBefore = material.notBefore, let notAfter = material.notAfter else { return false }
        return !material.certificateDER.isEmpty
            && material.certificateDER.count <= 16 * 1024
            && material.commonName == label
            && material.extendedKeyUsageOIDs == [clientAuthOID]
            && material.isP256
            && material.certificatePublicKey?.isEmpty == false
            && material.certificatePublicKey == material.identityPublicKey
            && notBefore < notAfter
    }

    static func validDates(_ material: TransportIdentityMaterial, now: Date) -> Bool {
        guard let notBefore = material.notBefore, let notAfter = material.notAfter else { return false }
        return notBefore <= now && notAfter > now.addingTimeInterval(renewalMargin)
    }

    static func label(for targetID: String) throws -> String {
        guard !targetID.isEmpty, targetID.utf8.count <= 128,
              targetID.utf8.allSatisfy({ byte in
                  (48...57).contains(byte) || (65...90).contains(byte)
                      || (97...122).contains(byte) || byte == 45 || byte == 95
              }) else {
            throw TransportIdentityStoreError.invalidTargetID
        }
        return "Syn \(targetID) transport"
    }

    static func pem(for certificateDER: Data) -> Data {
        let body = certificateDER.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return Data("-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n".utf8)
    }

    private static func withCreationLock<T>(targetID: String, _ body: () throws -> T) throws -> T {
        let path = "/private/tmp/org.syn-approvals.\(getuid()).transport-\(targetID).lock"
        let descriptor = Darwin.open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw TransportIdentityStoreError.localSetupFailed }
        defer { _ = Darwin.close(descriptor) }
        var info = stat()
        guard Darwin.fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              Darwin.fchmod(descriptor, 0o600) == 0,
              synFlock(descriptor, LOCK_EX) == 0 else {
            throw TransportIdentityStoreError.localSetupFailed
        }
        defer { _ = synFlock(descriptor, LOCK_UN) }
        return try body()
    }
}

final class MacTransportIdentityBackend: TransportIdentityBackend, @unchecked Sendable {
    func identities(label: String) throws -> [TransportIdentityMaterial] {
        let certificates = try Self.certificates(label: label)
        guard certificates.count <= 1 else { throw TransportIdentityStoreError.labelCollision(label) }
        return try certificates.map(Self.material)
    }

    private static func certificates(label: String) throws -> [SecCertificate] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: label,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnRef: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let certificates = result as? [SecCertificate] else {
            throw TransportIdentityStoreError.keychain(status)
        }
        return certificates
    }

    func createIdentity(label: String) throws -> TransportIdentityMaterial {
        let package = try Self.generatedPackage(label: label)
        try Self.importIdentity(container: package.container, password: package.password)
        return package.material
    }

    func deleteIdentity(label: String, certificateDER: Data) throws {
        let certificates = try Self.certificates(label: label).filter {
            SecCertificateCopyData($0) as Data == certificateDER
        }
        guard certificates.count <= 1 else { throw TransportIdentityStoreError.labelCollision(label) }
        guard let certificate = certificates.first else { return }
        var identity: SecIdentity?
        var privateKey: SecKey?
        if SecIdentityCreateWithCertificate(nil, certificate, &identity) == errSecSuccess,
           let identity {
            _ = SecIdentityCopyPrivateKey(identity, &privateKey)
        }
        if let privateKey {
            let status = SecItemDelete([
                kSecClass: kSecClassKey,
                kSecValueRef: privateKey,
            ] as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw TransportIdentityStoreError.keychain(status)
            }
        }
        let status = SecItemDelete([
            kSecClass: kSecClassCertificate,
            kSecValueRef: certificate,
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TransportIdentityStoreError.keychain(status)
        }
    }

    static func connectionIdentity(label: String, now: Date = .now) throws -> SecIdentity? {
        let certificates = try certificates(label: label)
        guard certificates.count <= 1 else { throw TransportIdentityStoreError.labelCollision(label) }
        let materials = try certificates.map(material)
        guard let selected = materials.first, let certificate = certificates.first else { return nil }
        guard TransportIdentityStore.validBinding(selected, label: label) else {
            throw TransportIdentityStoreError.labelCollision(label)
        }
        guard TransportIdentityStore.validDates(selected, now: now) else {
            throw TransportIdentityStoreError.renewalRequired(label)
        }
        var identity: SecIdentity?
        guard SecIdentityCreateWithCertificate(nil, certificate, &identity) == errSecSuccess,
              let identity else { return nil }
        return identity
    }

    private struct GeneratedPackage {
        let material: TransportIdentityMaterial
        let container: Data
        let password: String
    }

    static func generatedMaterialForTesting(label: String) throws -> TransportIdentityMaterial {
        try generatedPackage(label: label).material
    }

    private static func generatedPackage(label: String) throws -> GeneratedPackage {
        var key = try runOpenSSL([
            "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-pkeyopt", "ec_param_enc:named_curve",
        ])
        defer { key.resetBytes(in: key.indices) }
        let certificate = try runOpenSSL([
            "req", "-x509", "-new", "-key", "/dev/stdin",
            "-sha256", "-days", "365", "-nodes", "-subj", "/CN=\(label)",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=clientAuth",
        ], standardInput: key)
        let keyPublic = try runOpenSSL(["pkey", "-pubout"], standardInput: key)
        let certificatePublic = try runOpenSSL(["x509", "-pubkey", "-noout"], standardInput: certificate)
        let certificateDER = try runOpenSSL(["x509", "-outform", "DER"], standardInput: certificate)
        var generated = try Self.certificateMaterial(certificateDER: certificateDER, identityPublicKey: nil)
        generated = TransportIdentityMaterial(
            certificateDER: generated.certificateDER,
            commonName: generated.commonName,
            extendedKeyUsageOIDs: generated.extendedKeyUsageOIDs,
            certificatePublicKey: try Self.pemDER(certificatePublic, type: "PUBLIC KEY"),
            identityPublicKey: try Self.pemDER(keyPublic, type: "PUBLIC KEY"),
            isP256: generated.isP256,
            notBefore: generated.notBefore,
            notAfter: generated.notAfter
        )
        guard TransportIdentityStore.valid(generated, label: label) else {
            throw TransportIdentityStoreError.invalidGeneratedIdentity
        }

        var passwordBytes = [UInt8](repeating: 0, count: 32)
        let randomStatus = passwordBytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw TransportIdentityStoreError.localSetupFailed
        }
        let password = passwordBytes.map { String(format: "%02x", $0) }.joined()
        defer {
            _ = passwordBytes.withUnsafeMutableBytes {
                $0.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }
        let container = try Self.runOpenSSLWithAdditionalInput([
            "pkcs12", "-export", "-name", label,
            "-in", "/dev/stdin", "-inkey", "/dev/fd/3",
            "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1",
            "-passout", "fd:4",
        ], standardInput: certificate, additionalInput: key, passwordInput: Data(password.utf8))
        return GeneratedPackage(material: generated, container: container, password: password)
    }

    private static func material(_ certificate: SecCertificate) throws -> TransportIdentityMaterial {
        let der = SecCertificateCopyData(certificate) as Data
        var identityPublicKey: Data?
        var identity: SecIdentity?
        if SecIdentityCreateWithCertificate(nil, certificate, &identity) == errSecSuccess,
           let identity {
            var privateKey: SecKey?
            if SecIdentityCopyPrivateKey(identity, &privateKey) == errSecSuccess,
               let privateKey, let publicKey = SecKeyCopyPublicKey(privateKey) {
                identityPublicKey = externalRepresentation(publicKey)
            }
        }
        return try certificateMaterial(certificateDER: der, identityPublicKey: identityPublicKey)
    }

    private static func certificateMaterial(
        certificateDER: Data,
        identityPublicKey: Data?
    ) throws -> TransportIdentityMaterial {
        guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData),
              let publicKey = SecCertificateCopyKey(certificate) else {
            throw TransportIdentityStoreError.invalidGeneratedIdentity
        }
        var commonName: CFString?
        let commonNameStatus = SecCertificateCopyCommonName(certificate, &commonName)
        let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any]
        let keyType = attributes?[kSecAttrKeyType] as CFTypeRef?
        let keySize = attributes?[kSecAttrKeySizeInBits] as? Int
        let isP256 = keyType.map { CFEqual($0, kSecAttrKeyTypeECSECPrimeRandom) } == true && keySize == 256
        return TransportIdentityMaterial(
            certificateDER: certificateDER,
            commonName: commonNameStatus == errSecSuccess ? commonName as String? : nil,
            extendedKeyUsageOIDs: extendedKeyUsageOIDs(certificate),
            certificatePublicKey: externalRepresentation(publicKey),
            identityPublicKey: identityPublicKey,
            isP256: isP256,
            notBefore: certificateDate(certificate, oid: kSecOIDX509V1ValidityNotBefore),
            notAfter: certificateDate(certificate, oid: kSecOIDX509V1ValidityNotAfter)
        )
    }

    private static func extendedKeyUsageOIDs(_ certificate: SecCertificate) -> [Data] {
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(
            certificate, [kSecOIDExtendedKeyUsage] as CFArray, &error
        ) as? [CFString: Any],
              let property = values[kSecOIDExtendedKeyUsage] as? [CFString: Any],
              let usages = property[kSecPropertyKeyValue] as? [Data] else { return [] }
        return usages
    }

    private static func certificateDate(_ certificate: SecCertificate, oid: CFString) -> Date? {
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(
            certificate, [oid] as CFArray, &error
        ) as? [CFString: Any],
              let property = values[oid] as? [CFString: Any] else { return nil }
        if let date = property[kSecPropertyKeyValue] as? Date { return date }
        if let seconds = property[kSecPropertyKeyValue] as? NSNumber {
            return Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
        }
        return nil
    }

    private static func externalRepresentation(_ key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        return SecKeyCopyExternalRepresentation(key, &error) as Data?
    }

    private static func pemDER(_ pem: Data, type: String) throws -> Data {
        guard let text = String(data: pem, encoding: .utf8) else {
            throw TransportIdentityStoreError.invalidGeneratedIdentity
        }
        let begin = "-----BEGIN \(type)-----"
        let end = "-----END \(type)-----"
        guard text.components(separatedBy: begin).count == 2,
              text.components(separatedBy: end).count == 2,
              let start = text.range(of: begin)?.upperBound,
              let finish = text.range(of: end)?.lowerBound,
              start <= finish else {
            throw TransportIdentityStoreError.invalidGeneratedIdentity
        }
        let body = text[start..<finish].filter { !$0.isWhitespace }
        guard let der = Data(base64Encoded: String(body)), !der.isEmpty else {
            throw TransportIdentityStoreError.invalidGeneratedIdentity
        }
        return der
    }

    private static func runOpenSSL(_ arguments: [String], standardInput: Data? = nil) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let input = standardInput.map { _ in Pipe() }
        if let input { process.standardInput = input }
        do {
            try process.run()
            if let input, let standardInput {
                try input.fileHandleForWriting.write(contentsOf: standardInput)
                try input.fileHandleForWriting.close()
            }
            let result = try output.fileHandleForReading.readToEnd() ?? Data()
            process.waitUntilExit()
            guard result.count <= 64 * 1024,
                  process.terminationReason == .exit,
                  process.terminationStatus == 0 else {
                throw TransportIdentityStoreError.opensslFailed
            }
            return result
        } catch {
            throw TransportIdentityStoreError.opensslFailed
        }
    }

    private static func runOpenSSLWithAdditionalInput(
        _ arguments: [String], standardInput: Data, additionalInput: Data, passwordInput: Data
    ) throws -> Data {
        var input = [Int32]([-1, -1])
        var additional = [Int32]([-1, -1])
        var password = [Int32]([-1, -1])
        var output = [Int32]([-1, -1])
        guard Darwin.pipe(&input) == 0, Darwin.pipe(&additional) == 0,
              Darwin.pipe(&password) == 0, Darwin.pipe(&output) == 0 else {
            for descriptor in input + additional + password + output where descriptor >= 0 {
                _ = Darwin.close(descriptor)
            }
            throw TransportIdentityStoreError.localSetupFailed
        }
        defer {
            for descriptor in input + additional + password + output where descriptor >= 0 {
                _ = Darwin.close(descriptor)
            }
        }
        guard writeAll(standardInput, to: input[1]),
              writeAll(additionalInput, to: additional[1]),
              writeAll(passwordInput, to: password[1]) else {
            throw TransportIdentityStoreError.localSetupFailed
        }
        _ = Darwin.close(input[1]); input[1] = -1
        _ = Darwin.close(additional[1]); additional[1] = -1
        _ = Darwin.close(password[1]); password[1] = -1
        let null = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        guard null >= 0 else { throw TransportIdentityStoreError.localSetupFailed }
        defer { _ = Darwin.close(null) }

        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw TransportIdentityStoreError.localSetupFailed
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        for (source, destination) in [
            (input[0], STDIN_FILENO),
            (additional[0], 3),
            (password[0], 4),
            (output[1], STDOUT_FILENO),
            (null, STDERR_FILENO),
        ] {
            guard posix_spawn_file_actions_adddup2(&actions, source, Int32(destination)) == 0 else {
                throw TransportIdentityStoreError.localSetupFailed
            }
        }
        for descriptor in input + additional + password + output + [null]
        where descriptor > STDERR_FILENO && descriptor != 3 && descriptor != 4 {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else {
                throw TransportIdentityStoreError.localSetupFailed
            }
        }

        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw TransportIdentityStoreError.localSetupFailed
        }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw TransportIdentityStoreError.localSetupFailed
        }

        let duplicatedArguments = (["/usr/bin/openssl"] + arguments).map { strdup($0) }
        guard duplicatedArguments.allSatisfy({ $0 != nil }) else {
            for value in duplicatedArguments { free(value) }
            throw TransportIdentityStoreError.localSetupFailed
        }
        defer { for value in duplicatedArguments { free(value) } }
        var argv = duplicatedArguments + [nil]
        let environmentStrings: [String] = ["LC_ALL=C", "LANG=C"]
        let duplicatedEnvironment = environmentStrings.map { strdup($0) }
        guard duplicatedEnvironment.allSatisfy({ $0 != nil }) else {
            for value in duplicatedEnvironment { free(value) }
            throw TransportIdentityStoreError.localSetupFailed
        }
        defer { for value in duplicatedEnvironment { free(value) } }
        var environment = duplicatedEnvironment + [nil]
        var processID: pid_t = 0
        let spawnStatus = "/usr/bin/openssl".withCString { executable in
            argv.withUnsafeMutableBufferPointer { argvBuffer in
                environment.withUnsafeMutableBufferPointer { environmentBuffer in
                    posix_spawn(
                        &processID, executable, &actions, &attributes,
                        argvBuffer.baseAddress!, environmentBuffer.baseAddress!
                    )
                }
            }
        }
        guard spawnStatus == 0, processID > 1 else { throw TransportIdentityStoreError.opensslFailed }
        _ = Darwin.close(input[0]); input[0] = -1
        _ = Darwin.close(additional[0]); additional[0] = -1
        _ = Darwin.close(password[0]); password[0] = -1
        _ = Darwin.close(output[1]); output[1] = -1

        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(output[0], $0.baseAddress, $0.count)
            }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw TransportIdentityStoreError.opensslFailed }
            if count == 0 { break }
            guard result.count + count <= 64 * 1024 else { throw TransportIdentityStoreError.opensslFailed }
            result.append(contentsOf: buffer.prefix(count))
        }
        var childStatus: Int32 = 0
        while Darwin.waitpid(processID, &childStatus, 0) < 0 {
            if errno == EINTR { continue }
            throw TransportIdentityStoreError.opensslFailed
        }
        guard childStatus == 0 else { throw TransportIdentityStoreError.opensslFailed }
        return result
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) -> Bool {
        data.withUnsafeBytes { bytes in
            guard var base = bytes.baseAddress else { return data.isEmpty }
            var remaining = bytes.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, base, remaining)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { return false }
                remaining -= written
                base = base.advanced(by: written)
            }
            return true
        }
    }

    private static func importIdentity(container: Data, password: String) throws {
        let appPath = Bundle.main.bundleURL.path
        guard Bundle.main.bundleURL.pathExtension == "app" else {
            throw TransportIdentityStoreError.localSetupFailed
        }
        var trustedApplication: SecTrustedApplication?
        var status = try legacyTrustedApplicationCreate(path: appPath, result: &trustedApplication)
        guard status == errSecSuccess, let trustedApplication else {
            throw TransportIdentityStoreError.keychain(status)
        }
        var access: SecAccess?
        status = try legacyAccessCreate(
            descriptor: "Syn transport identity" as CFString,
            trustedApplications: [trustedApplication] as CFArray,
            result: &access
        )
        guard status == errSecSuccess, let access else {
            throw TransportIdentityStoreError.keychain(status)
        }
        var keychain: SecKeychain?
        status = try legacyKeychainCopyDefault(result: &keychain)
        guard status == errSecSuccess, let keychain else {
            throw TransportIdentityStoreError.keychain(status)
        }

        var format = SecExternalFormat.formatPKCS12
        var itemType = SecExternalItemType.itemTypeAggregate
        var parameters = SecItemImportExportKeyParameters()
        parameters.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
        let passphrase = password as CFString
        let keyAttributes = [kSecAttrIsPermanent, kSecAttrIsSensitive] as CFArray
        parameters.passphrase = Unmanaged.passUnretained(passphrase)
        parameters.accessRef = Unmanaged.passUnretained(access)
        parameters.keyAttributes = Unmanaged.passUnretained(keyAttributes)
        status = withExtendedLifetime((passphrase, access, keyAttributes)) {
            SecItemImport(
                container as CFData, "p12" as CFString, &format, &itemType, [],
                &parameters, keychain, nil
            )
        }
        guard status == errSecSuccess else {
            throw TransportIdentityStoreError.keychain(status)
        }
    }
}

// These Security.framework entry points are still the only API that lets an
// imported private key carry a per-application ACL. Apple marks the Swift imports
// deprecated along with the broader legacy Keychain API, so resolve just these
// stable C symbols dynamically and keep the compatibility boundary in one place.
private func withSecuritySymbol<T, Result>(
    _ name: StaticString,
    as type: T.Type,
    _ body: (T) -> Result
) throws -> Result {
    guard let handle = dlopen(
        "/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL
    ) else {
        throw TransportIdentityStoreError.localSetupFailed
    }
    defer { dlclose(handle) }
    guard let symbol = name.withUTF8Buffer({ buffer -> UnsafeMutableRawPointer? in
              guard let base = buffer.baseAddress else { return nil }
              return base.withMemoryRebound(to: CChar.self, capacity: buffer.count) {
                  dlsym(handle, $0)
              }
          }) else {
        throw TransportIdentityStoreError.localSetupFailed
    }
    return body(unsafeBitCast(symbol, to: type))
}

private func legacyTrustedApplicationCreate(
    path: String,
    result: inout SecTrustedApplication?
) throws -> OSStatus {
    typealias Function = @convention(c) (
        UnsafePointer<CChar>?, UnsafeMutablePointer<SecTrustedApplication?>?
    ) -> OSStatus
    return try withSecuritySymbol("SecTrustedApplicationCreateFromPath", as: Function.self) { function in
        path.withCString { function($0, &result) }
    }
}

private func legacyAccessCreate(
    descriptor: CFString,
    trustedApplications: CFArray,
    result: inout SecAccess?
) throws -> OSStatus {
    typealias Function = @convention(c) (
        CFString, CFArray?, UnsafeMutablePointer<SecAccess?>?
    ) -> OSStatus
    return try withSecuritySymbol("SecAccessCreate", as: Function.self) { function in
        function(descriptor, trustedApplications, &result)
    }
}

private func legacyKeychainCopyDefault(result: inout SecKeychain?) throws -> OSStatus {
    typealias Function = @convention(c) (
        UnsafeMutablePointer<SecKeychain?>?
    ) -> OSStatus
    return try withSecuritySymbol("SecKeychainCopyDefault", as: Function.self) { function in
        function(&result)
    }
}
