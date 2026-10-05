import CryptoKit
import Foundation
import Security
@preconcurrency import NIOCore
@preconcurrency import NIOPosix
@preconcurrency import NIOSSH

struct MobileHostKey: Error, LocalizedError, Sendable, Equatable {
    let publicKey: String
    var fingerprint: String {
        let encoded = publicKey.split(separator: " ").dropFirst().first.map(String.init) ?? ""
        let bytes = Data(base64Encoded: encoded) ?? Data()
        return "SHA256:" + Data(SHA256.hash(data: bytes)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
    var errorDescription: String? { "Verify the SSH host fingerprint using a trusted source before continuing." }
}

enum MobilePhase: String, Sendable { case cleanup, build, configure, activate, complete }
enum MobileArtifact: String, Sendable { case source, helper, request }
private enum MobileOperation: Sendable {
    case enroll(Data), profile, probe, recover
    case upload(MobileArtifact, URL, String, UInt64)
    case retain(String, String, UInt64)
    case prepare(String, String, String)
    case phase(MobilePhase, String)
    var request: String {
        let prefix = "syn-mobile --protocol-version 1 "
        switch self {
        case .enroll: return prefix + "enroll"
        case .profile: return prefix + "profile"
        case .probe: return prefix + "probe"
        case .recover: return prefix + "recover"
        case let .upload(artifact, _, hash, size): return prefix + "upload \(artifact.rawValue) \(hash) \(size)"
        case let .retain(op, hash, size): return prefix + "retain \(op) \(hash) \(size)"
        case let .prepare(op, request, source): return prefix + "prepare \(op) \(request) \(source)"
        case let .phase(phase, op): return prefix + "\(phase.rawValue) \(op)"
        }
    }
    var input: Data { if case let .enroll(data) = self { data } else { Data() } }
    var timeout: Int64 { if case .phase(.build, _) = self { 1800 } else { 150 } }
}

/// A closed set of setup operations; no arbitrary SSH command is exposed.
final class MobileSSH: @unchecked Sendable {
    private static let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let host: String
    private let port: Int
    private let hostKey: String?
    private let identity: Curve25519.Signing.PrivateKey

    init(host: String, port: Int, hostKey: String?) throws {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]".utf8)
        guard !host.isEmpty, host.utf8.count <= 253, host.first != "-",
              host.utf8.allSatisfy({ allowed.contains($0) }), (1...65535).contains(port) else {
            throw SynProtocolError.invalid("Enter a reachable hostname and SSH port.")
        }
        self.host = host; self.port = port; self.hostKey = hostKey
        identity = try Self.privateKey()
    }

    var publicKey: String { String(openSSHPublicKey: NIOSSHPrivateKey(ed25519Key: identity).publicKey) }

    func inspectHost() async throws -> MobileHostKey {
        let loop = Self.group.next()
        let observed = MobileCompletion<MobileHostKey>(loop: loop)
        let authentication = MobileAuthentication(key: identity)
        let trust = MobileTrust(expected: nil, observed: observed)
        let channel = try await ClientBootstrap(group: Self.group).connectTimeout(.seconds(8))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(NIOSSHHandler(
                        role: .client(.init(userAuthDelegate: authentication, serverAuthDelegate: trust)),
                        allocator: channel.allocator, inboundChildChannelInitializer: nil))
                    try channel.pipeline.syncOperations.addHandler(MobileParentError { _ in
                        observed.resolve(.failure(SynProtocolError.invalid("SSH host verification failed.")))
                    })
                }
            }.connect(host: host, port: port).get()
        defer { channel.close(promise: nil) }
        let timeout = loop.scheduleTask(in: .seconds(8)) {
            observed.resolve(.failure(SynProtocolError.invalid("SSH host verification timed out.")))
            channel.close(promise: nil)
        }
        defer { timeout.cancel() }
        return try await observed.promise.futureResult.get()
    }
    func enroll(_ data: Data) async throws -> Data {
        guard data.count <= 24 * 1024 else { throw SynProtocolError.invalid("Device enrollment is too large.") }
        return try await perform(.enroll(data))
    }
    func profile() async throws -> Data { try await perform(.profile) }
    func probe() async throws -> Data { try await perform(.probe) }
    func recover() async throws -> Data { try await perform(.recover) }
    func upload(_ artifact: MobileArtifact, file: URL, hash: String, size: UInt64) async throws {
        try Self.hex(hash, count: 64)
        guard file.isFileURL, size > 0, size <= 2 * 1024 * 1024 * 1024 else { throw SynProtocolError.invalid("Invalid setup artifact.") }
        _ = try await perform(.upload(artifact, file, hash, size))
    }
    func retain(operation: String, hash: String, size: UInt64) async throws {
        try Self.hex(operation, count: 32); try Self.hex(hash, count: 64)
        guard size > 0, size <= 128 * 1024 * 1024 else { throw SynProtocolError.invalid("Invalid setup helper.") }
        _ = try await perform(.retain(operation, hash, size))
    }
    func prepare(operation: String, requestHash: String, sourceHash: String) async throws {
        try Self.hex(operation, count: 32); try Self.hex(requestHash, count: 64); try Self.hex(sourceHash, count: 64)
        _ = try await perform(.prepare(operation, requestHash, sourceHash))
    }
    func phase(_ phase: MobilePhase, operation: String) async throws -> Data {
        try Self.hex(operation, count: 32)
        return try await perform(.phase(phase, operation))
    }
    private static func hex(_ value: String, count: Int) throws {
        guard value.utf8.count == count, value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw SynProtocolError.invalid("Invalid setup operation identity.")
        }
    }


    private func connect() async throws -> any Channel {
        let authentication = MobileAuthentication(key: identity)
        let trust = MobileTrust(expected: hostKey)
        return try await ClientBootstrap(group: Self.group)
            .connectTimeout(.seconds(8))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let handler = NIOSSHHandler(role: .client(.init(userAuthDelegate: authentication, serverAuthDelegate: trust)),
                        allocator: channel.allocator, inboundChildChannelInitializer: nil)
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }.connect(host: host, port: port).get()
    }

    private func perform(_ operation: MobileOperation) async throws -> Data {
        guard hostKey != nil else { throw SynProtocolError.invalid("Confirm the SSH host fingerprint first.") }
        let channel = try await connect()
        defer { channel.close(promise: nil) }
        let response = MobileCompletion<Data>(loop: channel.eventLoop)
        let childPromise = channel.eventLoop.makePromise(of: (any Channel).self)
        let timeout = channel.eventLoop.scheduleTask(in: .seconds(operation.timeout)) {
            response.resolve(.failure(SynProtocolError.invalid("SSH setup timed out.")))
            channel.close(promise: nil)
        }
        defer { timeout.cancel() }
        channel.eventLoop.execute {
            do {
                let ssh = try channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
                ssh.createChannel(childPromise, channelType: .session) { child, type in
                    guard type == .session else { return child.eventLoop.makeFailedFuture(SynProtocolError.invalid("Unsupported SSH channel.")) }
                    return child.eventLoop.makeCompletedFuture {
                        try child.pipeline.syncOperations.addHandler(MobileResponse(operation: operation, response: response))
                    }
                }
            } catch { childPromise.fail(error) }
        }
        childPromise.futureResult.whenFailure { error in response.resolve(.failure(error)) }
        return try await response.promise.futureResult.get()
    }

    private static func privateKey() throws -> Curve25519.Signing.PrivateKey {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.syn-approvals.SynIOS.Maintenance", kSecAttrAccount: "ssh-key-v1"]
        var read = query; read[kSecReturnData] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(read as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data { return try .init(rawRepresentation: data) }
        guard status == errSecItemNotFound else { throw KeyStoreError.keychain(status) }
        let key = Curve25519.Signing.PrivateKey()
        var write = query
        write[kSecValueData] = key.rawRepresentation
        write[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(write as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeyStoreError.keychain(added) }
        return key
    }
}

private final class MobileAuthentication: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private let key: NIOSSHPrivateKey
    private var attempted = false
    init(key: Curve25519.Signing.PrivateKey) { self.key = NIOSSHPrivateKey(ed25519Key: key) }
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard !attempted, availableMethods.contains(.publicKey) else {
            nextChallengePromise.fail(SynProtocolError.invalid("Authorize this iPhone’s restricted setup key in a trusted administrator terminal."))
            return
        }
        attempted = true
        nextChallengePromise.succeed(.init(username: "root", serviceName: "ssh-connection", offer: .privateKey(.init(privateKey: key))))
    }
}

private final class MobileTrust: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    let expected: String?
    private let observed: MobileCompletion<MobileHostKey>?
    init(expected: String?, observed: MobileCompletion<MobileHostKey>? = nil) { self.expected = expected; self.observed = observed }
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        let observed = String(openSSHPublicKey: hostKey)
        guard let expected else {
            self.observed?.resolve(.success(MobileHostKey(publicKey: observed)))
            validationCompletePromise.fail(MobileHostKey(publicKey: observed)); return
        }
        guard observed == expected else {
            validationCompletePromise.fail(SynProtocolError.invalid("SSH host identity changed. Verify the machine independently.")); return
        }
        validationCompletePromise.succeed(())
    }
}

private final class MobileResponse: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData
    private let operation: MobileOperation
    private var response: MobileCompletion<Data>?
    private var bytes = Data()
    private var exitStatus: Int?
    private var upload: FileHandle?
    private var remaining: UInt64 = 0
    private var sentInput = false
    init(operation: MobileOperation, response: MobileCompletion<Data>) { self.operation = operation; self.response = response }
    func channelActive(context: ChannelHandlerContext) {
        context.triggerUserOutboundEvent(SSHChannelRequestEvent.ExecRequest(command: operation.request, wantReply: true), promise: nil)
        if case let .upload(_, url, _, size) = operation {
            do { upload = try FileHandle(forReadingFrom: url); remaining = size }
            catch { fail(context); return }
        }
        sendNext(context)
    }
    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable { sendNext(context) }
        context.fireChannelWritabilityChanged()
    }
    private var writing = false
    private func sendNext(_ context: ChannelHandlerContext) {
        guard !writing, !sentInput, context.channel.isWritable else { return }
        do {
            let data: Data
            if let upload {
                if remaining == 0 { sentInput = true; try upload.close(); self.upload = nil; context.close(mode: .output, promise: nil); return }
                guard let chunk = try upload.read(upToCount: Int(min(remaining, 64 * 1024))), !chunk.isEmpty else { fail(context); return }
                remaining -= UInt64(chunk.count); data = chunk
            } else { data = operation.input; sentInput = true }
            var buffer = context.channel.allocator.buffer(capacity: data.count); buffer.writeBytes(data)
            writing = true
            let promise = context.eventLoop.makePromise(of: Void.self)
            let bound = NIOLoopBound((self, context), eventLoop: context.eventLoop)
            promise.futureResult.whenComplete { result in
                let (handler, context) = bound.value
                handler.writing = false
                switch result {
                case .failure: handler.fail(context)
                case .success:
                    if handler.sentInput { context.close(mode: .output, promise: nil) }
                    else { handler.sendNext(context) }
                }
            }
            context.writeAndFlush(wrapOutboundOut(.init(type: .channel, data: .byteBuffer(buffer))), promise: promise)
        } catch { fail(context) }
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let incoming = unwrapInboundIn(data)
        guard case let .byteBuffer(buffer) = incoming.data else { fail(context); return }
        guard incoming.type == .channel else { return } // Never include remote stderr or credentials in UI/errors.
        guard bytes.count + buffer.readableBytes <= 64 * 1024 else { fail(context); return }
        bytes.append(contentsOf: buffer.readableBytesView)
    }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let status = event as? SSHChannelRequestEvent.ExitStatus { exitStatus = status.exitStatus }
        else { context.fireUserInboundEventTriggered(event) }
    }
    func channelInactive(context: ChannelHandlerContext) {
        try? upload?.close(); upload = nil
        if let promise = response {
            response = nil
            if exitStatus == 0 { promise.resolve(.success(bytes)) }
            else { promise.resolve(.failure(SynProtocolError.invalid("The machine could not complete device setup. Check the trusted administrator terminal."))) }
        }
        context.fireChannelInactive()
    }
    func errorCaught(context: ChannelHandlerContext, error: Error) { fail(context) }
    private func fail(_ context: ChannelHandlerContext) {
        response?.resolve(.failure(SynProtocolError.invalid("The SSH setup response was rejected."))); response = nil
        context.close(promise: nil)
    }
}

private final class MobileCompletion<Value: Sendable>: @unchecked Sendable {
    let promise: EventLoopPromise<Value>
    private let lock = NSLock()
    private var completed = false
    init(loop: any EventLoop) { promise = loop.makePromise(of: Value.self) }
    func resolve(_ result: Result<Value, Error>) {
        let first = lock.withLock { if completed { return false }; completed = true; return true }
        if first { promise.completeWith(result) }
    }
}
private final class MobileParentError: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    private let failure: @Sendable (Error) -> Void
    init(failure: @escaping @Sendable (Error) -> Void) { self.failure = failure }
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        failure(error); context.close(promise: nil)
    }
}
