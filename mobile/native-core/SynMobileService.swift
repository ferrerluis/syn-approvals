import Combine
import Foundation

/// Only this facade crosses the React Native boundary. No keys, wire payloads,
/// signing primitive or arbitrary SSH operation are exposed.
@MainActor
public final class SynMobileService {
    private static var instance: SynMobileService?
    private let model: IOSModel
    private var observer: AnyCancellable?
    private var timer: Timer?
    private var revealed: [String: Set<Int>] = [:]
    public var onStateChanged: (() -> Void)?

    public static func open() throws -> SynMobileService {
        if let instance { return instance }
        let service = try SynMobileService()
        instance = service
        return service
    }

    private init() throws {
        model = try IOSModel()
        observer = model.objectWillChange.sink { [weak self] _ in
            Task { @MainActor in self?.onStateChanged?() }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.model.expire()
                self?.onStateChanged?()
            }
        }
    }

    public func setActive(_ active: Bool) { model.setForeground(active) }
    public func retry() { model.error = nil; model.retry() }
    public func checkHost(_ host: String, port: Int) async {
        model.error = nil; model.machineHost = host; model.machinePort = String(port)
        await model.checkHost()
    }
    public func trustHost() async { await model.trustHost() }
    public func pair() async { await model.connectMobile() }
    public func approve(_ requestID: String) async { await model.approve(requestID) }
    public func deny(_ requestID: String) async { await model.deny(requestID) }
    public func revealArgument(_ requestID: String, index: Int) {
        guard let request = model.pending.first(where: { $0.id == requestID }),
              !request.isExpired, request.arguments.indices.contains(index) else { return }
        revealed[requestID, default: []].insert(index)
        onStateChanged?()
    }

    public func snapshot() throws -> String {
        model.expire()
        revealed = revealed.filter { entry in model.pending.contains { $0.id == entry.key } }
        let targets = model.targets.map { target in
            MobileTarget(id: target.id, name: target.displayName,
                connected: model.connected.contains(target.id))
        }
        let requests = model.pending.map { request in
            MobileRequest(id: request.id, targetID: request.targetID,
                targetName: model.targets.first(where: { $0.id == request.targetID })?.displayName ?? request.targetID,
                executable: SafeDisplay.render(request.executable),
                arguments: request.arguments.enumerated().map { index, data in
                    MobileArgument(index: index,
                        value: SafeDisplay.likelyContainsSecret(data) && !(revealed[request.id]?.contains(index) ?? false)
                            ? nil : SafeDisplay.render(data))
                },
                workingDirectory: SafeDisplay.render(request.workingDirectory),
                invokingUser: request.invokingUser, runAsUser: request.runAsUser,
                expiresAt: request.expiresAt.timeIntervalSince1970 * 1000,
                authenticating: model.authenticating.contains(request.id))
        }
        let state = MobileState(schemaVersion: 1, deviceID: model.deviceID,
            developmentSigner: model.developmentSigner, releaseID: ReleaseIdentity.current.releaseID,
            targets: targets, requests: requests,
            setup: MobileSetup(host: model.machineHost, port: Int(model.machinePort) ?? 22,
                checking: model.checkingHost, fingerprint: model.hostCandidate?.fingerprint,
                bootstrapCommand: model.bootstrapCommand), error: model.error, status: model.status)
        return String(decoding: try JSONEncoder().encode(state), as: UTF8.self)
    }
}

private struct MobileState: Encodable {
    let schemaVersion: Int
    let deviceID: String
    let developmentSigner: Bool
    let releaseID: String
    let targets: [MobileTarget]
    let requests: [MobileRequest]
    let setup: MobileSetup
    let error: String?
    let status: String?
}
private struct MobileTarget: Encodable { let id: String; let name: String; let connected: Bool }
private struct MobileArgument: Encodable { let index: Int; let value: String? }
private struct MobileRequest: Encodable {
    let id: String; let targetID: String; let targetName: String; let executable: String
    let arguments: [MobileArgument]; let workingDirectory: String
    let invokingUser: String; let runAsUser: String; let expiresAt: Double; let authenticating: Bool
}
private struct MobileSetup: Encodable {
    let host: String; let port: Int; let checking: Bool; let fingerprint: String?; let bootstrapCommand: String?
}
