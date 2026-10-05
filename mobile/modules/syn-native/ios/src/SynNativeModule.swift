import ExpoModulesCore
import SynMobileCore

public final class SynNativeModule: Module {
    public func definition() -> ModuleDefinition {
        Name("SynNative")
        Events("onStateChanged")
        OnCreate { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                do {
                    let service = try SynMobileService.open()
                    service.onStateChanged = { [weak self, weak service] in
                        guard let state = try? service?.snapshot() else { return }
                        self?.sendEvent("onStateChanged", ["state": state])
                    }
                } catch { self.sendEvent("onStateChanged", ["error": "Syn could not open native storage."]) }
            }
        }
        OnDestroy {
            Task { @MainActor in
                guard let service = try? SynMobileService.open() else { return }
                service.onStateChanged = nil
                service.setActive(false)
            }
        }
        AsyncFunction("getState") { () async throws -> String in
            try await SynMobileService.open().snapshot()
        }
        AsyncFunction("setActive") { (active: Bool) async throws in
            try await SynMobileService.open().setActive(active)
        }
        AsyncFunction("retry") { () async throws in try await SynMobileService.open().retry() }
        AsyncFunction("checkHost") { (host: String, port: Int, user: String) async throws in
            try await SynMobileService.open().checkHost(host, port: port, user: user)
        }
        AsyncFunction("trustHost") { () async throws in try await SynMobileService.open().trustHost() }
        AsyncFunction("pair") { () async throws in try await SynMobileService.open().pair() }
        AsyncFunction("approve") { (id: String) async throws in try await SynMobileService.open().approve(id) }
        AsyncFunction("deny") { (id: String) async throws in try await SynMobileService.open().deny(id) }
        AsyncFunction("revealArgument") { (id: String, index: Int) async throws in
            try await SynMobileService.open().revealArgument(id, index: index)
        }
    }
}
