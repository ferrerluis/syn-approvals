import SwiftUI
import UIKit

@main
struct SynIOSApp: App {
    @Environment(\.scenePhase) private var phase
    @StateObject private var holder = ModelHolder()
    var body: some Scene {
        WindowGroup {
            Group {
                if let model = holder.model { SynIOSView(model: model) }
                else { ContentUnavailableView("Syn could not start", systemImage: "exclamationmark.lock", description: Text(holder.error ?? "Storage is unavailable.")) }
            }
            .task { holder.model?.setForeground(true) }
            .onChange(of: phase) { _, value in holder.model?.setForeground(value == .active) }
        }
    }
}

@MainActor
final class ModelHolder: ObservableObject {
    let model: IOSModel?
    let error: String?
    init() { do { model = try IOSModel(); error = nil } catch { model = nil; self.error = error.localizedDescription } }
}

struct SynIOSView: View {
    @ObservedObject var model: IOSModel
    @State private var showSetup = false
    @State private var revealed: Set<String> = []
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            List {
                if model.developmentSigner {
                    Section { Label("Simulator development signer", systemImage: "hammer")
                        Text("Approvals use a software key here. Face ID and Secure Enclave protection require a physical iPhone.").font(.caption).foregroundStyle(.secondary) }
                }
                if let error = model.error { Section { Text(error).foregroundStyle(.red) } }
                if let status = model.status { Section { Text(status).foregroundStyle(.secondary) } }
                Section("Machines") {
                    if model.targets.isEmpty { Text("Add a machine to receive approval requests.").foregroundStyle(.secondary) }
                    ForEach(model.targets) { target in
                        HStack { Label(target.displayName, systemImage: "desktopcomputer"); Spacer()
                            Text(model.connected.contains(target.id) ? "Connected" : "Disconnected")
                                .font(.caption).foregroundStyle(model.connected.contains(target.id) ? .green : .secondary) }
                    }
                    Button("Retry connection") { model.retry() }
                }
                Section("Requests") {
                    if model.pending.isEmpty { Text("No pending requests").foregroundStyle(.secondary) }
                    ForEach(model.pending) { request in
                        VStack(alignment: .leading, spacing: 12) {
                            Text(model.targets.first(where: { $0.id == request.targetID })?.displayName ?? request.targetID).font(.headline)
                            Text("\(request.invokingUser) → \(request.runAsUser)").font(.subheadline)
                            Text(SafeDisplay.render(request.executable)).font(.system(.body, design: .monospaced))
                            ForEach(Array(request.arguments.enumerated()), id: \.offset) { index, argument in
                                let id = "\(request.id):\(index)"
                                if SafeDisplay.likelyContainsSecret(argument) && !revealed.contains(id) {
                                    Button("Reveal argument \(index)") { revealed.insert(id) }
                                } else { Text("Argument \(index): " + SafeDisplay.render(argument)).font(.system(.caption, design: .monospaced)) }
                            }
                            Text("Folder: " + SafeDisplay.render(request.workingDirectory)).font(.caption)
                            Text("\(max(0, Int(request.expiresAt.timeIntervalSinceNow))) seconds remaining").font(.caption).foregroundStyle(.secondary)
                            HStack {
                                Button("Deny", role: .destructive) { Task { await model.deny(request.id) } }.buttonStyle(.bordered)
                                Spacer()
                                Button("Approve") { Task { await model.approve(request.id) } }.buttonStyle(.borderedProminent)
                                    .disabled(model.authenticating.contains(request.id) || request.isExpired)
                            }
                            Text("Applies to this request only.").font(.caption).foregroundStyle(.secondary)
                        }.padding(.vertical, 8)
                    }
                }
            }
            .navigationTitle("Syn")
            .toolbar { Button("Add a machine", systemImage: "plus") { showSetup = true } }
            .sheet(isPresented: $showSetup) { IOSSetupView(model: model) }
            .onReceive(timer) { _ in model.expire() }
        }
    }
}

struct IOSSetupView: View {
    @ObservedObject var model: IOSModel
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            Form {
                Section("Machine") {
                    TextField("Hostname", text: $model.machineHost).autocorrectionDisabled().textInputAutocapitalization(.never)
                    TextField("SSH port", text: $model.machinePort).keyboardType(.numberPad)
                    Button(model.checkingHost ? "Checking…" : "Check connection") { Task { await model.checkHost() } }
                        .disabled(model.checkingHost || model.machineHost.isEmpty)
                    if let candidate = model.hostCandidate {
                        Text(candidate.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Text("Compare this fingerprint with a trusted administrator terminal before trusting the host.").font(.caption)
                        Button("Trust this host") { Task { await model.trustHost() } }
                    }
                }
                if let command = model.bootstrapCommand {
                    Section("Authorize this iPhone") {
                        Text("Syn must already be installed on the machine at this app’s matching release. Run this command once in a trusted administrator terminal, then continue here.")
                        Text(command).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button("Copy setup command") { UIPasteboard.general.string = command }
                        Button("I’ve run the command — continue") { Task { await model.connectMobile(); if model.profileText.isEmpty && !model.targets.isEmpty { dismiss() } } }
                    }
                }
                DisclosureGroup("Advanced pairing") {
                    Button("Prepare device identity") { Task { await model.prepareEnrollment() } }
                    if !model.enrollmentText.isEmpty {
                        ShareLink(item: model.enrollmentText) { Text("Share public enrollment") }
                    }
                    TextEditor(text: $model.profileText).frame(minHeight: 120).font(.system(.caption, design: .monospaced))
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                    Button("Import trusted machine profile") { model.importProfile(); if model.profileText.isEmpty { dismiss() } }
                        .disabled(model.profileText.isEmpty)
                }
                Section("Background alerts") {
                    Text("For Codex tasks, Codex can tell you when Syn needs attention. Open Syn to receive and review requests directly; a Codex response never approves them.")

                }
                if let error = model.error { Section { Text(error).foregroundStyle(.red) } }
            }.navigationTitle("Add a machine").toolbar { Button("Done") { dismiss() } }
        }
    }
}
