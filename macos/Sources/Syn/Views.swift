import CryptoKit
import ServiceManagement
import SwiftUI

struct SynMenuView: View {
    @ObservedObject var model: SynModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if model.pending.isEmpty {
            Text("No pending approvals")
        } else {
            ForEach(model.pending) { request in
                Button {
                    openWindow(id: "main")
                    model.review(request.id)
                } label: {
                    Text("\(model.target(for: request)?.displayName ?? request.targetID): \(SafeDisplay.render(request.executable))")
                }
            }
        }
        Divider()
        Text("\(model.connectedTargets.count) of \(model.targets.count) targets connected")
        Button("Open Syn") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Quit Syn") { NSApp.terminate(nil) }
    }
}

struct SynContentView: View {
    @ObservedObject var model: SynModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            List(selection: $model.selectedRequestID) {
                Section("Pending") {
                    ForEach(model.pending) { request in
                        VStack(alignment: .leading) {
                            Text(model.target(for: request)?.displayName ?? request.targetID)
                            Text(SafeDisplay.render(request.executable)).font(.caption).foregroundStyle(.secondary)
                        }
                        .tag(request.id)
                    }
                }
                Section("Targets") {
                    ForEach(model.targets) { target in
                        HStack {
                            Circle()
                                .fill(model.connectedTargets.contains(target.targetID) ? .green : .gray)
                                .frame(width: 8, height: 8)
                            Text(target.displayName)
                            Text(model.connectedTargets.contains(target.targetID) ? "Connected" : "Disconnected")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
        } detail: {
            if let request = model.selectedRequest ?? model.pending.first {
                ApprovalDetailView(model: model, request: request)
            } else {
                SetupView(model: model)
            }
        }
        .frame(minWidth: 840, minHeight: 580)
        .onAppear { model.openMainWindow = { openWindow(id: "main") } }
        .alert("Syn", isPresented: Binding(
            get: { model.lastError != nil },
            set: { if !$0 { model.lastError = nil } }
        )) {
            Button("OK") { model.lastError = nil }
        } message: {
            Text(model.lastError ?? "")
        }
    }
}

private struct ApprovalDetailView: View {
    @ObservedObject var model: SynModel
    let request: VerifiedApprovalRequest
    @State private var revealedArguments: Set<Int> = []

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { timeline in
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Approval requested").font(.largeTitle.bold())
                    Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                        row("Target", model.target(for: request)?.displayName ?? request.targetID)
                        row("Target ID", request.targetID)
                        row("Target fingerprint", model.target(for: request)?.publicKey.map {
                            Data(SHA256.hash(data: $0.x963Representation)).hex
                        } ?? "Unavailable")
                        row("Request", request.id)
                        row("Source user", "\(request.invokingUser) (\(request.invokingUID))")
                        row("Run as", "\(request.runAsUser) (\(request.runAsUID)), group \(request.runAsGroup)")
                        row("Working directory", SafeDisplay.render(request.workingDirectory))
                        row("Executable", SafeDisplay.render(request.executable))
                        row("Environment", request.environmentNames.joined(separator: ", "))
                        row("Environment digest", request.environmentDigest.hex)
                        row("Remaining", remainingLabel(at: timeline.date))
                        row("Expires", request.expiresAt.formatted(date: .omitted, time: .standard))
                    }
                    .textSelection(.enabled)

                    Text("Arguments").font(.headline)
                    ForEach(Array(request.arguments.enumerated()), id: \.offset) { index, argument in
                        HStack(alignment: .top) {
                            Text("\(index)").foregroundStyle(.secondary).frame(width: 28, alignment: .trailing)
                            if SafeDisplay.likelyContainsSecret(argument) && !revealedArguments.contains(index) {
                                Text("•••••••• (possible secret)")
                                Spacer()
                                Button("Reveal") { revealedArguments.insert(index) }
                            } else {
                                Text(SafeDisplay.render(argument)).textSelection(.enabled)
                            }
                        }
                        .font(.system(.body, design: .monospaced))
                    }

                    if !request.riskMarkers.isEmpty {
                        Label(request.riskMarkers.joined(separator: ", "), systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                    Text("Approval confirms system user presence. macOS may offer your login password when Touch ID is unavailable.")
                        .font(.callout)
                        .foregroundStyle(.secondary)

                    HStack {
                        Button("Deny", role: .destructive) { Task { await model.deny(request.id) } }
                        Spacer()
                        Button("Approve once") { Task { await model.approve(request.id) } }
                            .buttonStyle(.borderedProminent)
                            .disabled(timeline.date >= request.expiresAt || model.authenticatingRequests.contains(request.id))
                    }
                }
                .padding(28)
            }
        }
    }

    private func remainingLabel(at date: Date) -> String {
        let seconds = max(0, Int(ceil(request.expiresAt.timeIntervalSince(date))))
        return seconds == 0 ? "Expired" : "\(seconds) seconds"
    }

    @ViewBuilder private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
        }
    }
}

private struct SetupView: View {
    @ObservedObject var model: SynModel

    var body: some View {
        Form {
            Section("Mac approver identities") {
                Text("The approval private key remains in the Secure Enclave. Only these public identities are copied to the Pi.")
                    .foregroundStyle(.secondary)
                Text( model.approverIdentityText)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                HStack {
                    Button("Generate identities") { model.generateApproverIdentities() }
                    Button("Copy public identities") { model.copyApproverIdentities() }
                }
            }
            Section("Pair a target") {
                Text("Import the root-approved JSON profile produced during pairing. Syn rejects plain ws:// endpoints, invalid target keys, and malformed certificate pins.")
                    .foregroundStyle(.secondary)
                TextEditor(text: $model.pairingProfileText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 150)
                Button("Import paired target") { model.importTargetProfile() }
                    .disabled(model.pairingProfileText.isEmpty)
            }
            Section("Targets") {
                ForEach(model.targets) { target in
                    HStack {
                        Text(target.displayName)
                        Spacer()
                        Button("Remove", role: .destructive) { model.removeTarget(target) }
                    }
                }
            }
            Section("App") {
                Toggle(
                    "Launch Syn at login",
                    isOn: Binding(
                        get: { SMAppService.mainApp.status == .enabled },
                        set: { model.setLaunchAtLogin($0) }
                    )
                )
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}
