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
        Text("\(model.connectedTargets.count) of \(model.targets.count) machines connected")
        Button("Open Syn") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("About Syn") { NSApp.orderFrontStandardAboutPanel(nil) }
        Button("Quit Syn") { NSApp.terminate(nil) }
    }
}

struct SynContentView: View {
    @ObservedObject var model: SynModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                SynBrandHeader()
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
                    Section("Machines") {
                        ForEach(model.targets) { target in
                            HStack {
                                Circle()
                                    .fill(model.connectedTargets.contains(target.targetID) ? .green : .gray)
                                    .frame(width: 8, height: 8)
                                Text(target.displayName)
                                Text(model.connectedTargets.contains(target.targetID) ? "Connected" : (model.pausedConnections.contains(target.targetID) ? "Retry needed" : "Disconnected"))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
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
        .sheet(isPresented: $model.showStartupPrompt, onDismiss: {
            model.dismissStartupPrompt()
        }) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Start Syn automatically when you log in?").font(.title2.bold())
                Text("Keep Syn available to receive approval requests without remembering to open it.")
                if let error = model.lastError {
                    Text(error).foregroundStyle(.red)
                }
                HStack {
                    Button("Not now") { model.dismissStartupPrompt() }
                    Spacer()
                    Button("No") { model.setLaunchAtLogin(false) }
                    Button("Yes (recommended)") { model.setLaunchAtLogin(true) }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(24)
            .frame(width: 440)
        }
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
                    HStack(spacing: 12) {
                        SynLogo(size: 36)
                        Text("Approval requested").font(.largeTitle.bold())
                    }
                    Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                        row("Machine", model.target(for: request)?.displayName ?? request.targetID)
                        row("Machine ID", request.targetID)
                        row("Machine fingerprint", model.target(for: request)?.publicKey.map {
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
            Section("Add a machine") {
                Text("Syn uses your existing SSH setup to check the machine. Installation and everyday approvals do not require an SSH terminal to remain open.")
                    .foregroundStyle(.secondary)
                TextField("Hostname", text: $model.addMachineHostname)
                    .textContentType(.URL)
                TextField("SSH account", text: $model.addMachineUsername)
                    .textContentType(.username)
                TextField("SSH port (optional)", text: $model.addMachinePort)
                    .frame(maxWidth: 220)
                Text("SSH sign-in uses your existing OpenSSH agent and strict saved host verification. Syn never stores an SSH password.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Button(model.addMachineState == .checking ? "Checking…" : "Check connection") {
                        model.checkMachineForSetup()
                    }
                    .disabled(model.addMachineState == .checking)
                    if model.addMachineState == .checking {
                        Button("Cancel") { model.cancelMachineCheck() }
                    }
                }
                switch model.addMachineState {
                case .idle:
                    EmptyView()
                case .checking:
                    Label("Checking SSH access and Ubuntu compatibility…", systemImage: "progress.indicator")
                case .readyToInstall:
                    Label("Compatible remote machine found. Syn is not installed yet.", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                    setupAuthorization
                case .updateRequired:
                    Label("An older Syn installation was found. Update required.", systemImage: "arrow.triangle.2.circlepath")
                        .foregroundStyle(.orange)
                    setupAuthorization
                case let .confirmHost(candidate):
                    Label("Confirm SSH host identity", systemImage: "key.horizontal")
                        .foregroundStyle(.orange)
                    Text("\(candidate.settings.hostname):\(candidate.port)")
                        .font(.headline)
                    ForEach(candidate.records, id: \.fingerprint) { record in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(record.algorithm).font(.caption)
                            Text(record.fingerprint)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                    Text("Compare these fingerprints with the machine owner before trusting them. Syn saves only the confirmed keys in its private host file.")
                        .font(.callout).foregroundStyle(.secondary)
                    HStack {
                        Button("Trust this host") { model.trustPendingSSHHost() }
                        Button("Cancel", role: .cancel) { model.cancelHostConfirmation() }
                    }
                case let .installing(progress):
                    Label(progress.rawValue, systemImage: "progress.indicator")
                    Button("Cancel setup") {
                        model.cancelMachineCheck()
                    }
                case let .installed(releaseID, configuration):
                    Label("Syn \(releaseID) is already installed (\(configuration)).", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                case let .failed(message):
                    Label(message, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }
            Section("Machines") {
                ForEach(model.targets) { target in
                    VStack(alignment: .leading) {
                        HStack {
                            Text(target.displayName)
                            Spacer()
                            if model.updateRequiredTargets.contains(target.targetID) {
                                Label("Update required", systemImage: "arrow.triangle.2.circlepath")
                                    .foregroundStyle(.orange)
                                Button("Update") { model.updateMachine(target) }
                                    .disabled(target.ssh == nil)
                            } else if !model.connectedTargets.contains(target.targetID) {
                                Button("Retry connection") { model.retryConnection(target) }
                                    .disabled(!model.keysReady)
                            }
                            Button("Remove", role: .destructive) { model.removeTarget(target) }
                        }
                        if let error = model.connectionErrors[target.targetID] {
                            Text(error).font(.callout).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Section("App") {
                LabeledContent("Syn release", value: ReleaseIdentity.current.releaseID)
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

    @ViewBuilder
    private var setupAuthorization: some View {
        if let command = model.maintenanceBootstrapCommand {
            Text("One-time setup on this machine").font(.headline)
            Text("Run this command in a trusted administrator terminal on the remote machine. Use a session that your agents cannot control. Enter the machine's password there if asked.")
                .font(.callout)
            Text(command).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            Button("Copy setup command") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(command, forType: .string)
            }
            Text("This authorizes this Mac to install and update Syn through a restricted SSH key. Future updates stay in Syn; your administrator password is never sent by the app.")
                .font(.callout).foregroundStyle(.secondary)
        }
        Button(model.maintenanceBootstrapCommand == nil ? "Install or update Syn" : "I've run the command — continue") {
            model.installCheckedMachine()
        }
    }
}
