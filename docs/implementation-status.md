# Implementation status

This repository is a compiling security-alpha foundation, not a reviewed or deployable release. The distinction matters because successful compilation does not prove a sudo ABI, PAM conversation, Secure Enclave policy, installer recovery path, or package upgrade on the actual Ubuntu ARM64 target.

## Delivered

- **Iteration 0, live validated:** explicit Nord Meshnet/Tailscale selection, exact local-interface and approver-address checks, a reboot-persistent recovery deadline, and one exact 30-second approval TTL. [Evidence and remaining limits](validation/2026-09-03-iteration-0.md).
- **Validation Phases 1–2 passed:** committed source baseline, refreshed local checks, current Pi inventory, root-only sudo-state backup, verified recovery timer, and retained root access through the acceptance gate. The timer was canceled after the gate; sudo remains unchanged. [Evidence](validation/2026-09-04-phases-1-2.md).
- **Validation Phases 3–4 passed:** clean native ARM64 build with system PAM development files, 29 Pi tests, explicit audited runtime dependencies, package reinstallation, and before/after authentication-state comparisons. Fresh ordinary password sudo passed; Syn remains unarmed. [Evidence](validation/2026-09-04-phases-3-4.md).
- **Validation Phase 5 passed:** real synthetic Touch ID approvals, explicit denial, actual authentication cancellation, notification privacy/Review reopening, and stable signed-app restart without repeated Keychain permission. [Evidence](validation/2026-09-04-phases-5-6-progress.md).
- **Validation Phase 6 passed:** final-build Mac approval executed the original real sudo invocation as root. Denial, Ctrl-C, malformed replies, 30-second non-interactive expiry, interactive PAM fallback, relay reconnection, and actual timed shadow recovery also passed on Ubuntu 26.04.1 ARM64. The original sudo/PAM/provider state is restored; fresh ordinary password sudo passed. Current checks pass 31 local Rust, 39 native Pi Rust, and 23 Swift tests. No passwordless rule was created. [Evidence](validation/2026-09-04-phases-5-6-progress.md).
- **Validation Phase 7 passed:** guarded normal installation, exact single-user rule/global plug-in/provider coupling, alternate-provider denial, ordinary-sudo Mac approval, actual automatic normal recovery, and reinstallation with a fresh approved healthy diagnostic passed. Latest checks: 35 local Rust, 43 native Pi Rust, and 23 Swift tests. Syn is armed at handoff with rollback scheduled for 2026-09-04 15:41:11 UTC; this is temporary validation state, not permanent enablement. [Evidence](validation/2026-09-04-phase-7.md).
- **Validation Phase 8 passed:** all armed-mode authentication matrix rows passed, including fresh repeat/concurrent approvals, actual system cancellation, Mac login-password approval, timeout/PAM behavior, alternate-provider denial, live malformed replies, and missing-plug-in failure. Each fault was restored and followed by a new ordinary-sudo approval. The denial notice explains retry; expanded signed-intent mismatch tests pass. Latest checks: 35 local Rust, 45 native Pi Rust, and 23 Swift tests. Doctor was healthy at 2026-09-04 16:06:04 UTC; rollback remains scheduled for 16:18:20 UTC. [Evidence and scope](validation/2026-09-04-phase-8.md).
- **Design authority:** threat model, protocol, privacy rules, ADRs, recovery procedure, and adversarial test matrix.
- **Protocol:** deterministic CBOR, COSE Sign1 ES256, typed sudo intent, exact request/decision binding, size limits, and shared Rust/Swift golden vectors.
- **Relay:** root-only local socket input, target-signature verification, in-memory pending queue, cancellation, mutual TLS 1.3, binary WebSocket messages, exact approver keys, deadlines, and no command execution surface.
- **sudo.ws plug-in source:** final argv/environment capture, duplicate and size checks, root-owned request signing, independent decision verification, local shell/interpreter policy, monotonic timeout, and dedicated PAM fallback.
- **Mac app source:** menu bar, pinned TLS, Keychain client identity, local notifications, safe byte/Unicode rendering, Secure Enclave `userPresence` approval, software denial key, and one-request decisions.
- **Lifecycle tooling:** diagnostics, target and approver key staging, profile generation, signed harmless-command preflight, guarded install ordering, recovery, systemd/PAM assets, and ARM64 Debian package assembly.

## Not yet proven or complete

- Phases 9–10 remain: real package installation and Codex usage, package/provider upgrades, armed reboot, post-reboot recovery, and permanent enablement. The Phase 8 matrix does not substitute for those workflow and lifecycle checks.
- Armed-mode missing-plug-in failure passed; unreadable/corrupted plug-ins and every interrupted-install boundary have not been separately fault-injected. Normal installation and stat-override recovery passed on the target, but upgrade behavior remains unproven.
- Pairing uses a manually transferred, root-approved profile and transport identity. The planned QR/custom-URL `/v1/pair` exchange is not implemented end to end.
- Fresh Secure Enclave approval with Touch ID and system cancellation passed in earlier phases; the Mac login-password path also passed in armed mode. Automatic dismissal of an untouched expired authentication prompt still needs dedicated live evidence.
- The Debian package is installed on Ubuntu 26.04 ARM64. Actual shadow and normal-install timed recovery passed; interruption at every passwordless-install phase remains untested.
- No Developer ID signing, notarization, SBOM, reproducible-build proof, independent review, sudo-rs RFC, or 1Password research run has occurred.

## Release state

Do not run `synctl install --apply` until the existing Pi has a proven local timed rollback and preserved root path. Follow the [live Pi validation plan](live-pi-validation-plan.md); spare hardware is not required.
