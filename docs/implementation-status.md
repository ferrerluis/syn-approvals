# Implementation status

This repository is a compiling security-alpha foundation, not a reviewed or deployable release. The distinction matters because successful compilation does not prove a sudo ABI, PAM conversation, Secure Enclave policy, installer recovery path, or package upgrade on the actual Ubuntu ARM64 target.

## Delivered

- **Iteration 0, live validated:** explicit Nord Meshnet/Tailscale selection, exact local-interface and approver-address checks, a reboot-persistent recovery deadline, and one exact 30-second approval TTL. [Evidence and remaining limits](validation/2026-09-03-iteration-0.md).
- **Validation Phases 1–2 passed:** committed source baseline, refreshed local checks, current Pi inventory, root-only sudo-state backup, verified recovery timer, and retained root access through the acceptance gate. The timer was canceled after the gate; sudo remains unchanged. [Evidence](validation/2026-09-04-phases-1-2.md).
- **Design authority:** threat model, protocol, privacy rules, ADRs, recovery procedure, and adversarial test matrix.
- **Protocol:** deterministic CBOR, COSE Sign1 ES256, typed sudo intent, exact request/decision binding, size limits, and shared Rust/Swift golden vectors.
- **Relay:** root-only local socket input, target-signature verification, in-memory pending queue, cancellation, mutual TLS 1.3, binary WebSocket messages, exact approver keys, deadlines, and no command execution surface.
- **sudo.ws plug-in source:** final argv/environment capture, duplicate and size checks, root-owned request signing, independent decision verification, local shell/interpreter policy, monotonic timeout, and dedicated PAM fallback.
- **Mac app source:** menu bar, pinned TLS, Keychain client identity, local notifications, safe byte/Unicode rendering, Secure Enclave `userPresence` approval, software denial key, and one-request decisions.
- **Lifecycle tooling:** diagnostics, target and approver key staging, profile generation, signed harmless-command preflight, guarded install ordering, recovery, systemd/PAM assets, and ARM64 Debian package assembly.

## Not yet proven or complete

- The sudo plug-in has been built, linked, and unit-tested natively on the Ubuntu 26.04 ARM64 Pi, but not loaded into a real `sudo.ws` invocation.
- The PAM fallback has not been exercised with the real Ubuntu common-auth stack.
- The transactional installer and `dpkg-statoverride` recovery have not been fault-injected on the target OS.
- Pairing uses a manually transferred, root-approved profile and transport identity. The planned QR/custom-URL `/v1/pair` exchange is not implemented end to end.
- Secure Enclave signing compiles, but fresh Touch ID/login-password behavior must be device-tested in the signed app bundle.
- The Debian package has been built and installed on Ubuntu 26.04 ARM64 without arming Syn. Actual sudo restoration and interrupted-install recovery still require live testing; the completed timer test used a harmless action and a pre-install reboot.
- No Developer ID signing, notarization, SBOM, reproducible-build proof, independent review, sudo-rs RFC, or 1Password research run has occurred.

## Release state

Do not run `synctl install --apply` until the existing Pi has a proven local timed rollback and preserved root path. Follow the [live Pi validation plan](live-pi-validation-plan.md); spare hardware is not required.
