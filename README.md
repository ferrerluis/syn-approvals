# Syn

Syn is a human-approval gate for privileged actions on remote development machines. The first adapter gates an ordinary, already-authorized `sudo.ws` invocation on Ubuntu and asks a paired Mac for a one-use signed decision.

> [!WARNING]
> Syn is a private security alpha. Do not install its sudo integration on a machine without console or recovery access. It has not received an independent security review.

The privileged approval path has passed live Pi validation, but package/reboot lifecycle validation remains in progress. The approval window is 90 seconds; ordinary unavailability can then fall back to the Ubuntu password only in an interactive terminal. Read [the implementation status](docs/implementation-status.md) before treating any milestone as complete.

## What exists

- A deterministic CBOR/COSE ES256 protocol shared through Rust/Swift test vectors.
- A root-side `sudo.ws` approval plug-in that never executes network-provided commands.
- An unprivileged, mutually authenticated TLS/WebSocket relay for Nord Meshnet or Tailscale networks.
- `synctl` with stable JSON output for diagnostics, keys, policies, request inspection, and guarded installation planning.
- A native SwiftUI menu-bar approver with local notifications and Secure Enclave signing.
- Ubuntu systemd, PAM, sudo, and Debian packaging assets.
- Threat model, protocol specification, ADRs, recovery procedure, and security tests.

The installer is intentionally **not automatically armed** by a package install. `synctl install --user NAME` prints a plan; `--apply` refuses unless pairing material, sudo provider checks, and recovery state all validate.

## Repository layout

- `crates/syn-protocol`: signed wire types, deterministic encoding, and validation.
- `crates/syn-agent`: rootless Unix-socket to mTLS WebSocket relay.
- `crates/syn-sudo-plugin`: classic sudo approval ABI and PAM fallback.
- `crates/synctl`: diagnostics and root-only lifecycle operations.
- `crates/syn-sim`: offline target/approver simulator.
- `macos`: native SwiftUI approver.
- `packaging`: Ubuntu service, PAM, policy, and package assets.
- `docs`: design authority and recovery guidance.

## Developer setup

Rust 1.85+, Swift 6/Xcode, clang, and pkg-config are required.

```sh
make check
make test
make lint
make macos-app
```

Install the read-only CLI locally:

```sh
make install-local
synctl --json doctor
```

## CLI contract

Human-readable output is the default. `--json` writes one stable JSON value to stdout; diagnostics go to stderr. Error JSON has `{"ok":false,"error":{"code","message"}}` and never includes private keys, passwords, certificate contents, or pairing secrets.

Start with:

```sh
synctl --json doctor
synctl --json status
synctl --json policy show
synctl --json recovery status
```

Security-sensitive mutations require root and an explicit `--apply`. There is deliberately no raw command-submission API.

Before installation, `synctl recovery prove --apply` exercises a harmless local timer and `synctl recovery arm --minutes 15 --apply` creates the required absolute, reboot-persistent rollback deadline.

For Phase 6, preview `synctl --json install --user NAME --shadow`. Adding `--apply --acknowledge-console-recovery` records recovery state and registers the plug-in, but **does not** change the sudo alternative, provider modes, agent state, or passwordless policy. Test by invoking `/usr/bin/sudo.ws` directly. `synctl recover --restore-local-sudo --apply` restores the original file and permissions, archives the shadow state, and cancels the timer after recovery succeeds. A fresh signed preflight and at least ten minutes of rollback time are still required.

## Supported alpha

- Target: Ubuntu 26.04 ARM64 with classic `sudo.ws` 1.9.x.
- Approver: macOS 15 or newer on a Secure Enclave-capable Mac.
- Connectivity: Nord Meshnet or Tailscale, with no public ingress or Syn cloud relay.
- Topology: one managed Linux user and one approver Mac per target; one Mac may pair with many targets.

See [docs/protocol.md](docs/protocol.md), [docs/threat-model.md](docs/threat-model.md), and [docs/recovery.md](docs/recovery.md) before installing.

The current pairing path is a manual, authenticated alpha workflow; the planned QR `/v1/pair` exchange is not yet complete. Use the [live Pi validation plan](docs/live-pi-validation-plan.md) and its timed-recovery gates before arming the sudo integration.

## License

Licensed under either Apache-2.0 or MIT, at your option. Publication remains gated on an independent security review.
