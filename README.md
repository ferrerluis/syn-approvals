<p align="center"><img src="assets/branding/light/syn-app-icon-light.png" width="112" height="112" alt="Syn logo"></p>

# Syn

Syn lets a Mac approve one privileged action on a remote machine at a time. Download the Mac release, open Syn, choose **Add a machine**, and provide only the remote hostname, SSH account, and optional port. The exactly matching remote source and helper are already bundled inside the Mac release.

The remote machine must already be reachable by that hostname, accept SSH for the selected account, and allow that account to use `sudo`. Setup uses SSH only to inspect, transfer, build, install, pair, update, recover, or uninstall Syn; everyday approval requests use a direct mutually authenticated TLS connection to the saved hostname, with no SSH tunnel, VPN-provider integration, or Syn cloud relay.

> [!WARNING]
> The Mac-led flow is a security-sensitive experimental release. Its [12-case hybrid acceptance suite](docs/onboarding-e2e-test-plan.md) passed with the [documented live/component boundaries](docs/validation/2026-09-14-onboarding-e2e-results.md), but Syn has not received an independent security review.

## Install the experimental Mac build

1. [Download the latest experimental Mac ZIP](https://github.com/ferrerluis/syn-approvals/releases/latest/download/Syn-macOS-latest-experimental.zip).
2. Open the ZIP and move **Syn.app** into **Applications**.
3. Open Syn. The current ad-hoc-signed build may require macOS's per-app **Open Anyway** confirmation in **System Settings → Privacy & Security**; do not disable Gatekeeper or other system-wide protections.
4. Choose whether Syn should start when you log in, then select **Add a machine** and enter its reachable hostname, SSH account, and optional port.

The Mac release already contains the exact remote source and helper it will install. You do not download or run a separate Ubuntu installer.

## Everyday use

When the configured remote account invokes an eligible `sudo` command, the remote plug-in signs the exact executable, arguments, working directory, identities, and environment digest. The Mac shows that one request and signs either one approval or one denial after macOS user-presence authentication.

The request expires after 90 seconds. In an interactive terminal, pressing Enter while the request is still pending cancels that request and opens the remote machine's normal password prompt immediately; ordinary timeout or Mac unavailability can also use password authentication. Explicit denial, invalid data, replay, local policy rejection, and non-interactive use fail closed.

The Mac may use Touch ID or the Mac login password through the system authentication prompt. During everyday sudo use, the remote account password stays in the remote PAM conversation: Syn does not send it to the Mac, save it, or place it in command arguments.

For first setup, Syn shows one command to run in a trusted administrator terminal on the remote machine. Enter any administrator password there, in a session your agents cannot control. The command installs this Mac's restricted SSH maintenance key; Syn never collects or sends that password. Subsequent setup and updates use the key.

## Add a machine

The candidate flow is:

1. The Mac confirms the SSH host identity and inspects the remote platform and installed state with fixed, read-only operations.
2. It verifies that the Mac app, ARM64 helper, and source archive carry the same compact UTC release ID and exact Git commit.
3. On first setup, it transfers the helper and shows the one-time command. Run it in a trusted remote administrator session, then click **I've run the command — continue**. The command verifies the helper's root-owned copy before authorizing the restricted maintenance key; future updates reuse that access.
4. The remote builds as a locked non-administrator account, installs the exact package, preserves or creates identities, and returns a certificate-pinned profile over SSH.
5. A signed preflight approval succeeds before Syn changes sudo. A local reboot-persistent recovery deadline remains armed until a second, fresh approval verifies the exact live release and sudo configuration.

Only the remote machine's public profile returns to the Mac. The target authorization private key stays remote; Mac authorization keys and the client identity stay in Keychain or the Secure Enclave.

The separate maintenance SSH key stays in a private directory under the Mac's `~/Library/Application Support/Syn/Maintenance`. The remote entry forces Syn's fixed dispatcher and disables forwarding, user startup hooks and terminal allocation. SSH must permit forced root public-key commands; Syn will not enable unrestricted root login or change your SSH policy. This key authorizes privileged Syn installation, so protect it like an administrator credential.

## Connections and versions

The remote agent listens on the server-side address selected during SSH setup, while the Mac reconnects through the hostname the user supplied. Reachability can come from a LAN, an existing private network, or another route the user controls; Syn neither configures a network provider nor opens public ingress.

Approval messages bind both endpoints to the exact compiled release ID and commit. A valid signature from another release is still rejected, and the Mac reports a mismatch as update required rather than attempting approval.

## Update, recovery, and uninstall

**Update** is Mac-led and uses SSH again. It preserves the target identity and settings, restores ordinary password sudo before package replacement, installs the Mac's exact remote release, and keeps the previous recovery helper until the updated release passes its fresh final approval.

If setup disconnects or stops after privileged state may exist, retry resumes from the protected operation journal or runs local recovery; it never treats a lost SSH reply as success. Recovery removes Syn's `NOPASSWD` rule first, restores ordinary password sudo and provider state, and retains protected keys and backups.

Uninstall follows the same safety ordering, verifies that ordinary sudo is restored, then disables Syn's runtime service and removes the package. Pairing keys, the recovery helper, and sudo backups remain available for conservative recovery rather than being silently deleted.

To remove the Mac's maintenance access locally, run `sudo /var/lib/syn/maintenance/synctl --json maintenance revoke --apply` in a trusted administrator session. Revocation removes only Syn's recorded SSH entry; unrelated keys and recovery access remain. A replacement Mac needs a new bootstrap after revocation.

## Current support and distribution limits

- Remote candidate: Ubuntu 26.04 ARM64 with classic `sudo.ws` 1.9.x. A Raspberry Pi 5 is the tested hardware example, not a product name or a requirement.
- Mac candidate: macOS 15 or newer on a Secure Enclave-capable Apple silicon Mac.
- Topology: one managed remote account and one approving Mac per remote target; one Mac may store several targets.
- Distribution: source and experimental release assets are publicly accessible. Syn has not received an independent security review; treat these builds as experimental.
- Signing: current development builds use ad-hoc signing and are not Developer ID signed or notarized. They may produce normal macOS provenance/security prompts; do not disable system-wide protections to bypass them.

See [implementation status](docs/implementation-status.md), [protocol](docs/protocol.md), [threat model](docs/threat-model.md), [recovery](docs/recovery.md), and the [SSH maintenance contract](docs/ssh-maintenance-contract.md) before live use.

## Repository layout

- `crates/syn-protocol`: signed wire types, deterministic encoding, and validation.
- `crates/syn-agent`: rootless Unix-socket to direct mTLS WebSocket relay.
- `crates/syn-sudo-plugin`: classic sudo approval ABI and PAM fallback.
- `crates/synctl`: diagnostics and guarded lifecycle operations.
- `macos`: native SwiftUI approver and Mac-led setup source.
- `packaging`: remote service, PAM, policy, and Debian package assets.
- `docs`: security, protocol, recovery, implementation, and validation records.

## Developer checks

Rust 1.85+, Swift 6/Xcode, clang, and pkg-config are required.

```sh
make check
make test
make lint
make macos-app
```

Human-readable CLI output is the default. `--json` emits one stable JSON value; diagnostics go to stderr, and security-sensitive changes require root plus explicit `--apply`. There is no network command-submission API.

## License

Licensed under either Apache-2.0 or MIT, at your option.
