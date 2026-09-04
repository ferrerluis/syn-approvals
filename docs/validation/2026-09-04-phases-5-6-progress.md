# Phases 5–6 progress — 2026-09-04 UTC

Status: **in progress, neither phase passed**. Work started from `cd36a57` on `validation/phases-5-6`; this report describes a private validation checkpoint, not a released or deployment-approved build.

## Live evidence

- SSH reconfirmed Ubuntu ARM64 with `/usr/bin/sudo` resolving to `/usr/lib/cargo/bin/sudo`. No Syn install state, managed sudoers rule, or plug-in registration was present before this run.
- Showing the main SwiftUI window explicitly fixed the initial Computer Use timeouts. The setup window, identity generation, and profile import were then exercised through native UI controls.
- The user approved generation/pairing. Syn.app generated its Secure Enclave approval identity and separate denial identity; only their public keys were sent to the Pi.
- The Pi generated its target signing key locally, root:root mode 0600. Its separate transport key is root:syn mode 0640. The agent cannot read the target signing key.
- The rootless service started with exact Nord Meshnet bind address `100.99.102.171:41781` and approver address `100.70.150.245`. A single UFW rule permits only that peer, destination, port, and `nordlynx` interface. Existing SSH/RDP rules were preserved. TCP reachability passed after that rule was added.
- A Mac HTTPS probe without a client certificate was rejected; the agent recorded a mutual-TLS failure. The initial `openssl s_client` exit-zero result with immediate EOF was **not** counted as proof: the follow-up HTTP read failed instead.
- The certificate-pinned `pi-main` profile was imported into Syn.app. TLS reached the client certificate-signing step with the intended Syn identity; a complete hello/approval round trip has not yet passed.
- macOS presents a Keychain prompt for **Syn transport identity**. Computer Use explicitly refuses access to `com.apple.SecurityAgent` for safety reasons. The user was asked to complete this specific system prompt. No access to unrelated Apple Development keys was approved.

## Bugs found and changes made

1. The preflight requester used per-read timeouts and accepted late verified decisions. It now shares one monotonic deadline across signing, connection, framed IO, and final signature verification.
2. Shadow sudo setup had no recovery state, so the existing timer would do nothing. `install --shadow` now records a protected, durable backup/state before registering the plug-in. It creates no NOPASSWD rule and changes neither providers nor agent state. Recovery restores file contents/mode and archives shadow state after validation. **Live recovery testing remains pending.**
3. Normal recovery did not retain the original sudo alternative's auto/manual mode. New install state records it, along with original sudo.conf permissions. Older state remains readable.
4. The Mac's original identity script exposed a wrapping password in process arguments. The replacement passes the one-use value through stdin to a native Keychain import helper. Direct empty-password PKCS#12 and PEM-import attempts failed; they were not counted as completed identities. Private temporary directories were cleaned by the script.
5. TLS certificates now explicitly use named P-256 parameters and the appropriate client/server usage. Apple's bundled LibreSSL generated explicit parameters without this option; a new certificate-validation test caught Apple's rejection of that encoding.
6. URLSession/ATS rejected the private target certificate before the desired flow completed. The app now uses Network.framework for TLS 1.3 with exact pins, per-connection anchors, hostname/validity checks, and bounded WebSocket messages. No system trust-store change was made.
7. The first Network.framework build crashed because its verification callback inherited main-thread isolation while running on the TLS queue. The callback is explicitly Sendable. The subsequent app launch survived and reached Keychain authentication.
8. A Keychain identity query filtered only by label returned an unrelated Apple identity. The app now resolves the labeled certificate first, checks its name, creates the matching identity, and compares certificate bytes. A read-only live check confirmed the corrected lookup resolves the Syn certificate/identity.
9. Approval rechecks expiry after system authentication. Profile import updates in-memory state only after persistence succeeds.
10. Agent-side WebSocket size limits now match the wire limit, handshakes have deadlines, and malformed WebSocket errors wake pending requests with an integrity failure rather than a timeout fallback.

## Checks completed

- Local Rust workspace: 30 tests passed, including new deadline, framing, replay, wrong-target, tampering, and shadow-plan tests.
- Native Pi workspace: 37 tests passed, including the seven Linux plug-in tests; native formatting and Clippy with warnings denied passed.
- Local Clippy with warnings denied and ARM64 Linux plug-in type-check passed.
- Swift: seven tests passed, including a generated-certificate test proving correct-pin success and wrong-pin, wrong-host, and expired-certificate rejection.
- Rust/Swift golden fixture copies match; protocol encoding was not changed.
- Updated shell scripts pass shell syntax checks. Ad-hoc app builds and signature verification passed, but stable signing/Keychain continuity still needs validation.

Native release compilation and ARM64 package assembly passed. The new package is `/home/ferrerluis/src/syn-phase34.SUtPjH/dist/syn-approvals_0.1.0~alpha1_arm64.deb`, SHA-256 `90e266b5727724b6070aa6750c3754be13feb127265766607fa4d801f9273cd6`. It was initially uninstalled; the follow-up staging section below records its later installation. The fresh CLI's help/status commands were exercised from `/tmp`, and its root shadow preview correctly reported missing signed preflight evidence and an unarmed recovery timer as blockers. Pi source/build directory: `/home/ferrerluis/src/syn-phase34.SUtPjH`.

## Follow-up live iteration

- The initial Keychain prompt cleared. The Mac displayed the green connected indicator after a matching target hello, and a real root-signed synthetic request reached the review window. The visible details matched `pi-main`, the managed user, root run-as identity, working directory, resolved executable, and distinct argv row. No command was executed.
- **The first live Deny test failed.** Reading Keychain material blocked the main thread and triggered another system dialog; the Pi correctly expired its request instead of accepting a late decision. This does not count as a successful denial. Computer Use returned `-10005: timeoutReached` during the click while SecurityAgent was running.
- Denial signing now reads only the denial key, never the approval key. Both signing paths run off the main actor, while pending-request updates remain on the main actor. Approval authentication uses a fresh context with no reuse window and invalidates it afterward.
- Failed or canceled approval authentication attempts a signed denial for a still-live request. A concurrent Deny removes the pending request before signing so an in-flight approval can no longer be sent. Repeated Approve clicks cannot open parallel authentication prompts. Authentication finishing after expiry sends nothing.
- A failed send is now described as **unconfirmed delivery**, not proof that the command did not run. If a signed denial cannot be delivered, the UI explicitly warns that the Pi may offer its ordinary timeout fallback.
- Review requests open the main window; target connection state has visible text, and the review sheet includes the target key fingerprint. Request IDs used by UI/notifications include the target identity; target cancellation cannot remove a different target's request. Expired entries are pruned and the pending/replay maps have bounds.
- A wire-message kind above 255 now produces a parser error instead of trapping during integer conversion. Wire formats/golden messages were not changed.
- Notification construction has a unit test proving the title/body/metadata contain only target, user, age, and request reference—not command or environment contents. Actual macOS banner delivery and notification Review/Deny actions still need live proof.
- The Mac app was built twice with the existing Apple Development identity, hardened runtime, and a verified stable designated requirement. This is **not** Developer ID notarization. The signed app launched; conversion from the earlier ad-hoc build still requires legitimate Keychain authorization. No Keychain ACL was weakened through CLI and no unrelated private-key permission was granted. Cross-rebuild Keychain continuity remains unproven until the user completes that system prompt.

### Updated checks and Pi staging

- Local Rust: 30 tests, formatting, Clippy with warnings denied, and ARM64 plug-in type-check passed again.
- Native Pi Rust: all 37 tests, formatting, and Clippy with warnings denied passed again.
- Swift: **16 tests passed with warnings treated as errors**, including one-use approval, signed denial, canceled authentication, expiry, concurrent denial, duplicate approval prevention, transport-error wording, window-opening callback, notification privacy, and oversized wire kind. These use isolated in-memory test keys, not the production Secure Enclave identity.
- Golden-vector regeneration byte-matches the committed fixture and its Swift copy. Shell syntax, plist checks, final app build/signature verification, and `git diff --check` passed.
- Fresh protected backup: `/var/backups/syn/phase56-20260904T0334Z.ef1sG1`. Its authentication-file manifest SHA-256 is `8e4f24bb680dd003b1bddc85a7a32ff1420a78b39b64ebaa777242d8b1a0c170`.
- With retained root access and a durable 15-minute timer, the exact package above was copied into that backup, hash-checked, inspected, dry-run, then installed. Installed CLI/agent/plug-in bytes match native release outputs. The restarted relay's executable was verified as `/usr/libexec/syn/syn-agent`, running as `syn:syn`, listening only on the configured Meshnet address/port.
- Sudo/PAM file hashes, provider owner/modes, sudo alternatives (including auto mode), and stat overrides matched their fresh pre-install records. Sudoers parses successfully. There is still no plug-in registration, managed rule, install state, or successful signed-preflight marker.
- The installed shadow preview correctly blocks on missing signed pairing/preflight evidence. No shadow apply was attempted. After verifying unchanged authentication state, the setup-only timer was canceled; it must be re-armed before shadow tests.

## Remaining acceptance gates

- Complete the legitimate Keychain permission, confirm the `pi-main` hello/connection state, and exercise synthetic approval, denial, authentication cancellation, notification privacy, and the complete request renderer.
- Live-verify the implemented signed-denial handling for canceled Mac authentication and opening of Review from notifications when the main window is closed.
- Record a fresh successful signed preflight only after the real Mac signing flow works. Use stable developer signing before treating repeated app rebuilds as a usable approval UX.
- Re-establish root recovery access and re-arm the timer before shadow changes; refresh the backup if any sudo/provider state changes from the recorded baseline.
- Prove actual shadow timer recovery, then live sudo approval, denial, malformed response, cancellation, and timeout through `/usr/bin/sudo.ws`; restore the original sudo configuration afterward.
- Re-run the full check suite, review privacy evidence, and update this report with actual outcomes. Unit tests do not substitute for those live gates.

The Pi is **not armed**: no Syn passwordless rule or sudo plug-in registration was added during this run. The Mac/Pi public pairing, private keys on their owning devices, restricted firewall rule, and running unprivileged relay are setup state only. The relay is not enabled at boot yet. Final checks confirmed the original sudo provider, no install state/rule/plug-in line, and no recovery timer; the retained root SSH shell was then closed. Re-establish it and arm the timer before shadow setup.
