# Phases 5–6 progress — 2026-09-04 UTC

Status: **Phases 5–6 passed**. Work started from `cd36a57` on `validation/phases-5-6`; this report describes a private validation checkpoint, not a released or deployment-approved build. The latest results below supersede historical pending gates farther down this chronological report.

## Final acceptance and restoration — 14:35–14:37 UTC

- Luis confirmed he had not been paying attention during the two expired attempts and requested a retry. Those attempts remain recorded as expiry, not a signing defect or approval.
- Retained independent root access verified the baseline again, armed a fresh 15-minute Pi-local recovery timer, and applied guarded shadow mode using the still-fresh successful 14:26 signed preflight. No NOPASSWD rule, provider switch, or provider-mode change was made.
- **Final-build real sudo approval passed:** `/usr/bin/sudo.ws -n /usr/bin/id -u` produced request `81676b340460eb02156c53bba27627a9`. The Mac showed the managed user, root run-as identity, working directory, resolved executable, separate arguments, and environment-name/digest fields. After Approve once and system user presence, the original invocation printed **0** and `SYN_FINAL_APPROVAL_EXIT=0`. Non-interactive mode excluded password fallback from this success.
- The tested Mac executable SHA-256 remains `07dc2a4ae8cfcb6affed55fec48fd568341392c5be0ac50855edb204a3f148f3`; installed native package SHA-256 remains `f59637c542a925826827c3e116f71d8c396ac3d017ed42d417f6918bfe9ac7fc`. No code changed between the completed final checks and this acceptance test.
- Manual recovery completed at **14:36:06 UTC**. Every captured sudo/PAM hash, sudo alternative, and stat override matched the protected baseline. Both providers remain root:root 4755. Syn's managed rule and install state are absent; the recovery timer is not armed, inactive, and disabled. The unprivileged relay remains active.
- After invalidating the ordinary sudo timestamp, default non-interactive sudo correctly refused authentication with exit 1. Fresh ordinary password sudo then printed root UID 0 and `SYN_BASELINE_PASSWORD_EXIT=0`, without a Syn request.
- Both providers' ordinary sudo timestamps were invalidated and both validation SSH shells were closed after restoration. The default provider still resolves to sudo-rs, and the relay remains disabled at boot.
- This completes the Phases 5–6 acceptance scope. Phase 7 passwordless arming, provider restrictions, reboot/upgrade validation, and public-release review remain separate, uncompleted work.

## Resumed validation — 14:24–14:30 UTC

- Luis returned and requested continuation. Fresh read-only checks found the expected original provider, no plug-in registration, and no recovery timer. A new independent root shell verified every captured sudo/PAM hash, alternatives, stat overrides, and the installed plug-in against the native release output before arming a 15-minute timer.
- Final Mac app signature verification passed; executable SHA-256 is `07dc2a4ae8cfcb6affed55fec48fd568341392c5be0ac50855edb204a3f148f3`. Syn showed Keys ready and Connected without another setup permission.
- Fresh preflight **passed**, request `03897248ff6dbcf03e86450f108681e7`, hash `ca19222062e728d198ce3dcec046807a46e1b142c5d30c6189313045ec038975`. The Pi verified the approval and recorded fresh preflight evidence.
- Guarded shadow apply passed without a NOPASSWD rule or provider switch. Real request `e35cc2fdb233f596bf42a609ce11faf9` reached the review UI but expired without a signed decision. Its Ubuntu fallback was canceled; exit 1, no command result. A fresh non-interactive retry, `7755f278e0b9bd54190b4608ac10dc6b`, also expired without a decision and exited 1 without prompting. Neither attempt counts as positive approval. Whether the system authentication prompts appeared to Luis is not yet confirmed.
- At 14:29:44 UTC, manual recovery was complete: all captured authentication hashes, alternatives, and stat overrides again matched the original backup; install state and managed rule were absent, and the timer was canceled. The independent root and unprivileged test shells remain open for this resumed validation window; verify their handles before reuse.

## Shadow sudo iteration — 04:15–04:31 UTC

Luis confirmed both remaining notification checks: its preview contained target/user metadata but no command, and Review reopened the closed Syn window. The Pi verified his subsequent denial. This completes Phase 5; earlier unverified-notification statements below are historical.

The shadow installer then passed its guarded preview and apply with retained root access, fresh signed preflight, and more than ten minutes of timed recovery remaining. Classic sudo loaded the plug-in. The ordinary sudo alternative stayed on sudo-rs, both providers retained root:root 4755, sudoers parsed, and no Syn NOPASSWD rule was created.

| Live test | Observed result |
| --- | --- |
| Real sudo approval, initial build | Request `5e780a4fd45abed9f42eee9f370f3755` showed the resolved executable, separate arguments, managed UID, run-as root, working directory, and environment-name/digest fields. After actual Mac authentication, the original invocation printed root UID 0 and exited 0. |
| Real explicit denial, initial build | Request `67b27eaf63e40db3b514d571f9feab37` exited 1 promptly, with no command result or password fallback. |
| Terminal cancellation, initial build | **Failed:** Ctrl-C left request `ce3bfeb5bd0bec1356d8dadc071dde3e` pending and eventually offered PAM fallback. The prompt was canceled; no command ran. Sudo was recovered before patching. |
| Manual shadow recovery | Restored original sudo.conf bytes, archived shadow state, preserved providers, validated sudoers, and canceled the timer. |
| Terminal cancellation, rebuilt plug-in | Request `6a10309fa4ca9866f940da46b888286d` disappeared from the Mac immediately; sudo printed the cancellation notice and exited 1 within the one-second observation. No PAM prompt appeared. |
| Malformed local reply | The root-only one-shot fixture sent a bounded invalid-CBOR response, without parsing, logging, or executing the request. Real sudo rejected it in about one second, exit 1, no fallback. The normal agent was stopped for this isolated fixture and restored afterward. |
| Non-interactive absence | With the agent stopped and a valid ordinary sudo timestamp, `sudo.ws -n` reached Syn, waited exactly 30 seconds by the shell clock, and exited 1 without prompting. |
| Interactive absence | Reached the dedicated no-echo PAM prompt. The supplied Ubuntu password authorized the original invocation, which printed root UID 0 and exited 0. The 96-second total includes time waiting for test-driver password entry; it is not the approval timeout. |
| Request after password fallback | Generated another Syn wait, not a standing approval. The first repetition expired while the app was paused after the relay shutdown; it is recorded as expiry, not denial. |
| Rebuilt Mac, restart and denial | The app restarted with Keys ready and Connected without new Keychain permission. After another actual relay restart it reconnected automatically; request `23479f4dc7a618795a7e2185a4244397` arrived and was explicitly denied, exit 1 with no fallback. |

### Fixes driven by these tests

- sudo's front end records signals while the synchronous approval callback runs. The plug-in now temporarily catches cancellation signals, uses bounded 100-ms IO/wait slices, closes the request on cancellation, and restores/re-delivers to the original handlers before returning or invoking PAM. Failure to restore signal state terminates rather than continuing. The installed Ubuntu ABI documentation permits temporary handlers with mandatory restoration; [upstream signal handling](https://github.com/sudo-project/sudo/blob/main/src/signal.c) explains why the original blocking wait missed Ctrl-C. A separate-process native regression test proves cancellation wakes blocked IO and preserves/re-delivers to the original handler.
- A stopped relay produced a completed, content-free Network.framework callback without WebSocket metadata. That now counts as ordinary disconnection, not a protocol violation requiring manual retry. Present or incomplete content without metadata still fails closed. Regression tests and a live relay restart passed. Trust failures and interrupted initial client authorization still require explicit retry.

Current native package SHA-256: `f59637c542a925826827c3e116f71d8c396ac3d017ed42d417f6918bfe9ac7fc`, staged from root-owned `syn-cancellation.deb` in the existing protected backup. This supersedes both earlier package hashes. Installed plug-in bytes matched the native release output. Authentication-file hashes matched the baseline before staging and shadow reapplication.

Current checks: **31 local Rust tests, 39 native Pi Rust tests, 23 Swift tests**, Rust formatting, local/native Clippy with warnings denied, ARM64 plug-in Clippy/type-check, fixture comparison, app build/strict signature verification, and diff whitespace checks passed.

Luis is away from the Mac. No further fingerprint prompt will be opened unattended. A successful real sudo approval on the final rebuilt versions remains required; after recovery, the expired preflight must first be refreshed through a real signed approval. Do not fabricate or extend the evidence marker to avoid that check. A one-minute Pi-local rollback was armed at 04:30:20 UTC for deadline `1788496280`; its actual result is recorded in the next checkpoint.

### Automatic recovery and safe end state — 04:31–04:33 UTC

- The Pi's journal records systemd starting real recovery at **04:31:20 UTC** and finishing successfully at **04:31:21 UTC**. No SSH recovery command was issued during that interval. The service restored sudo.conf and archived the shadow state as `sudo.conf.shadow.1788495775486.recovered-state.json` before canceling its own timer.
- Byte comparisons verified sudo.conf, sudoers, sudoers.d, and all captured PAM files against the protected backup. Sudo alternatives (including auto mode) and stat overrides matched exactly. Both sudo providers retained root:root mode 4755; `/usr/bin/sudo` still resolves to `/usr/lib/cargo/bin/sudo`. Sudoers parsed successfully.
- No install state, Syn managed rule, or Syn plug-in registration remains. Recovery status is not armed; its timer is inactive and disabled. The relay is active and disabled at boot, as it was before shadow testing.
- After explicitly invalidating the ordinary sudo timestamp, non-interactive sudo correctly required authentication. Fresh password sudo then printed root UID 0 and exited 0, without a Syn request.
- macOS is 26.6.1 build 25G76. Strict verification of the final app outside the Codex sandbox passed with the stable Apple Development designated requirement. The same check inside the sandbox reported an invalid signature; it was not treated as proof of a changed binary.
- Phase 5 is passed. Phase 6's cancellation, denial, malformed-reply, non-interactive timeout, interactive PAM fallback, and actual recovery checks passed on Ubuntu 26.04.1 ARM64. Its **final-build positive Mac approval** remains outstanding because Luis left the machine. The earlier real positive sudo result predates the cancellation patch and is not substituted for that retest.
- Final native rerun again passed all 39 Rust tests and warning-denied Clippy; golden regeneration byte-matched both committed copies. A bounded relay-journal scan found zero private-key/token/test-argument marker matches; this is a marker check, not a claim of complete secret-exfiltration testing.
- Source changes are staged against `4bf642d`, not committed or pushed. Git is configured for SSH signing through 1Password (`op-ssh-sign`); committing is deferred rather than opening a new approval prompt or disabling signing while Luis is away.

## Latest checkpoint — 04:13 UTC

The chronological sections below preserve earlier failures. They are superseded by this checkpoint where they describe Keychain permission as blocked or say no real signature has passed.

- **Real synthetic approval passed:** the user authenticated with Touch ID, and the installed Pi requester verified request `d6fafe6d1d3bc7b020bb885da573f418`, hash `b68b7124d39b18ba1a27a3022127a2a1a88d5c39a144b989e27e25634d7ab78d`, around 03:58 UTC. It wrote root-owned signed-preflight and pairing-complete evidence. The synthetic test does not execute a command.
- **Real denial passed:** request `bb96efc499746b019212b45ad7ee2418` returned a cryptographically verified explicit denial without approval-key authentication.
- **Fresh authentication passed again:** request `ff05f3d27bb0ebe56e27ad17d34c8677` was approved with another fingerprint. It was intended as a cancellation test, but the user confirmed using Touch ID; it is recorded as approval, never as cancellation.
- **Actual system Cancel passed:** for replacement request `5f5f35610cb17ed4fa2b935eb8a6000b`, the user pressed Cancel and the Pi verified an explicit signed denial. Syn displayed “Approval canceled or unsuccessful. Nothing was approved.” This is not an expiry result.
- **Stable restart passed:** the latest Apple Development-signed app loaded the same key identities and reconnected immediately without another Keychain permission dialog. The user confirmed choosing Always Allow previously. No identity was regenerated and no Keychain ACL was changed through CLI.
- **Notification gate remains open:** System Settings shows Syn notifications enabled for Desktop, Notification Center, and Lock Screen. The separate global setting suppresses notifications while sharing a display; it was not changed. Computer Use could inspect the calendar widget but timed out inspecting the menu-bar control. Actual banner contents and Review reopening a closed Syn window remain unverified. A harmless synthetic request during this inspection expired; it was not approved.
- **Sudo remains unchanged:** at 04:12:53 UTC, retained root access was healthy and no Syn install state, managed rule, or plug-in registration existed. The setup-only timer reached its deadline at 04:03:54 UTC; systemd correctly skipped recovery because no install state existed. This is not proof of shadow recovery. Re-arm and verify the timer before applying shadow mode.

### Prompt-loop diagnosis and corrections

The repeated prompts were not caused by the user failing to choose Always Allow. The Pi allowed only ten seconds for mutual-TLS setup while macOS was still asking for Keychain permission; logs aligned the client signing attempt with the server handshake timeout. Automatic retries could then leave the user approving a dead handshake. Repeated Keychain reads added further prompts.

- TLS setup now has a separate 120-second server budget and 130-second client budget. The signed command deadline is still exactly 30 seconds. The agent caps simultaneous connection attempts at four.
- Interrupted client authentication or trust errors require an explicit Retry connection action. Ordinary network failures still reconnect with bounded backoff. Successful hello clears the visible connection error.
- Setup loads the opaque Secure Enclave representation and denial material once per app lifetime before connecting. Every approval still creates a new authentication context with zero reuse, performs a protected key operation, and invalidates that context. Caching representation is not caching user authentication.
- Expiry, cancellation, and concurrent Deny now invalidate an in-flight authentication context. Unit tests cover cancellation before prompt creation and expiry during signing; actual user Cancel is also verified above. Automatic dismissal of an untouched expired system prompt still needs a live check.

### Current build and staging evidence

- Local Rust: 31 tests; native Pi Rust: 38 tests, including seven Linux plug-in tests. Formatting, Clippy with warnings denied, ARM64 plug-in checks, and golden-vector comparisons passed.
- Swift: 22 tests passed with warnings treated as errors. The latest app build and strict signature verification passed using the same Apple Development designated requirement; this is not Developer ID signing or notarization.
- Installed native package SHA-256: `5877bdd20723ff7f8459894bf605e79198cdd0ff0daa0f14c8927069ada1b01a`. This supersedes the earlier package hash below. Installed agent bytes matched the native release build after restart.
- Protected staging backup: `/var/backups/syn/phase56-promptfix-20260904T0350Z.YEc0Qm`; authentication manifest SHA-256: `8e4f24bb680dd003b1bddc85a7a32ff1420a78b39b64ebaa777242d8b1a0c170`. Sudo/PAM contents, provider ownership/modes, alternatives, and stat overrides matched before and after package installation.
- The unprivileged relay remains active on the exact Meshnet address and disabled at boot. Neither shadow sudo nor passwordless policy coupling has been applied.

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

## Completed scope and remaining limits

- Phases 5–6 are complete, including final-build real approval and baseline restoration. Earlier incomplete checkpoints above are retained as test history.
- No passwordless arming, provider overrides, package-manager installation, or Phase 7 work was performed. Mac login-password fallback and automatic dismissal of an untouched expired prompt are not claimed as tested.
- The local checkpoint uses the existing Git signing configuration; no push is authorized.

The Pi is **not armed**: the temporary shadow plug-in registration was removed after the successful final test, and no passwordless rule was ever created. The Mac/Pi pairing, device-owned private keys, restricted firewall rule, staged package, and unprivileged relay remain setup state. The relay is not enabled at boot. Establish fresh root recovery access and re-arm the timer before any future shadow setup.
