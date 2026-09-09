# Syn: sequential end-to-end acceptance tests

Plan only. **12 live test cases**, run sequentially by one dedicated Sol agent after component tests pass. This covers the [Mac-led delivery plan](distribution-onboarding-plan.md), including actual uninstall from both devices and reinstall through the new flow.

## Ownership and preparation

The E2E agent alone uses Computer Use and changes the live Mac/Pi during acceptance. Implementation agents test components and fix code in separate worktrees; they do not run their own live E2E passes. Coordinate through Codex messages, with the orchestrator reviewing results and controlling handoffs.

Before starting:

- Pass Rust/Swift checks, relevant ARM64 tests and protocol fixtures. Keep exhaustive input, timing, identity and crash permutations in component tests.
- Prepare genuine downloadable releases **A and B**, each with matching Mac/remote timestamp IDs and exact commits. Use a Mac-only change for B to exercise publishing both components anyway.
- Inventory the real devices and confirm an ordinary LAN route is available. Prove administrator recovery independent of Syn; preserve the installed app/package, sudo configuration and relevant settings in protected backups.
- Preserve Secure Enclave/Keychain identities. Reversibly clear active app profiles/preferences for clean onboarding; disclose any reused identities rather than claiming first-ever key creation.
- Arrange one user-assisted window after unattended preparation. Group real authentication here, pause safely if Luis leaves, and never promise one fingerprint for multiple command approvals.

Use Computer Use for the actual download/setup/update screens and SSH for remote observations. Use harmless commands such as `sudo /usr/bin/id -u`; verify remote execution, not just the Mac's success message. Expire sudo authentication timestamps before password checks. Keep credentials, private keys and sensitive command data out of evidence; use elevated `op` only immediately before an authorized password use.

## The 12 cases

Run in order. Each bundled case passes only when its listed outcomes pass; record any failing step explicitly.

| ID | What to do | What must be true |
| --- | --- | --- |
| E01 · Uninstall both devices safely | Prove recovery access and backups. Uninstall Syn from the Pi, verify password sudo, then quit/remove the Mac app, unregister its login item and reversibly clear active profiles/preferences. | Actual app/package removal, not an install-over. No Syn process/listener, dangling plug-in reference or ungated `NOPASSWD`. Password sudo works, unrelated administrator settings remain intact, and retained keys/backups are listed. |
| E02 · Setup errors are recoverable | Download A through README and open Add a machine. Try an unreachable hostname and cancel authentication before using the correct connection. | Clear errors and retry; failed/canceled authorization makes no remote installation changes. No stored passwords or need to repair SSH configuration. |
| E03 · Fresh Mac-led installation | Choose No for startup, then enter the real hostname/account. Run Syn's one-time bootstrap command in the trusted administrator session established in E01, then continue installation and pairing in Syn. Complete setup approvals. Relaunch, then enable startup in Settings. | The Mac never asks for or transmits the remote password. The restricted key rejects shell/extra-command and forwarding requests; the helper rejects a substituted hash. No manual profile/key transfer. Both report A and become Ready only after real health checks. One app/target; pairing survives relaunch; startup settings match macOS. |
| E04 · Offline update, then A → B | Make the test update route temporarily unavailable while preserving recovery access. Open downloaded Mac B and check the mismatch; restore the route and use the Mac update flow to bring the Pi to B. | Offline/update-required status is accurate; mismatched versions cannot approve, including over an old connection. Retry obtains necessary authorization, installs exactly B, preserves keys/settings and cancels recovery only after health success. |
| E05 · Notifications and fresh approvals | Close the main window, trigger a harmless command, open Review from its notification and approve with Touch ID. Immediately run a second command and approve using the Mac login password. | Privacy-safe notification; Review opens the intended app. Correct machine/action shown; both commands execute once, with separate requests and fresh system authentication. |
| E06 · Denial and cancellation | Deny one request. For another, cancel the real system-authentication dialog. | Neither command executes; pending UI clears. No password fallback for the explicitly denied invocation and no cancellation counted as approval. |
| E07 · Immediate password escape | While waiting, press Enter and use the Pi password. Repeat with one incorrect synthetic password and cancel; also verify that Enter after a completed denial cannot reopen that invocation. | Correct password executes the original command once without waiting 90 seconds. Wrong password does not execute. Pending approval is invalidated and late decisions cannot execute again. Respect PAM lockout policy. |
| E08 · Timeout and non-interactive behavior | Leave an interactive request unanswered for 90 seconds, then use password fallback. Run `sudo -n` once with a Mac approval and once unanswered. | No early execution/fallback. Interactive authentication completes once; non-interactive approval works, but unanswered non-interactive sudo fails without a password prompt. Production timing stays unchanged. |
| E09 · LAN, disconnection and reconnect | Verify a real approval through an ordinary LAN hostname/address. Close installer SSH sessions, interrupt only Syn's connection, then restore it and approve again. | No provider selection, fixed Mac-IP requirement or persistent SSH tunnel. Actual traffic uses the LAN route; disconnection never approves anything. Reconnect verifies the same paired identity. A separate SSH session used to trigger sudo is not an approval tunnel. |
| E10 · Failed update and reboot recovery | Using the protected restore procedure, establish A again for one guarded A → B attempt. Interrupt it during final activation while recovery is armed; reboot the Pi before the recovery deadline. Observe recovery, re-establish independent access, then retry through the Mac. | The original deadline survives reboot without extending. Recovery actually restores password sudo without the Mac, not merely a timer status. No ungated passwordless state or false Ready. Retry finishes on B with preserved identities/settings. |
| E11 · Mac lost, local access retained | Quit/uninstall Syn on the Mac first. Use Enter-to-password on the Pi, then its supported local recovery/uninstall procedure. | Losing the Mac does not prevent password administration or removing Syn. Remote removal needs no Mac approval; retained data follows the documented policy. |
| E12 · Final clean reinstall and handoff | Clear active profiles using E01 safeguards, reinstall final B from its real download and Add a machine. Choose Yes in the first-launch startup prompt. Verify a fresh approval, password escape and final device state. | Matching final B on both devices; startup is really enabled and persists. One intended app/target, working sudo and no leftover maintenance timer, test service or privileged session. Report retained backups and restore unrelated settings/routes. |

E01 and E11–E12 exercise actual removal/reinstallation in both orders. Recovery copies stay protected and inactive; do not delete non-exportable identities to make a test appear cleaner.

Include maintenance access in E01/E11 cleanup: revoke Syn's exact root SSH entry with the retained helper and confirm unrelated SSH keys remain. Reversibly retain the Mac maintenance key for recovery, documenting it alongside Keychain identities. E12 must exercise bootstrap authorization again after revocation; E04 must reuse the established key without a remote password prompt. The bootstrap terminal must be outside the managed agent account's control; typing a password into an already compromised shell is not a safe substitute.

E10 uses only a recoverable failure boundary already proven by component tests. Never corrupt the user's sudo files, destroy the recovery tool, fill the disk or remove all administrator access. If independent recovery cannot be proven, stop before the mutation.

## Coverage moved out of the live suite

To genuinely reduce manual testing—not just rename 33 cases—implementation agents cover these with automated component or isolated integration tests:

- Malformed setup inputs, wrong/changed SSH and TLS identities, corrupted downloads, missing prerequisites and unsupported platforms.
- Release-ID tampering, downgrade handling, address re-resolution, duplicate setup and startup-prompt dismissal/error variants.
- Exhaustive Enter/approval/denial races, closed input, concurrent request routing and replay/expiry checks.
- Interrupted transfer/build, every maintenance journal boundary, ambiguous override ownership and multi-target isolation.

These checks are still required before E2E, but do not each require Computer Use, live device changes or Luis's authentication. Existing-alpha migration also needs isolated regression coverage; this live suite prioritizes the requested clean installation and real A → B update.

## Evidence, fixes and completion

Keep one concise result file under `docs/validation/`: case ID, release/commit, actual outcome, redacted evidence, cleanup and **pass / fail / blocked / not run**. Screenshots prove UI behavior; remote results prove execution. Do not label an isolated test as a real-device pass.

On failure, stop dependent work, restore a known state and send the issue to its implementation agent. The E2E owner keeps device control while fixes are reviewed. Rerun the failed case and affected checks; before acceptance, validate the 12-case sequence with the final A/B candidate pair. Group any unavoidable additional authentication rather than prompting throughout development.

Completion requires all 12 cases and prerequisite automated checks to pass, no unresolved critical/high findings, and working Syn on both devices. Missing LAN access, credentials or recovery access remains a stated blocker. Public notarization stays in separate TODO 5.
