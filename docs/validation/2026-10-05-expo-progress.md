# Expo mobile implementation progress

This is an incomplete local candidate on `codex/ios-approver`, in the existing isolated worktree. Swift rollback point: `12e207ddbfd710f7828ec85f8cfdabfde8da85b5`. No changes to the real Pi installation have been applied during this Expo implementation. The registered goal remains incomplete.

## Implemented

- React Native UI with Expo 57.0.26, React Native 0.86.3, React 19.2.3, and a checked-in npm lockfile.
- Local Expo module wrapping native Swift request verification, pairing, pinned connections, identity storage and request-bound signing. JavaScript cannot supply signing payloads or private keys.
- Typed setup/status/review/error/expiry UI, user IDs and group, environment names/digest, warning markers, machine fingerprint, secret argument reveal, Approve and Deny. Malformed native state clears stale approval controls. The existing Mac candidate already uses Approve; one invocation semantics remain unchanged.
- Reproducible XCFramework scripts with checked-in Swift package pins. Generated Expo native projects are separate from shared Swift sources.
- Embedded production JavaScript in Debug simulator acceptance, remote updates disabled, and simulator-only development keys explicitly labeled. Xcode provides simulator entitlement embedding; host executable entitlements are empty.
- APNs registration, delivery and entitlements removed. Codex attention instructions preserve the original command process and never treat a reply as authorization.
- Pinned local agent-device 0.21.20, semantic simulator checks, screenshots and Maestro-compatible regression flows.

## Passing checks so far

| Check | Evidence |
|---|---|
| Expo lint | `npm run lint` passes |
| TypeScript | `npm run typecheck` |
| Typed state tests | 5 passed, including malformed identities/digests/argument order and unknown machine rejection |
| React Native UI tests | 9 passed; ID-only approval, expiry, denial during authentication, lifecycle disconnect, approval while setup waits, complete review fields, stale-state removal, changed-host setup binding |
| Expo Doctor | 21/21 passed |
| Standalone simulator build | Xcode 26.6 / iOS 26.5, embedded release JavaScript, Metro absent on port 8081 |
| Native iOS tests | 19 passed in the iPhone 17 Pro simulator, including display privacy/reveal and foreign-machine rejection |
| Native production framework | unsigned Release compilation for iPhone ARM64 succeeded; hardware authentication remains unverified |
| Rust Clippy | workspace/all-targets, warnings denied |
| Rust tests | 106 passed across workspace test binaries/doc tests |
| macOS Swift tests | 149 passed with warnings treated as errors |
| Golden vectors | Rust regenerated protocol-v2 and both fixture copies matched; Swift review encoding also matches a shared JavaScript display fixture |
| ARM64 checks | workspace/all-targets type-check and Clippy with warnings denied; 124 Rust tests executed on isolated Ubuntu ARM64 |
| Privacy / release staging | log privacy 4 tests; iOS release staging 3 tests, including generated-cache allowance and hidden-source rejection |

Detailed local logs are under `/private/tmp/syn-expo-*` and `mobile/artifacts/`. Simulator UUID: `A0231B4A-C845-463B-BE74-8E5CBD9F2A04`. Screenshot `mobile/artifacts/01-standalone-start.png` proves app startup and its signer label. Screenshot `mobile/artifacts/02-real-pi-ssh-fingerprint.png` proves SSH contact with the real Pi; its displayed Ed25519 fingerprint matches an independent existing SSH session. Neither screenshot proves signed request reception or sudo execution. Current-build screenshots and exact compile metadata are recorded in ignored `mobile/artifacts/2026-10-05-expo-evidence.json`. A Maestro-compatible SSH setup flow passed through agent-device against the real Pi and is now kept at `mobile/flows/setup-ssh.yaml`; it checks the independently trusted fingerprint without authorizing setup. Recorded `.ad` replay rejected a changed accessibility ancestry before its first tap; that failed replay remains in the evidence record.

## Outstanding acceptance

The user approved the bounded phone installer/recovery scope. The candidate now implements per-phone retained helpers/account bindings, fixed bounded uploads with permanent privilege removal, phone-first/additional identities, native matching-release setup/update and phone-only setup-key revocation. Isolated ARM64 installation/update/rollback and live acceptance remain unverified. The Mac maintenance key and real-Pi recovery route have not been changed.

The real Pi runs its prior release and does not yet have mobile enrollment commands. A matching candidate must be installed only after isolated Ubuntu ARM64 testing with independent recovery access. Required real-Pi proof remains: Connected, signed pending request, Approve, the original `/usr/bin/sudo -n /usr/bin/true` exits zero, a fresh repeat needs approval, and Mac pairing still works. Live race/failure checks are still pending. The unsigned production Expo app compiled successfully at candidate `1e5766814011f6261627a26d08e2ff7d34993425`, with embedded JavaScript, a Secure Enclave symbol, and no simulator signer in its native framework. Subsequent review checkpoint builds are recorded separately with their exact source commit in local evidence.

An isolated Ubuntu 26.04 ARM64 QEMU guest is running with independently verified root SSH recovery under `/private/tmp/syn-expo-arm64-vm`, using an official checksum-verified cloud image. It is separate from the Pi and uses a disposable SSH identity. Recovery checks confirm `aarch64`, Ubuntu `26.04`, root UID `0` and active SSH. The default sudo is sudo-rs and sudo.ws is also installed; the existing alternate-provider audit must be preserved during installation. Its image SHA256 is `63a93bd5a8d76e33b15ceb5daa3657bd79be804748051ab178e643b0f5da22e7`.

## Native Ubuntu ARM64 execution

All 124 existing Rust tests passed as the unprivileged `syn-test` account in the isolated Ubuntu 26.04 ARM64 guest, including the explicitly enabled read-only sudo search-path test. Cross-built executables were linked against that guest's actual public PAM library and SHA-256 checked before execution. See [exact test artifacts and recovery results](2026-10-05-arm64-tests.json).

The first runs exposed two invalid Linux-only test fixtures: a mismatched signing key ID and an approval without the required authentication class. Both are already rejected before signing. The corrected test asserts those rejections and separately verifies target rejection of a valid signature under the wrong key role; production authentication code is unchanged. Rust formatting and workspace/all-target ARM64 Clippy with warnings denied pass after this correction.

Root SSH recovery remains available, no Syn sudoers file is installed in the guest, and unprivileged noninteractive sudo exits 1. These tests do not exercise a Syn installation or the original real-Pi command. The latest simulator and unsigned production app builds remain tied to `dabe1490c8a7a5cd2f29305922e2dfda216a3939`; only Linux test fixtures and validation records changed afterward.

## Dependency findings

`npm audit --omit=dev` currently reports 24 high findings arising from two upstream advisories: [braces recursion](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) and [node-forge RSA verification](https://github.com/advisories/GHSA-86w9-cpqp-85rv). Both advisory pages currently list no patched version. The suggested forced fix downgrades Expo to SDK 44 and is not compatible with this plan.

These packages occur in the Expo/Metro tooling dependency graph. Syn request authentication, certificate generation/checks and signing use the native Swift core. This is not a claim that the entire dependency tree is vulnerability-free; builds should consume the locked, trusted source and avoid exposing development tooling to untrusted input. A UUID override removes the separately fixable older UUID finding.

## Scope limits and cleanup

Apple enrollment, physical-device installation, hardware Secure Enclave proof and real Codex phone notification delivery are outside simulator acceptance. No Syn push credentials were created. Generated projects, dependencies, framework output, VM keys and local evidence are ignored or outside the repository. Keep the worktree and VM artifacts until acceptance finishes; record final recovery checks and remove disposable access when testing ends.

## Approved installer candidate checks

The new installer regressions reject unsupported commands/paths, partial or changed uploads, symlinks, other-device/account requests and development signing without an explicit grant. A shared `mobile-onboarding-v1.json` golden is decoded and re-encoded by Rust, macOS Swift and iOS Swift. The mobile UI also rejects setup controls after changing the Linux account.

Host Rust tests: 111 passed (one platform-specific test ignored); macOS Swift: 150 passed; mobile: 5 state and 10 UI tests; native iOS: 20 tests passed after the profile-import adjustment. Formatting, host/ARM64 Clippy, TypeScript and Expo lint pass at the checked candidate stages. Exact non-development builds and live guest execution must still be completed for this installer candidate.

Phone-led updates also accept signed preflight from a currently paired additional approver. Request binding, approval/denial key roles, required authentication class and expiry remain enforced; installer evidence is checked against the current trust set. The returned signer ID identifies the device that actually approved.

## Native phone-first ARM64 milestone

At `f468fcd0bcd96ec5936d4e3c797a5a95154f02c9`, release `20261005184947`, the Expo Debug simulator completed the native phone-led installation on the isolated Ubuntu 26.04 ARM64 VM. Two separate signed setup requests were approved and operation `e59cdcc66f86460e882c55310336be7f` reached `complete`. The simulator uses explicitly granted development keys; this does not verify hardware Secure Enclave behavior.

The first matching-release update exposed a stale relay process: its executable SHA-256 differed from the installed executable. The app rejected its older release handshake. A diagnostic relay-only restart through independent root SSH restored Connected; the following native setup retry completed. Configuration now explicitly restarts the relay after installing/configuring its package; a subsequent automatic update must verify this fix before real-Pi deployment.

Local pinned agent-device Maestro-compatible flows verified the target/user, `/usr/bin/true`, per-invocation scope and Approve. The original `/usr/bin/sudo -n /usr/bin/true` under UID 1000 exited zero for PID 40337 (17.755 seconds) and a fresh repeat PID 40447 (13.715 seconds), each after a separate simulator approval. Earlier manual attempts expired and exited 1; no late success was reported. These are actual sudo invocations on the isolated VM, not the real Pi.

Local screenshots: `mobile/artifacts/07-phone-setup-approval.png`, `08-phone-final-approval.png`, `09-phone-setup-complete.png`, `11-arm64-original-sudo-flow.png`, and `12-arm64-repeat-sudo-flow.png`. Public exact process receipts are retained under `/private/tmp/syn-expo-arm64-vm/`; native ARM64 workspace tests passed 130 tests, followed by both read-only protected-target checks. Current host Rust tests pass 112 tests, macOS Swift 150, and native iOS 24, with the shared setup-probe golden and required Clippy checks passing.

Original sudo success/repeat, automatic update/rollback, live failure cases and Mac pairing on the real Pi remain required. The real Pi still runs `20260921060301`; no Expo implementation changes have been applied there.

## Automatic update, final-denial recovery and certificate rejection

Code candidate `d381856eb1a4b2b3d85cefb947572787b3f4cbc8`, release `20261005193050`, compiled both the unsigned production Expo app and the standalone Debug simulator app with the exact verified native ARM64 helper. Both embed JavaScript; Metro was stopped. The production framework excludes the simulator signer. The helper passed its loader and compiled-release checks on both the isolated Ubuntu ARM64 VM and the real Pi as an ordinary user, without changing the Pi installation.

The phone used its existing restricted setup key to update the isolated guest. Operation `29732137d70f4950be08390c0d341bae` reached `complete`; the relay restarted automatically, and its loaded executable SHA-256 equaled the newly installed executable. The first setup decision ran through the flow; an offscreen final-request wait failed, after which a manual agent-device tap completed the still-live final request. No administrator relay restart or new setup grant was used. Earlier failed flow attempts and the preflight expiry are retained in the local artifacts rather than reported as successful updates.

The committed original-invocation flow then passed twice at this release. The original UID-1000 `/usr/bin/sudo -n /usr/bin/true` processes were PID 59720 (exit 0, 10.940 seconds) and fresh repeat PID 59817 (exit 0, 13.120 seconds). The earlier live Deny test, PID 44038, exited 1 in 11.658 seconds. These are isolated-VM results; the real-Pi original invocation is not yet proven.

The corrected full setup flow passed in 156.6 seconds for operation `dd09046275e44d82b89e93df55ef1f16`, approving the first harmless preflight and denying the final verification. An independent root observer recorded activation with `/etc/sudoers.d/90-syn-managed-user` present and both alternate providers at mode 0755. It then observed the rule removed before provider restoration, followed by the original sudo-rs alternative and both providers restored to 4755. Independent SSH remained active, automatic recovery was disarmed, and subsequent noninteractive sudo required a password. This proves recovery to ordinary password sudo; it is not a package downgrade.

A temporary replacement of the guest relay's public certificate produced the visible error “The target TLS certificate does not match its pinned fingerprint.” The test restored the original certificate automatically; explicit Retry reconnected. A prior live relay stop/start also showed Disconnected followed by Connected. The new app rejected the previous relay release before updating. Native ARM64 tests cover signed replay against changed execution intent and nonce, rejection of another device's decision, and cancellation after competing valid responses; live Mac/phone cancellation on the real Pi remains required.

Current checks: host Rust 112 passed; native Ubuntu ARM64 Rust 130 passed, two protected-target tests separately passed while armed at the previous candidate; macOS Swift 150 and native iOS 24 passed for unchanged Swift sources; TypeScript, 5 state tests, 10 UI tests, Expo Doctor 21/21, Rust formatting and warning-denied host/ARM64 Clippy passed. The matching Mac candidate also built and signed with the existing Apple Development identity but has not replaced the working old Mac app. Hardware Secure Enclave behavior remains unverified.

Public receipts are in `/private/tmp/syn-expo-arm64-vm/` and `mobile/artifacts/2026-10-05-expo-update-evidence.json`. Screenshots include `19-arm64-phone-update-first.png`, `19-arm64-phone-update-final-manual.png`, `20-arm64-phone-update-complete.png`, `21-arm64-updated-original.png`, `22-arm64-updated-repeat.png`, `23-arm64-final-denial-first.png`, `23-arm64-final-denial-final.png`, `23-arm64-final-denial-result.png`, `24-arm64-certificate-rejected.png` and `25-arm64-certificate-restored.png`. A diagnostic sudo-rule flag used the wrong filename; its receipt explicitly marks that probe invalid. The correct root observation and doctor coupling report are the installation/recovery evidence.

The Pi's existing restricted root maintenance probe passed and its working Mac app still showed Connected. Only ordinary-user bootstrap files have been staged there; their helper and script hashes match the local candidate. An attempted bootstrap through sudo was blocked by Syn's existing policy against direct root shells/interpreters before execution. The trusted administrator bootstrap still needs the Pi password's 1Password item reference; no Syn policy was weakened and no privileged Expo changes were applied to the Pi. Real-Pi sudo success/repeat, matching Mac request receipt/cancellation and final cleanup remain outstanding.
