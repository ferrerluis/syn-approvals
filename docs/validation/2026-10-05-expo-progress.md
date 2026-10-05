# Expo mobile implementation progress

This is an incomplete local candidate on `codex/ios-approver`, in the existing isolated worktree. Swift rollback point: `12e207ddbfd710f7828ec85f8cfdabfde8da85b5`. No changes to the real Pi installation have been applied during this Expo implementation. The registered goal remains active.

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
| React Native UI tests | 8 passed; ID-only approval, expiry, denial during authentication, lifecycle disconnect, approval while setup waits, complete review fields, stale-state removal |
| Expo Doctor | 21/21 passed |
| Standalone simulator build | Xcode 26.6 / iOS 26.5, embedded release JavaScript, Metro absent on port 8081 |
| Native iOS tests | 19 passed in the iPhone 17 Pro simulator, including display privacy/reveal and foreign-machine rejection |
| Native production framework | unsigned Release compilation for iPhone ARM64 succeeded; hardware authentication remains unverified |
| Rust Clippy | workspace/all-targets, warnings denied |
| Rust tests | 106 passed across workspace test binaries/doc tests |
| macOS Swift tests | 149 passed with warnings treated as errors |
| Golden vectors | Rust regenerated protocol-v2 and both fixture copies matched; Swift review encoding also matches a shared JavaScript display fixture |
| ARM64 checks | workspace/all-targets type-check and sudo plugin Clippy with warnings denied |
| Privacy / release staging | log privacy 4 tests; iOS release staging 3 tests, including generated-cache allowance and hidden-source rejection |

Detailed local logs are under `/private/tmp/syn-expo-*` and `mobile/artifacts/`. Simulator UUID: `A0231B4A-C845-463B-BE74-8E5CBD9F2A04`. Screenshot `mobile/artifacts/01-standalone-start.png` proves app startup and its signer label. Screenshot `mobile/artifacts/02-real-pi-ssh-fingerprint.png` proves SSH contact with the real Pi; its displayed Ed25519 fingerprint matches an independent existing SSH session. Neither screenshot proves signed request reception or sudo execution. Current-build screenshots and exact compile metadata are recorded in ignored `mobile/artifacts/2026-10-05-expo-evidence.json`. A Maestro-compatible SSH setup flow passed through agent-device against the real Pi and is now kept at `mobile/flows/setup-ssh.yaml`; it checks the independently trusted fingerprint without authorizing setup. Recorded `.ad` replay rejected a changed accessibility ancestry before its first tap; that failed replay remains in the evidence record.

## Outstanding acceptance

Phone-first installation, matching-release updates and rollback are not implemented yet. Automatic approval review rejected the proposed root installer/forced SSH endpoint change as too broad without specific approval; a separate, bounded scope was presented for approval. No edits from that rejected call were applied. The Mac maintenance key and recovery route remain untouched.

The real Pi runs its prior release and does not yet have mobile enrollment commands. A matching candidate must be installed only after isolated Ubuntu ARM64 testing with independent recovery access. Required real-Pi proof remains: Connected, signed pending request, Approve, the original `/usr/bin/sudo -n /usr/bin/true` exits zero, a fresh repeat needs approval, and Mac pairing still works. Live race/failure checks are still pending. The unsigned production Expo app compiled successfully at candidate `1e5766814011f6261627a26d08e2ff7d34993425`, with embedded JavaScript, a Secure Enclave symbol, and no simulator signer in its native framework. The subsequent review changes need a fresh app build.

An isolated Ubuntu 26.04 ARM64 QEMU guest is running with independently verified root SSH recovery under `/private/tmp/syn-expo-arm64-vm`, using an official checksum-verified cloud image. It is separate from the Pi and uses a disposable SSH identity. Recovery checks confirm `aarch64`, Ubuntu `26.04`, root UID `0` and active SSH. The default sudo is sudo-rs and sudo.ws is also installed; the existing alternate-provider audit must be preserved during installation. Its image SHA256 is `63a93bd5a8d76e33b15ceb5daa3657bd79be804748051ab178e643b0f5da22e7`.

## Dependency findings

`npm audit --omit=dev` currently reports 24 high findings arising from two upstream advisories: [braces recursion](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) and [node-forge RSA verification](https://github.com/advisories/GHSA-86w9-cpqp-85rv). Both advisory pages currently list no patched version. The suggested forced fix downgrades Expo to SDK 44 and is not compatible with this plan.

These packages occur in the Expo/Metro tooling dependency graph. Syn request authentication, certificate generation/checks and signing use the native Swift core. This is not a claim that the entire dependency tree is vulnerability-free; builds should consume the locked, trusted source and avoid exposing development tooling to untrusted input. A UUID override removes the separately fixable older UUID finding.

## Scope limits and cleanup

Apple enrollment, physical-device installation, hardware Secure Enclave proof and real Codex phone notification delivery are outside simulator acceptance. No Syn push credentials were created. Generated projects, dependencies, framework output, VM keys and local evidence are ignored or outside the repository. Keep the worktree and VM artifacts until acceptance finishes; record final recovery checks and remove disposable access when testing ends.
