# TLS callback isolation crash — 2026-09-04

Status: **fixed and live-regression tested**. This follow-up starts from commit
`8ab2147a8e1edd059744408de4159ba9a8a15106` on branch
`codex/validation-phases-9-10`. It does not change the Pi enforcement path or
replace the completed Phase 9–10 acceptance ledger.

## Report diagnosis

The supplied crash report is real, but it is not from the app installed during
the final Phase 9–10 validation. It records an unsigned transient build at
23:07:09 EDT on 2026-09-03, launched from a user build path. Its executable UUID
is `18B6D754-0234-30C5-AFF8-3FE71A41FC98`.

The failing thread was Network.framework's
`org.syn-approvals.tls-verification` queue. The stack reached
`_swift_task_checkIsolatedSwift`, then `_dispatch_assert_queue_fail`, from the
trust callback inside `TargetConnection.start()`. The callback had inherited
`TargetConnection`'s `MainActor` isolation even though Network.framework invokes
it on the configured TLS verification queue. Swift therefore trapped before
certificate verification completed.

## Correction

TLS verification is now created by an explicitly `nonisolated` static factory.
The returned `@Sendable` callback captures only immutable hostname and pin values
plus the lock-protected handshake tracker. Trust evaluation remains unchanged:
the exact certificate pin, hostname, validity, private trust anchor, and disabled
network fetch are still required.

A synchronous nonisolated test constructs the callback outside `MainActor`.
Removing the factory's isolation boundary now fails at compile time rather than
waiting for another live TLS crash.

## Verification

- Swift build and all 25 tests passed with warnings treated as errors.
- Local Rust formatting, warning-denied Clippy, all 37 tests, the ARM64 plug-in
  check, and four log-privacy tests passed.
- Native Pi formatting, warning-denied Clippy, all 47 tests, and four
  log-privacy tests passed from the synchronized source.
- The installed app is strictly signature-valid. Its executable UUID is
  `56B9F804-54F3-3060-9179-86949A9337ED` and SHA-256 is
  `3916dde9273e23da42aded23f2653a70e37ed7b0a44f28e720f4d6ba56e94f38`.
- The installed app completed its initial connection and three full
  quit/relaunch mTLS reconnect cycles. Every cycle returned to `Connected` for
  `pi-main`, exercising the TLS verification callback on the real network path.
- Final request `5a6a32f0221e0107ba616bcce3adaa2e` passed through the newly
  installed app with fresh Touch ID. The original Pi
  `sudo -n /usr/bin/id -u` process returned root UID `0` and exit 0; no Ubuntu
  password or fallback path was used. Syn returned to its connected idle state.
- At 20:38 UTC, the new app process was still running and macOS had created no
  `Syn` diagnostic report since this build was installed.

The previous installed bundle is retained temporarily at
`/private/tmp/Syn-before-tls-fix.app` for recovery. This is bounded regression
evidence for the reported failure, not a claim that unrelated Mac crashes are
impossible.
