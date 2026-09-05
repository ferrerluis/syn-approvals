# Adversarial follow-up: P1 hardening branch

Scope: `codex/fix-p1-security-gaps`, originally reviewed at `bd66ce6` against `main` at `4b452c7`. A separate security-review sub-agent challenged the new provider protection, hidden-environment restrictions, recovery behavior and compatibility. This is an AI-assisted internal review, not the independent security review required for public release.

The reviewer found no additional demonstrated P0/P1 bypass under the ordinary managed-user/compromised-relay threat model. It did find a merge-blocking P2 compatibility regression and a privileged-concurrency recovery risk. The [original assessment](security-assessment-2026-09-04.md) remains a historical record, not a claim that every finding is closed.

## Fixed: ordinary sudo rejected before any approval

The original hardening matcher omitted `SUDO_HOME`, which sudo 1.9.17p2 itself generates. Its sudoers rule also appended package variables to the inherited defaults, preserving values such as `LS_COLORS` which the final matcher rejected. Either problem could prevent a normal invocation reaching the notification or eligible password fallback. [Pinned sudo environment implementation](https://github.com/sudo-project/sudo/blob/v1.9.17p2/plugins/sudoers/env.c).

The correction validates `SUDO_HOME` against the invoking account's NSS home, separately from the run-as account's `HOME`. Managed-user `env_keep` and `env_check` now replace the built-in lists with explicit supported names; unsupported inherited metadata is discarded by sudo rather than admitted through a broad plug-in exemption.

Regression tests cover source-derived sudo-generated fields, expected inherited/discarded names, the alignment of every configured inherited name with the final validator, wrong-home rejection and malicious values reintroduced after normalization. Diagnostics remain fixed categories with no environment names or values; the protocol, Mac approval flow and 90-second deadline are unchanged.

The same reviewer re-examined the correction and repeated its validator probe. It confirmed that the original merge blocker was corrected and identified no further merge-blocking finding; guarded live sudo acceptance remains required.

## Fixed: hosted Swift checks never reached the tests

SYN-SEC-006: the macOS runner's default Xcode has Swift 6.1, but Syn requires Swift 6.2. CI now selects the preinstalled Xcode 26.2 explicitly, reports the compiler version and treats Swift warnings as errors. Rust CI uses the committed lockfile, and the privacy-checker tests now run in CI. [Official macOS 15 runner toolchain inventory](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md).

## Deferred P2: concurrent administrator override during aborted installation

Preparation records an alternate provider with no existing override as a planned Syn-owned change. If a privileged administrator adds an identical protective override before `protect()` applies it, protection detects the change and aborts, but recovery cannot distinguish that new administrator override from one Syn created; it may remove it and restore the previously recorded mode.

This requires concurrent privileged activity, not an ordinary-user or relay exploit. Recovery still removes `NOPASSWD` first, so the scenario does not establish an ungated passwordless-sudo interval. The fix needs durable per-operation ownership/apply state and transaction coordination, with crash/interruption tests against the real package tools; a post-success flag alone would leave a crash window and is not an adequate fix.

Do not run installation/recovery concurrently with package maintenance or administrator provider changes. This limitation remains open; no privileged transaction code was added merely to satisfy this review without the corresponding fault-injection validation.

## Qualified claim: newly relocated sudo providers

The branch closes the original case where a known non-setuid provider lacks a persistent override and an upgrade restores its setuid bit. Complete inventory verification is performed during installation and diagnostics, not continuously on every possible provider execution. A future package relocating a setuid provider to a new path needs a new audit; this branch does not establish automatic protection against arbitrary future package-layout changes.

## Validation and rollout limits

See the [hardening validation record](p1-hardening.md#validation-and-deployment-boundary) for the Mac, ARM64, formatting, strict lint, protocol-vector and privacy checks. No live sudo policy, installed plug-in, Mac app, pairing identity, service or recovery timer was changed during this review.

The branch still needs a separately guarded privileged rollout with independent recovery access and live approval/denial/timeout/recovery acceptance. Other original P2 findings (display ambiguity, large-message decoding and decision-routing isolation) remain open; they were not silently reclassified by this branch review.
