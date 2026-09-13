# Test-only approval harness review — September 12

## Release preparation checkpoint

Signing blocker resolved by Luis's explicit permission for unsigned candidate commits. Candidate A is now local commit `abb48464fd1b381c77c020f1b14167848b7f114c`, parent `44df4880ec47e2854b1dcea48fb492f54b8670a4`, on `codex/e2e-candidate-a-20260912-2320`. Its worktree is clean and contains the ten previously tested paths plus the requested AGENTS.md autonomy guidance. The non-AGENTS diff hash remains the tested value below. Per-commit unsigned signing left repository/global Git settings unchanged; nothing was pushed or merged. Historical staged/signing-failure notes below describe the earlier checkpoint, not a remaining blocker.

The exact-candidate E2E builder and CI test wiring pass bounded independent review: 15 focused Python tests, shell syntax and diff checks passed. It requires a clean selected production checkout and matching release/source/helper artifacts, builds in staging, rechecks the checkout, and publishes output create-only after validation. No genuine new A/B artifacts have been built or published.

Candidate A is staged, **not committed**, in `/private/tmp/syn-candidate-a-20260912-2320` on `codex/e2e-candidate-a-20260912-2320`, based on live-verified main `44df4880ec47e2854b1dcea48fb492f54b8670a4`. Its 10 intended files contain the protocol cutover, shared fixture, production injection seams and narrow contract documentation, excluding test-only B support and user assets. Staged-diff SHA-256: `685c4e8e0b452ee588a310650d9a5f206d6384ee9b5da11550e52f7955ff895c`. Candidate Swift tests: 111 passed, one opt-in live-SSH test skipped.

The normal commit failed because the 1Password signing agent returned an error. An unsigned retry was rejected by policy; no commit exists and no further retry is authorized without resolving that decision. Additional temporary artifacts tracked for cleanup: this candidate worktree/branch, `/tmp/syn-candidate-a-build` and `/tmp/syn-candidate-a-swift-cache`. Preserve the staged work until it is safely committed/integrated; do not delete it as generic temporary data.

Pre-commit Pi checks subsequently passed against a source-only snapshot, not a fabricated candidate commit. The staged diff hash above remained unchanged before/after; corrected archive SHA-256 `345d7357a1e6a2d635c68e0cfefd7df80f16cb038d119b5859e1fca2bac351da` matched on Mac and Pi. Native rustc host: `aarch64-unknown-linux-gnu`. Formatting, workspace all-targets clippy with warnings denied, workspace tests (103 passed, two documented live checks ignored), and explicit ARM64 sudo-plugin clippy all passed. The first export omitted compile-time inputs; a later explicit-target attempt hit temporary-storage quota. Both were corrected without product changes or privileged actions.

Verified cleanup removed Pi `/tmp/syn-candidate-a-precommit.adNVJp`, `/tmp/syn-candidate-a-precommit.GJkDUJ`, the obsolete `/tmp/syn-protocol-verify.czm1rx`, and both Mac transfer archives. Pi `/tmp` then reported 3.0 GB free (63% used). No signing retry, candidate commit, release or live E2E occurred.

## Latest checkpoint: local empty-state smoke passed

The core signer review below is complete. The functional test runtime now has isolated dependencies, process-lifetime keys and a per-request grant inbox. The owner reports 16 focused tests and 127 full Swift tests passing, with one opt-in live-SSH test skipped; both app builds and shipping mock-symbol exclusion pass. The app has not been launched or connected to the Pi. These are component results, not E2E passes.

Graceful cleanup and explicit coordinator-owned crash-residual tracking now satisfy the build milestone. An initial concern about exposing public identities before a request grant was withdrawn: public keys do not authorize a decision, and pairing precedes request creation. Exact request validation remains required at signing.

Functional review found a **P2 pre-live gate**: the inbox accepted an insufficiently protected caller directory and read a grant before safely claiming it. Another local account could inject a grant if the app were paired using a group/world-writable directory. There is no currently deployed or paired exposure; the reviewer corrected the initial P1 label accordingly. The fix now requires owned non-symlink 0700 directories, regular owned 0600 bounded grant files, and identity-safe atomic claim before reading. The reviewer confirmed this authorization-boundary fix. Owner evidence: 18 focused tests, 129 full Swift tests with one explicit live-SSH skip, both build/isolation checks, and diff-check passed.

The final cleanup correction also passes review: graceful exit removes the identity-matched empty inbox even when no request arrived or the coordinator removed the offer, preserving grant/foreign files and replaced directories. Focused tests: 19/19 passed; diff-check clean. The final bounded reviewer reports no residual P0/P1/P2. Full builds were not repeated for this isolated cleanup edit.

The sole UI owner rebuilt and launched only the separate test app with a fresh private local profile. Computer Use showed the startup choice and real Pending/Machines/Add-a-machine empty UI, with login-at-start off and no authentication prompts. Final process session `25744` exited 0; its profile was empty after cleanup, the isolated preferences plist was absent, and `/tmp/syn-e2e-smoke.0JbEuR` was removed. An earlier empty preferences-file residual was removed and the test entrypoint now uses in-memory startup preferences; the production default is unchanged. Focused startup tests: 2/2 passed; rebuilt two-app isolation and diff-check passed.

No Pi connection, pairing, bootstrap, production-app replacement or login-item enablement occurred. Production target-file metadata remained unchanged (mtime, size and inode); this was not a before/after content-hash comparison. Production known_hosts remained absent. This is not an E2E case pass: process-only test keys do not prove pairing across relaunch, and mocked startup/notification adapters do not prove real OS behavior. Those acceptance requirements remain open. Live cross-device testing still needs the trusted administrator bootstrap and the final-approval ordering decision.

Retained Mac test artifacts requiring cleanup before goal completion: `/tmp/syn-e2e-app-output/SynE2E.app`, `/tmp/syn-swift-cache`, `/tmp/syn-clang-cache`, `/tmp/syn-e2e-swift-build`, `/tmp/syn-e2e-full-build`. Verify ownership and current contents before removal; preserve unrelated resources. The earlier Pi test directory was removed during the pre-commit cleanup recorded above.

A fresh read-only check confirmed ordinary `ssh pi` works, but this Mac has no saved SSH setup or maintenance private key for its legacy target. Protected remote maintenance files could not be inspected by the ordinary account; their absence is not proven. The one-time trusted administrator bootstrap remains a prerequisite for live lifecycle testing.

Core signer status: **fixed; bounded independent re-review clean**. Luis authorized adding these fixes to the test plan and continuing. The reviewer initially classified two findings P1; root reassessed them as P2 because this scaffold is undeployed, unpaired and confined to tests, with no demonstrated privileged execution path. All four corrections and the subsequent cleanup edge cases passed re-review. Nothing was deployed; this remains test-only groundwork, not a complete cross-device harness.

## Findings

| Priority | Finding | Required authorized correction |
| --- | --- | --- |
| P2 | `E2EScenarioSigner` validates the request at construction but later signs caller-provided bytes without verifying that they encode the permitted decision. | Bind signing to the exact verified request and expected decision-signature input. Reject substituted request, target, action, version and decision data at signing time. |
| P2 | The grant's expiry is not capped by the real request's expiry. | Reject expired requests at construction and signing; enforce the earlier deadline and one-use consumption. |
| P2 | Disposable-key cleanup trusts a supplied directory without ownership/symlink checks, then removes that directory. | Create and track an owned private test directory; verify its identity and exact contents before cleanup, refusing replacements or foreign files. |
| P2 | The resource manifest checks path spelling but not symlinks or ownership by its recorded run. | Reject symlink targets and bind resources to the exact run; refuse cleanup claims on another run's resources. |

Reviewed files: `macos/Tests/SynTests/E2ETestApprovalHarness.swift` and `scripts/e2e-resource-manifest.py`, with their tests. Proposed fixes require regression tests and a second independent bounded review. Passing existing tests does not override these findings.

## Resolution

- Signing validates the canonical signature input against the exact verified request, target, action, protocol, release and key at signing time. Expiry uses the earlier request/grant deadline; every attempt consumes the grant once.
- Disposable key creation, rollback and cleanup use descriptor-relative operations and identity-checked atomic staging. They preserve unexpected replacements and caller-owned roots. Regressions include partial writes, initial identity failure, expiry, substituted decisions, replay, symlinks and foreign files.
- Manifest validation rejects unsafe or symlinked resources, verifies ownership markers and binds source/profile/account/unit identities to the run. It remains dry-run-only with no command execution.
- Final independent Sol review found no residual P0/P1/P2 in these bounded changes. The reviewer inspected code/tests but did not rerun tests; the implementation owners supplied execution results below.

## Completed checks, not E2E acceptance

- Protocol flag change: Swift suite 111 passed; ARM64 workspace formatting, clippy and tests passed (103 tests, two existing ignored tests).
- Final target-specific check: `cargo clippy -p syn-sudo-plugin --target aarch64-unknown-linux-gnu --locked -- -D warnings` exited 0 on the Pi, session 80137, in `/tmp/syn-protocol-verify.czm1rx`.
- Final post-fix Swift suite: `swift test -Xswiftc -warnings-as-errors`, 124 passed; one opt-in real-SSH test skipped. This supersedes the earlier seven-test/117-test groundwork checkpoint.
- Post-fix manifest suite: eight regression tests passed; Python compilation and diff whitespace checks passed. No provisioning/execution API was added.
- No E2E case is newly passed by these component results.

## Temporary resources and deployment state

The unprivileged Pi directory `/tmp/syn-protocol-verify.czm1rx` contains the explicitly authorized minimal source archive/tree and build outputs. It remains for exact cleanup before goal completion. Earlier `/tmp/syn-protocol-verify.VTkQEh` was observed missing, not deleted by this verification step.

No privileged test account, service, paired test key, production trust change or reboot occurred. The next step is a separate test-app composition and isolated cross-device integration, using these reviewed helpers. Full E2E readiness, bootstrap/recovery and final production-key restoration remain unproven; this clean review alone does not satisfy those gates.

## Linux PAM boundary and final restore constraint

A separate test account cannot exercise Syn unless it temporarily becomes the exact managed UID and username: the approval plug-in passes other UIDs through without Syn ([linux.rs lines 245–254](../../crates/syn-sudo-plugin/src/linux.rs#L245)). The narrow isolated test can recover the production install, stage the run-owned account/configuration, and reuse Syn's existing shadow installation. Shadow mode registers the real approval plug-in while preserving providers and omitting Syn's production `NOPASSWD` rule ([installer.rs lines 111–130](../../crates/synctl/src/installer.rs#L111), [installer.rs lines 671–746](../../crates/synctl/src/installer.rs#L671)); its existing recovery restores the original sudo configuration and archives the shadow state ([installer.rs lines 749–790](../../crates/synctl/src/installer.rs#L749)).

The test account's ordinary, exact-command `PASSWD` sudoers rule means sudo performs its initial password authentication before calling Syn's approval plug-in. After that, pressing Enter in Syn still reaches the real `syn-sudo-fallback` PAM call ([linux.rs lines 287–331](../../crates/syn-sudo-plugin/src/linux.rs#L287), [linux.rs lines 896–906](../../crates/syn-sudo-plugin/src/linux.rs#L896), [linux.rs lines 1132–1160](../../crates/syn-sudo-plugin/src/linux.rs#L1132)). This is valid isolated coverage of Syn's fallback implementation, but it does **not** prove the production no-initial-password experience created by Syn's managed `NOPASSWD` rule.

Final production restoration cannot replay E05 evidence. Activation always requests a fresh signed preflight before installing ([onboarding.rs lines 795–849](../../crates/synctl/src/onboarding.rs#L795)), and completion requests another fresh signed proof before committing the recovery helper and disarming recovery ([onboarding.rs lines 900–923](../../crates/synctl/src/onboarding.rs#L900)). Installer validation also binds protected evidence to the current approval key and rejects evidence older than 30 minutes ([installer.rs lines 133–170](../../crates/synctl/src/installer.rs#L133)). Completing E10 with temporary trust and then replacing only the keys would leave coupling evidence inconsistent. The safe two-approval sequence is therefore to move E05's real Touch ID and Mac-password proofs to the final post-E10 production activation/completion; no stale approval, new privileged protocol, or raw install-state restoration is permitted.
