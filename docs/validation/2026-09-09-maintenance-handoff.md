# Maintenance bootstrap: implementation and E2E handoff

September 9, 2026. Component validation only; E01–E12 remain unproven.

## Candidate and ownership

- Source of truth: `/Users/ferrerluis/.codex/worktrees/d612/syn`, branch `codex/mac-led-onboarding`.
- HEAD: `73a96a06a966dbd0f4f0e65515a76e10345c0284`. The implementation includes uncommitted tracked and untracked files; HEAD alone does not identify this candidate.
- There is an unfinished merge from `19fccb22aebd089e6d71d532f55990fc04e0df9e`, with no unresolved paths. Preserve the merge, existing branding changes, and user `output/` artifacts.
- E2E owner: Codex task `01a08758-a357-7de3-9016-3614e2acd18c` (“Test task”). Orchestrator: `01a07340-0d27-7fc1-b20b-f5336ec62e52`.
- Only the E2E owner may use Computer Use or mutate the installed Mac/Pi while the live suite runs. Send implementation questions and failures to the orchestrator.

## Approved security change

The Mac no longer asks for or sends the remote administrator password. First setup stages the bundled helper and displays one command to run in a trusted administrator session outside the managed agent's control. That command verifies a root-owned copy before installing the restricted maintenance key.

The endpoint retains a fixed dispatcher and managed-account configuration under `/var/lib/syn/maintenance`. Its root SSH entry disables forwarding, PTY and user startup hooks; it accepts only the documented maintenance vocabulary. Root SSH policy must already allow forced public-key commands; the installer does not weaken it.

Everyday approvals remain separate. The maintenance key authorizes privileged installation and must be protected as an administrator credential. Later updates reuse it. Local uninstall/revocation removes the exact Syn SSH entry while preserving unrelated entries.

The focused review identified that `-i` plus `IdentitiesOnly=yes` could still select configured keys. The approved fix uses `-F /dev/null` and carries over only resolved routing/host-verification options. An actual `ssh -G` unit check proves exactly one identity, no agent/certificate, preserved route and strict host verification.

Completion now stops the recovery timer and service, then rechecks sudo configuration before recording success. The agent disconnect test verifies that abandoning a local request removes it and broadcasts cancellation.

## Checks passed

| Check | Result |
| --- | --- |
| `swift test --package-path macos` | Suite passed; 110 tests reported. The opt-in live SSH integration test remains excluded. |
| Pi `cargo fmt --all -- --check` | Passed. |
| Pi `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed on Ubuntu ARM64. |
| Pi `cargo test --workspace --locked` | 102 passed, 2 explicitly ignored live-target tests; zero failures. |
| Release/helper Python tests | 17 passed during this implementation. |
| Log privacy tests | 4 passed during this implementation. |
| `git diff --check` | Passed. |

Rust checks used `/tmp/syn-onboarding-root.nPr8qc` on the Pi. No installed Syn, sudo policy, SSH authorization or service was modified by this component-test run. Source was transferred as inert files over SSH; Rust tests ran as the ordinary user.

## E2E starting instructions

Read the current [12-case test plan](../onboarding-e2e-test-plan.md), [delivery plan](../distribution-onboarding-plan.md), and [maintenance contract](../ssh-maintenance-contract.md). E03 and E12 now require the approved one-time bootstrap; E04 must update using the existing key without a remote password prompt.

1. Inspect the authoritative worktree rather than the E2E task's default `/Users/ferrerluis/repos/syn` checkout. Coordinate any commit/release preparation with the orchestrator. Genuine downloadable A/B releases are still required; synthetic local labels do not count.
2. Re-inventory both devices and prove independent administrator recovery before uninstalling. Historical state is not current proof. Preserve Keychain/Secure Enclave keys and make protected backups of SSH/Syn settings.
3. `ssh pi` uses the configured private route. The Pi has previously required legacy `scp -O` because SFTP was disabled. Use normal host verification; do not disable it.
4. Group user interaction into the coordinated live window. Retrieve passwords through elevated macOS `op` only immediately before an authorized use; never print, log or save them. Do not bootstrap through a shell controlled by the managed agent account.
5. Run the cases sequentially and record actual outcomes and cleanup. A harmless sudo execution probe is `/usr/bin/sudo -n /usr/bin/true`, not `sudo -v`; in Pi Codex it may require host-level execution rather than the sandbox.
6. Confirm uninstall removes Syn's restricted SSH entry. If testing explicit revocation separately, perform it while the retained helper exists. Preserve unrelated authorized keys and document retained Mac maintenance keys.
7. Review follow-up still needing observed evidence: missing/corrupt install state can stop conservative uninstall; Enter cancellation relies on dropping the local socket. Report failures against E01/E07/E11 rather than assuming these edge cases pass.
8. Stop and report any P0/P1 finding for Luis's decision. Stop safely if he leaves during required authentication. Do not count an unrun case or simulated fingerprint as a pass.

The final state must be one functioning Syn app, matching genuine release B on both machines, working approvals/password access, and no leftover recovery timer or privileged test session.
