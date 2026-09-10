# Implementation status

As of September 9, 2026, Syn is an onboarding candidate. The current flow has not passed the required [12-case live suite](onboarding-e2e-test-plan.md).

## Current candidate

- The Mac app's **Add a machine** flow accepts a reachable hostname, SSH account and optional port. It discovers the remote endpoint, checks Ubuntu 26.04 ARM64, transfers inert inputs and runs only fixed privileged operations.
- Bootstrap copies the incoming helper into a root-owned directory, verifies its exact digest and size there, then executes that protected copy. The helper also checks its path, parents, open executable and compiled release identity.
- First setup now includes one command in a trusted remote administrator session. It installs a restricted maintenance SSH key; the Mac no longer collects or sends administrator passwords. Later updates reuse that key, and local revocation removes its exact entry.
- Onboarding is split into resumable `prepare`, `cleanup`, `build`, `configure`, `activate` and `complete` phases. `recover` removes `NOPASSWD` before restoring or removing other state.
- Successful setup leaves the Mac app talking directly to the remote machine over mutually authenticated TLS. Everyday approvals do not use an SSH tunnel, cloud relay or VPN-provider dependency.
- The wire protocol is version 2. Hello, request and decision messages bind the target, release ID and exact release commit; mixed releases fail closed before an approval is accepted.
- Each approval is limited to one signed invocation and expires after 90 seconds. An interactive user may press Enter to cancel the pending remote approval and use ordinary password sudo; denial and integrity failures do not fall back.
- Candidate update, interrupted-operation recovery, uninstall and login-startup paths exist. Completion requires a fresh approval and an exact live release/coupling check before recovery protection is canceled.

## Evidence available

- Historical September 5–6 component runs passed Swift, Rust ARM64, release-tool, privacy and formatting/lint checks. Those results are recorded in the [onboarding checkpoint](validation/2026-09-05-onboarding-implementation.md); they predate some current integration changes and are not a current-HEAD acceptance claim.
- Earlier live Pi validation exercised the core sudo/PAM, mutual-TLS approval and timed-recovery design. It did not exercise the current Mac-led download, protected bootstrap, phased install, update or uninstall flow.
- Current source contains focused automated tests for release binding, onboarding state and retry behavior, protected-source checks, recovery ordering and Mac coordinator decisions. The full current-HEAD check matrix still needs to be recorded with the live suite.

## Not yet proven

- Cases E01–E12 have not run against the current Mac-led flow. No first install, A-to-B update, interruption boundary, recovery or uninstall is accepted until that ledger passes.
- Real private-release download authorization and genuine A/B artifacts still need end-to-end evidence. A private repository cannot be treated as an anonymous public download source.
- Mac artifacts are ad-hoc signed for development. There is no Developer ID distribution, notarization, reproducible-build proof, SBOM or independent security review.
- Linux activation recovery now uses a root-owned worker lease and process identity checks. Its behavior across real interrupted updates and reboot remains an E10 acceptance requirement.
- Package/provider upgrades to a genuinely newer external version and every damaged or unreadable-file boundary have not been live fault-injected.

## Release state

Do not call the Mac-led milestone complete or deploy it to an ordinary machine yet. Run the [12-case live suite](onboarding-e2e-test-plan.md) with independent recovery access, record exact release IDs and commits, and leave both machines in a verified final state.
