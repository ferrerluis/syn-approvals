# Mac-led onboarding: implementation checkpoint

Status updated September 8, 2026: candidate implementation with automated component coverage. This is not an acceptance report or permission to deploy; the [12-case E2E suite](../onboarding-e2e-test-plan.md) remains the completion gate.

## Historical component results

The September 5 source checkpoint passed:

- 51 Swift component tests with warnings denied.
- One opt-in, read-only SSH platform check against the Pi.
- 67 Rust workspace tests on ARM64, with two device-specific tests ignored.
- Nine release-tool tests, four log-privacy tests, Python compilation, shell syntax and whitespace checks.
- ARM64 formatting and all-targets Clippy with warnings denied, plus Mac release-mode compilation.

The September 6 checkpoint passed:

- 64 Swift tests with warnings denied, including the opt-in read-only SSH check.
- 72 native ARM64 Rust workspace tests, with the same two device-specific tests ignored.
- Mac release-mode compilation, four log-privacy tests and fifteen release/helper tests.
- ARM64 formatting and all-targets Clippy with warnings denied.
- Rust-generated version-2 fixtures in both languages, including rejection of the same release timestamp with a different commit.

Those were isolated source checks. They did not install packages, change live sudo state, launch an installed release or prove the current integrated onboarding flow. Later source changes need their own current-HEAD results.

The isolated Pi also produced an uninstalled ARM64 Debian package with synthetic release metadata. Its helper reported that compiled identity and used only the expected Ubuntu runtime loader and libraries; the package was not installed.

## Integrated candidate since the checkpoint

- The Mac app now leads **Add a machine** from hostname, SSH account and optional port, discovers the server-side address from `SSH_CONNECTION`, validates the platform and preserves an installed target identity during update.
- Source and metadata transfer are inert. Privileged bootstrap copies the helper into a protected root-owned path, checks its exact digest and size there, and only then executes the protected copy.
- The helper validates its canonical location, root-owned parent chain, mode, open executable identity and compiled release metadata. Protected source files are reopened without following symlinks and revalidated immediately before build or copy.
- `prepare`, `cleanup`, `build`, `configure`, `activate`, `complete` and `recover` are fixed, operation-bound phases. Retries reconcile prior success, and completion requires an exact live release/coupling check plus a fresh approved diagnostic before it cancels recovery protection.
- The protocol hello, request and decision all bind the target, release ID and exact release commit. Mixed releases fail closed before the request reaches the approver.
- Everyday traffic is direct mutual TLS to the saved hostname. SSH is onboarding and maintenance transport, not an approval tunnel or continuing provider dependency.
- The candidate lifecycle includes first install, A-to-B update, interruption recovery, uninstall and startup handling.

## Automated coverage added

Focused tests exercise coordinator state and retry behavior, exact release matching, corrupted and symlinked protected inputs, installer/helper/journal crash windows, recovery ordering and operation-bound completion. This describes test coverage in source, not a fresh full-suite pass on the final integrated commit.

## Live acceptance still required

- E01 through E12: **not run** for this Mac-led flow.
- No current checkpoint work changed an installed Mac app, package, live sudo configuration or recovery timer.
- Real private-release authentication and A/B downloads remain unproven end to end.
- Ad-hoc signing is suitable only for development; Developer ID signing and notarization are absent.
- Boot-scoped orphan containment still needs a worker or cgroup interface beyond the current session/process-group cleanup.
- Independent security review and every interrupted installation boundary remain open.

Acceptance must record the actual release ID and commit, redacted evidence, outcome and cleanup for every case, then leave both machines on the verified final release with ordinary password recovery proven.
