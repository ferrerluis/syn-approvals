# Syn: autonomous-first end-to-end acceptance tests

**12 hybrid acceptance cases**, coordinated by one designated GPT-5.6 Sol E2E sub-agent. Run autonomous tests first, the reboot test after asking Luis, then the single real Mac-approval case for the final installation. Reboot remains the last disruptive test. This covers the [Mac-led delivery plan](distribution-onboarding-plan.md), including actual uninstall from both devices and reinstall through the new flow. Mock only the Mac user-presence/signing boundary outside E05; the cross-device lifecycle and Linux enforcement remain real. Record that boundary explicitly rather than claiming every authentication was live.

## Ownership and preparation

The tester coordinates execution and is the only Computer/Browser Use operator. The Astra task is planning-only: no duplicate testing, routine CI polling, or implementation work. Use existing Codex messages for handoffs; no custom coordination service.

| Owner | Work and limits |
| --- | --- |
| Sol: E2E owner | Owns the case sequence, all UI actions, human approval requests, and the decision to advance. Reviews the helpers' evidence. |
| Sol: Pi verification | SSH inventory and read-only observations. Triggers a test command or changes Pi state only for an explicitly assigned step; never operates the GUI. |
| Sol: releases and evidence | Checks CI, release IDs, artifact hashes and coverage; maintains the result file. No UI or live-device changes. |

Before each case, the tester sends its ID, required starting state and each helper's allowed actions. Helpers acknowledge completion or a blocker before dependent work advances. Only one owner changes Pi state at a time, including changes initiated by the Mac app. Read-only observations may overlap when they do not disturb timing or authentication.

- During preparation, overlap Mac/download readiness, Pi inventory, and artifact verification.
- During install/update, the tester operates Syn while the Pi helper observes and the evidence helper checks the results.
- During approval tests, agree on one request before the Pi helper triggers it; the tester handles the matching UI prompt. Do not interleave unrelated sudo requests.
- Preserve uninstall/install/update/recovery dependencies while following the three stages below. Preparation for a later case must not change the current case's starting state.
- Report when finished or blocked, not repeatedly while unchanged. Use bounded waits for active jobs. Reuse passed component results unless a relevant change requires a rerun.
- Assign necessary fixes to a Sol agent in an isolated worktree, with explicit file ownership and affected tests. No live deployment until the tester coordinates it. New P0/P1 findings stop dependent work for Luis's decision.

The evidence helper is the sole result-file editor; other agents send it observations. The tester must verify each case's required outcomes before accepting a pass. The explicit coverage changes are mocked Mac authentication outside E05 and replacement of direct-LAN testing with Meshnet connectivity plus automated provider-independence checks.

Before starting:

- Pass Rust/Swift checks, relevant ARM64 tests and protocol fixtures. Keep exhaustive input, timing, identity and crash permutations in component tests.
- Prepare genuine downloadable releases **A and B**, each with matching Mac/remote timestamp IDs and exact commits. Use a Mac-only change for B to exercise publishing both components anyway.
- Both candidates must include the `syn-maintenance --protocol-version 1 <operation>` request format in the Mac and remote helper. The older published A/B artifacts predate this change and cannot prove the revised flow; retain them as historical evidence, not final candidates.
- Inventory the real devices and the working Meshnet route. Direct home-LAN access is unavailable and is not required for this acceptance run. Before any privileged live change, prove administrator recovery independent of Syn and preserve the installed app/package, sudo configuration and relevant settings in protected backups.
- Preserve Secure Enclave/Keychain identities. Reversibly clear active app profiles/preferences for clean onboarding; disclose any reused identities rather than claiming first-ever key creation.
- Reserve at most two real Mac approvals, both in E05 after autonomous work. Do not spend this budget on repeated setup prompts, harness debugging or routine tests. Ask for any separately necessary bootstrap/credential permission explicitly before acting; do not assume a password is available or silently add human test cases.

Use Computer Use for the actual download/setup/update screens and SSH for remote observations. Use harmless commands such as `sudo /usr/bin/id -u`; verify remote execution, not just the Mac's success message. Expire sudo authentication timestamps before password checks. Keep credentials, private keys and sensitive command data out of evidence; use elevated `op` only immediately before an authorized password use.

## Execution order and permissions

1. **Autonomous first.** Finish component tests and the reviewed test-only signing harness, then execute E01–E04, E06–E09, E11 and E12's clean reinstall wherever authorized prerequisites hold. Use real cross-device transport, installation, sudo/PAM and recovery with scripted Mac decisions. Luis has explicitly approved copying only required private source into a fresh temporary Pi directory for unprivileged tests, excluding secrets and Git history and without deletion-based synchronization. Stop for missing administrative authority or credentials; do not fabricate a pass or improvise password transfer.
2. **Reboot: last disruptive test.** Prepare E10 with scripted Mac decisions, then ask Luis immediately before any reboot or deliberate update interruption. Give the expected interruption and recovery path; wait for an explicit answer. Do not schedule or assume a safe time. Observe actual recovery and finish the retry on B before final production activation. A failed automatic recovery still fails E10 even if manual rescue succeeds.
3. **Two real approvals, then handoff.** Run E05 with the shipping signer for final B's fresh activation and completion checks: Touch ID and Mac-password fallback, at most two approvals total. These are real signed round trips, not sudo executions; the hybrid cases prove sudo execution separately. Remove test trust, verify real OS settings and paired identity persistence, and finish E12's final-state/cleanup checks. No further disruptive test follows. System-dialog cancellation remains covered by the isolated signer tests.

This reversible scheduling adjustment follows Luis's instruction to make in-scope reversible decisions independently. Fresh production proofs are required after a reinstall; moving E05 after E10 preserves the two-approval limit without replaying old evidence or changing the product's authentication protocol. Asking immediately before reboot remains mandatory.

Luis has explicitly authorized installing temporary resources on both his MacBook and Pi needed for testing, with removal before completion. This includes the separate SynE2E app and scoped test support once recovery and cleanup have been reviewed; it is not permission to export secrets, weaken production authentication or reboot without asking. Authentication credentials must still be available through an authorized path. Only ask for specific permissions that are missing: name the action, machine, files affected and expected interruption. New P0/P1 findings still require Luis's decision before dependent work continues.

Luis has preemptively authorized work documented in this implementation/test plan, including the harness fixes below and their validation. Do not ask again for these scoped changes or normal implementation steps. This does not override explicit gates such as permission immediately before reboot, the two-real-approval limit, or handling secrets through an authorized path. Assess security severity from demonstrated reachability and impact; hypothetical future deployment alone does not make an undeployed test defect P1.

Track each temporary directory, package installed only for tests, service/timer, test account, SSH key entry and paired test identity before creating it, together with its original state and exact cleanup action. Existing user resources must not be claimed or removed. Before completion, remove temporary test resources, revoke test trust, verify their absence and restore any changed pre-test settings. Required final Syn/runtime dependencies remain; list intentional protected recovery backups separately. A remaining temporary resource keeps cleanup incomplete.

### Test-only Mac approvals

Extend the existing `DecisionSigning` injection and software-only `TestSigner` into a separate test app/harness. It must use the real request parsing, rendering, transport and cryptographic decision path, replacing only the hardware/user-presence signer. Existing unit tests alone do not constitute this cross-device harness. Do not add a runtime “skip Touch ID” setting to the shipping app or distribute test keys in release artifacts.

The test app uses a distinct identity/profile and temporary approver keys. Pair them only for the coordinated test run, approve only the exact expected target/action for the active case, and stop after that request or deadline. It must not become an unattended general approval service. Preserve production identities, record every test-trust change and remove test trust at handoff. Review this temporary privileged test boundary before enabling it; real root effects remain subject to the case's authorization and recovery safeguards.

Build each temporary test app against that candidate's exact clean production checkout, with its validated release metadata and matching remote source/helper artifacts. Shared test-only code may come from the harness checkout; shipping source must come from the candidate being tested. Record both revisions. Development/invalid identity labels, missing installer resources or a B production build relabeled as A cannot pass a candidate test.

The local empty-state smoke uses in-memory startup preferences, suppressed notifications and disposable test keys persisted only inside the run-owned isolated profile. Relaunch continuity of those test keys can support A's test pairing, but it does **not** prove production Keychain identity continuity, real login-item registration or notification delivery. Prove production Keychain continuity with final shipping B in E05/E12, without spending additional real approvals; do not count a simulated switch or retained target JSON as proof of the OS setting or production identity persistence.

Before enabling the harness, resolve the four P2 findings in the [September 12 review](validation/2026-09-12-test-harness-review.md) and pass these automated regressions:

- Bind the exact signing input to the verified request and permitted decision at signing time. Substituted payload, request, target, action, key or protocol data must fail without a signature.
- Enforce the earlier of request expiry and grant expiry at construction and signing. Test expiry between those steps, cancellation, repeat calls and concurrent attempts; at most one permitted signature may be produced.
- Own a private disposable directory and verify its identity before cleanup. Reject symlinks, directory replacement, foreign files and unsafe permissions; preserve everything the harness did not create.
- Bind the resource manifest to its run and actual owned paths. Reject symlinks, traversal, another run's resources and production names; permit only fixed, exact cleanup targets.

Keep these as component gates within the existing 12 cases, not additional human tests. Run focused regressions and full relevant suites, then a bounded independent Sol review. These findings are P2 in the current undeployed, unpaired test scaffold; that does not permit enabling an unfixed harness for privileged E2E.

These four fixes now pass their component tests and bounded review (see the linked evidence). Next, build the separate test app using the real Syn screens and connection code, with isolated settings and test keys. Check that the shipping app contains no mock signer. Before live Pi testing, verify that the temporary account actually reaches Syn's managed-user password path, and that restoring production trust after E10 preserves the existing installation checks. These are preparation steps, not extra E2E cases or completed E2E results.

For each hybrid pass, prove actual Pi execution or non-execution, installation, package versions, network transport and recovery outcomes. Label Mac user presence as **mocked**. PAM remains real; handle its credentials through an authorized trusted path without logs or model exposure. E05 alone proves actual Touch ID, Mac-password fallback and Secure Enclave signing. Test failures may not trigger extra human prompts without Luis's decision.

Before running the harness, design and test the switch between temporary test trust and the preserved production keys, including post-reboot restoration. Onboarding currently requires two real approval gates; spend the budget on those gates once in E05. Its activation/completion probes exchange signed requests directly and do not execute through sudo. Do not change the privileged production completion protocol just to save a test prompt. Prove actual sudo execution in the hybrid suite and real hardware signing in E05, stating the separate coverage boundaries.

E10 precedes E05, so no production proof is replayed and no special post-E05 restore mechanism is needed. Preserve existing identities and use the supported final setup flow, not raw sudo-file replacement. Do not leave test trust installed or quietly request a third approval. Any missing bootstrap/PAM credential remains a separate prerequisite: the two-Mac-approval budget does not eliminate Linux authentication requirements.

## The 12 cases

Use the execution stages above; case IDs identify coverage, not a mandatory numerical schedule. Each bundled case passes only when its listed outcomes pass; record any failing step explicitly.

| ID | What to do | What must be true |
| --- | --- | --- |
| E01 · Uninstall both devices safely | Prove recovery access and backups. Uninstall Syn from the Pi, verify password sudo, then quit/remove the Mac app, unregister its login item and reversibly clear active profiles/preferences. | Actual app/package removal, not an install-over. No Syn process/listener, dangling plug-in reference or ungated `NOPASSWD`. Password sudo works, unrelated administrator settings remain intact, and retained keys/backups are listed. |
| E02 · Setup errors are recoverable | Download A through README and open Add a machine. Try an unreachable hostname and cancel authentication before using the correct connection. | Clear errors and retry; failed/canceled authorization makes no remote installation changes. No stored passwords or need to repair SSH configuration. |
| E03 · Fresh Mac-led installation | Choose No for startup, then enter the real hostname/account. Run Syn's one-time bootstrap command in the trusted administrator session established in E01, then continue installation and pairing in Syn. Complete setup approvals. Relaunch, then enable startup in Settings. | The Mac never asks for or transmits the remote password. The restricted key rejects shell/extra-command and forwarding requests; the helper rejects a substituted hash. No manual profile/key transfer. Both report A and become Ready only after real health checks. One app/target; pairing survives relaunch; startup settings match macOS. |
| E04 · Offline update, then A → B | Make the test update route temporarily unavailable while preserving recovery access. Open downloaded Mac B and check the mismatch; restore the route and use the Mac update flow to bring the Pi to B. | Offline/update-required status is accurate; mismatched versions cannot approve, including over an old connection. Retry obtains necessary authorization, installs exactly B, preserves keys/settings and cancels recovery only after health success. |
| E05 · Only real Mac-approval case | With production keys and signer, complete final B's activation preflight using Touch ID, opening Review from its notification. Complete its second signed health check using Mac-password fallback. Maximum two real approvals total. | Privacy-safe notification; Review opens the intended production app. Correct machine/action shown; two separate request-bound signatures verified on the Pi with fresh system authentication. Shipping B is ready and recovery disarmed. Neither uses test trust. These checks prove real Mac authentication and signed transport, not execution through sudo. |
| E06 · Denial and cancellation | Deny one request through the real decision path. For another, make the test signer return the same cancellation error as system authentication. | Neither command executes; pending UI clears. No password fallback for the explicitly denied invocation and no cancellation counted as approval. System-dialog cancellation is mocked, not claimed as physically tested. |
| E07 · Immediate password escape | While waiting, press Enter and use the Pi password. Repeat with one incorrect synthetic password and cancel; also verify that Enter after a completed denial cannot reopen that invocation. | Correct password executes the original command once without waiting 90 seconds. Wrong password does not execute. Pending approval is invalidated and late decisions cannot execute again. Respect PAM lockout policy. |
| E08 · Timeout and non-interactive behavior | Leave an interactive request unanswered for 90 seconds, then use password fallback. Run `sudo -n` once with a Mac approval and once unanswered. | No early execution/fallback. Interactive authentication completes once; non-interactive approval works, but unanswered non-interactive sudo fails without a password prompt. Production timing stays unchanged. |
| E09 · Meshnet, disconnection and reconnect | Use the reachable Meshnet hostname. Close installer SSH sessions, interrupt only Syn's connection, then restore it and approve a real Pi request through the test signer. | Actual cross-device traffic works over Meshnet without an SSH approval tunnel; disconnection never approves anything and reconnect verifies the same paired identity. Automated endpoint tests cover ordinary addresses/provider independence. Direct physical-LAN behavior is explicitly not live-tested. |
| E10 · Failed update and reboot recovery | Using the protected restore procedure, establish A again for one guarded A → B attempt. Interrupt it during final activation while recovery is armed; reboot the Pi before the recovery deadline. Observe recovery, re-establish independent access, then retry through the Mac. | The original deadline survives reboot without extending. Recovery actually restores password sudo without the Mac, not merely a timer status. No ungated passwordless state or false Ready. Retry finishes on B with preserved identities/settings. |
| E11 · Mac lost, local access retained | Quit/uninstall Syn on the Mac first. Use Enter-to-password on the Pi, then its supported local recovery/uninstall procedure. | Losing the Mac does not prevent password administration or removing Syn. Remote removal needs no Mac approval; retained data follows the documented policy. |
| E12 · Final clean reinstall and handoff | Clear active profiles using E01 safeguards and exercise B's clean reinstall with the test signer. After E10, finish final shipping B setup with E05's two real approvals. Choose Yes in the first-launch startup prompt. Verify approval, real password escape and final device state; complete handoff checks after E05. | Matching final B on both devices; startup is really enabled and persists. One intended production app/target, working sudo and no leftover test-key trust, test app, maintenance timer, test service or privileged session. Preserve the real identity tested in E05; report retained backups and restore unrelated settings/routes. |

E01 and E11–E12 exercise actual removal/reinstallation in both orders. Recovery copies stay protected and inactive; do not delete non-exportable identities to make a test appear cleaner.

Include maintenance access in E01/E11 cleanup: revoke Syn's exact root SSH entry with the retained helper and confirm unrelated SSH keys remain. Reversibly retain the Mac maintenance key for recovery, documenting it alongside Keychain identities. E12 must exercise bootstrap authorization again after revocation; E04 must reuse the established key without a remote password prompt. The bootstrap terminal must be outside the managed agent account's control; typing a password into an already compromised shell is not a safe substitute.

Within E03, verify that the installed helper accepts `syn-maintenance --protocol-version 1 probe` and rejects the old `syn-maintenance-v1 probe` spelling and an unsupported version. E04 and E10 must exercise update and recovery through the same explicit-version format. Automated tests cover every operation plus missing, duplicate, reordered and malformed version flags, shell syntax and extra arguments. These checks stay within the existing 12 cases. The SSH key ownership marker is not the wire command and must still support exact revocation.

E10 uses only a recoverable failure boundary already proven by component tests. Never corrupt the user's sudo files, destroy the recovery tool, fill the disk or remove all administrator access. If independent recovery cannot be proven, stop before the mutation.

For E10, an open SSH root session alone does not survive reboot. Before failure injection, verify the restricted maintenance SSH path and retained recovery helper, including successful restoration of password sudo. Coordinate any preliminary reboot with Luis too. This can provide recovery over Meshnet without physical access, provided boot and SSH/network reconnection work; do not assume that merely finding a key or helper proves recovery.

## Coverage moved out of the live suite

To genuinely reduce manual testing—not just rename 33 cases—implementation agents cover these with automated component or isolated integration tests:

- Malformed setup inputs, wrong/changed SSH and TLS identities, corrupted downloads, missing prerequisites and unsupported platforms.
- Release-ID tampering, downgrade handling, address re-resolution, duplicate setup and startup-prompt dismissal/error variants.
- Exhaustive Enter/approval/denial races, closed input, concurrent request routing and replay/expiry checks.
- Interrupted transfer/build, every maintenance journal boundary, ambiguous override ownership and multi-target isolation.

These checks are still required before E2E, but do not each require Computer Use, live device changes or Luis's authentication. Existing-alpha migration also needs isolated regression coverage; this live suite prioritizes the requested clean installation and real A → B update.

## Evidence, fixes and completion

Keep one concise result file under `docs/validation/`: case ID, release/commit, actual outcome, redacted evidence, cleanup and **pass / fail / blocked / not run**. Screenshots prove UI behavior; remote results prove execution. Do not label an isolated test as a real-device pass.

On failure, stop dependent work, restore a known state and send the issue to its implementation agent. The E2E owner keeps device control while fixes are reviewed. Rerun the failed case and affected checks; before acceptance, validate all 12 cases with the final A/B candidate pair using the stages above. Group any unavoidable additional authentication rather than prompting throughout development.

Completion requires all 12 hybrid cases and prerequisite automated checks to pass, no unresolved critical/high findings, and working production Syn on both devices with test trust removed. The report must identify mocked Mac authentication and the untested physical LAN. Missing administrative credentials or recovery access remains a stated blocker; missing home-LAN access does not. Public notarization stays in separate TODO 5.
