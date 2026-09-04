# Live Pi test-and-iterate plan

This plan validates Syn on Luis's real Raspberry Pi 5 without treating the machine as expendable. The safety rule is **recoverable**, not **disposable**: every privileged change must have a local timed rollback, a preserved root path, and captured pre-change state.

Codex can execute the plan from the Mac using SSH and CLI commands. Computer control is reserved for the native Syn UI, macOS notifications, Touch ID prompts, and Windows App recovery checks.

## Verified starting point

Observed from the Mac on 2026-09-02:

- SSH alias: `pi` → `ferrerluis97-everest.nord`, user `ferrerluis`.
- Dedicated unattended key: `~/.ssh/id_ed25519_syn_pi`; `ssh pi` works with the 1Password agent disabled.
- Pi: `pi-main`, Ubuntu 26.04, ARM64, Raspberry Pi kernel 7.0.
- Root filesystem: ext4 on `/dev/nvme0n1p2`; 235 GB total and roughly 212 GB free.
- Current sudo: `sudo-rs 0.2.13`, selected through `update-alternatives` at `/usr/lib/cargo/bin/sudo`.
- Classic sudo: `sudo.ws 1.9.17p2`, installed setuid at `/usr/bin/sudo.ws`.
- Alternate setuid entry points exist at `/usr/bin/sudo-rs` and `/usr/lib/cargo/bin/sudo`.
- Network: NordVPN Meshnet on `nordlynx`, Pi `100.99.102.171`; Mac peer `100.70.150.245`.
- Tailscale is absent on the Pi. NordVPN tunnel status is disconnected, but Meshnet is active and carries SSH.
- Build gaps: `build-essential` is installed; Rust, Cargo, Clang, pkg-config, CMake, and PAM headers are not.
- Windows App has saved Pi devices, but it is reserved for recovery rather than normal validation.

Recheck these facts at the start of a later run. A saved alias or successful command from an older run is not current proof.

## Completion contract

Syn is ready for personal use only when all of these are true:

- Normal `sudo` from SSH and Codex sends a clear approval request to the Mac.
- One Mac approval runs one unchanged command. Repeating the command requires a new approval.
- Rejecting, canceling, altering, or reusing a request never runs the command and never opens the Ubuntu password fallback.
- If the Mac is simply unavailable for 90 seconds, an interactive terminal offers the normal Ubuntu password. A non-interactive command fails without prompting.
- Directly invoking `sudo-rs` cannot bypass Syn and become root.
- If Syn's sudo plug-in is missing, unreadable, or damaged, sudo refuses the managed command instead of silently running it.
- A timer running locally on the Pi can remove Syn's passwordless sudo rule and restore ordinary password sudo even when the Mac app and SSH connection are unavailable.
- Reinstalling Syn, upgrading either sudo provider, or rebooting the Pi keeps the Mac approval requirement active. The same recovery command must still restore ordinary password sudo afterward.
- Automated checks search captured Syn output for the supplied test passwords, PEM private-key markers, a unique environment-value marker, and a unique command-argument marker. None may appear.

A successful build proves only that the source is valid enough for the compiler. It does not prove that the real Pi's sudo loads the plug-in, the Mac receives a request, the approved command runs, or recovery works after a failure; the live tests below prove those behaviors.

## Human inputs that cannot be automated away

Codex can run every test except the final Touch ID check:

- Use the supplied Ubuntu password for initial setup and the 90-second fallback test.
- Use the supplied Mac login password for Mac approval tests before the final Touch ID check.
- Use Computer control to press Deny and cancel authentication in negative tests.
- Ask Luis to perform one final Touch ID approval only after every password-based and failure-path test passes.

The supplied passwords must not remain in this file, shell history, environment variables, command arguments, logs, screenshots, or test evidence. Codex enters them only into the intended password prompt and does not repeat them in status messages.

## How Codex will operate

Use these tools in this order:

1. `ssh pi` and non-interactive CLI commands.
2. Local Mac CLI for builds, fixture comparison, signing inspection, and network probes.
3. Computer control for Syn.app notifications and request details.
4. Windows App only for recovery if SSH is unhealthy.
5. A Pi-local systemd rollback timer as the independent safety path.

Keep one SSH control connection open during each active test window. The dedicated Pi key avoids biometric prompts for routine SSH and can be revoked by removing its single `authorized_keys` entry.

## Evidence rules

Create one local directory per run under `test-runs/YYYYMMDD-HHMMSS/`. Store only:

- Git commit and dirty-state summary.
- Tool and package versions.
- Redacted `synctl doctor` JSON.
- Test name, start/end time, expected outcome, actual result, and pass/fail.
- Service state, provider modes, key fingerprints, request IDs, digests, latency, and error categories.
- Screen captures of Syn UI only after checking that they contain no secrets.

Do not capture shell tracing, complete environments, private configuration files, key contents, approval signatures, full argv, terminal password prompts, or unredacted journals. Standard sudo logs may contain command text; reference their timestamps without copying them into the repository.

## Iteration 0 — close three deployment gaps

**Completed on 2026-09-03.** [Validation evidence](validation/2026-09-03-iteration-0.md) records the Mac and native Pi checks, package staging, harmless timer proof, and reboot persistence. Syn sudo remains unarmed. This completes the deployment prerequisites, not the later real sudo/PAM/Mac approval acceptance tests.

Do not arm the sudo integration until these changes pass locally and on the Pi.

### A. Support the network that actually exists

The original implementation and package claimed Tailscale was mandatory, but the Pi and Mac communicate through NordVPN Meshnet. The Pi's Meshnet address happens to fall inside the same CGNAT range, so address-range checks alone are misleading validation, not compatibility.

Change the transport configuration to name the overlay explicitly:

- Supported alpha values: `tailscale` and `nord_meshnet`.
- Bind only to a concrete overlay address, never wildcard or ordinary LAN addresses.
- For `nord_meshnet`, verify the configured address belongs to `nordlynx` and that the paired peer is the configured Mac.
- Keep mutual TLS, exact certificate pins, target signatures, and approver signatures unchanged; the overlay provides reachability, not approval authority.
- Remove Tailscale as an unconditional Debian dependency and systemd requirement. Document it as one supported transport.
- Add config tests proving that the wrong interface, wildcard address, loopback, and LAN address fail closed.

Run the full Rust, Swift, golden-vector, and ARM64 checks after this change.

### B. Add a durable dead-man rollback

The initial installer rolled back its own immediate errors but lacked reboot-persistent timed recovery. The implemented root-owned recovery service/timer is managed by `synctl`:

- `synctl recovery arm --minutes 15 --apply` records a deadline and enables a persistent timer.
- The timer invokes `synctl recover --restore-local-sudo --apply` locally on the Pi.
- `synctl recovery cancel --apply` is allowed before installation, or after `synctl doctor` and the cancel command itself pass through healthy Syn-controlled sudo.
- Reboot must not erase the timer or extend its original deadline.
- Installation requires at least ten minutes remaining, and an elapsed timer is never reported as armed.
- Re-arming replaces only Syn's own timer after validating ownership and permissions.
- Timer status and deadline appear in `synctl doctor` without secrets.

Unit-test command construction and state transitions locally. Prove the timer first with a harmless marker action before trusting it with sudo recovery.

### C. Set the approval wait to 90 seconds

The private alpha uses one exact 90-second approval TTL everywhere. This supersedes the earlier 30-second choice at the user's request on 2026-09-04; earlier validation reports remain historical evidence of that earlier build, not proof of the new timeout.

- Rust configuration defaults and validation.
- Request TTL, monotonic deadline, socket wait, and late-decision rejection.
- Example configurations, PAM comments, threat model, recovery docs, and test matrix.
- Mac request countdown and expiry display.
- Golden vectors if the encoded TTL changes.

Add boundary tests for a decision immediately before the 90-second deadline and a decision immediately after it. A decision arriving late must never race with or override the Ubuntu password fallback.

## Phase 1 — establish a clean repository baseline

**Passed on 2026-09-04 UTC.** Commit `0c48afc` was validated on local branch `validation/phases-1-2`; the full local check suite and ad-hoc signed app verification passed. [Evidence](validation/2026-09-04-phases-1-2.md).

Before changing the Pi:

1. Commit the current implementation on a local validation branch.
2. Record `git status`, commit SHA, Rust/Swift versions, and app signature details.
3. Run:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
   - ARM64 Linux plug-in type-check
   - `swift test --package-path macos`
   - deterministic fixture regeneration and comparison
   - shell and plist validation
4. Build an ad-hoc signed `Syn.app` and verify it with `codesign --verify --deep --strict`.

If a check fails, fix that failure, add a regression test where practical, rerun the complete local suite, and use Computer control to inspect any affected Mac UI. Continue to Phase 2 only after the local suite passes; a failure creates another iteration rather than ending the project.

## Phase 2 — capture and prove Pi recovery state

**Passed on 2026-09-04 UTC.** The root-only sudo backup was hashed and compared with live state, the 15-minute deadline was checked from root and ordinary-user sessions, and the retained root session survived the gate. The test timer was canceled afterward; re-arm it and refresh the backup before a later privileged change. [Backup location and evidence](validation/2026-09-04-phases-1-2.md).

Start with read-only inventory over `ssh pi`:

- OS, kernel, architecture, uptime, boot ID, root filesystem, and free space.
- `sudo`, `sudo.ws`, `sudo-rs`, alternatives, setuid modes, stat overrides, and sudoers validation.
- Installed Syn files, service state, ports, and prior install-state files.
- Nord Meshnet interface/address and exact Mac peer.
- Available package versions for the missing build dependencies.

Then use the supplied Ubuntu password at the real sudo prompt to establish the initial root recovery path. Do not place it in a command, environment variable, file, log, or evidence record. Before any sudo integration change:

1. Copy `/etc/sudo.conf`, `/etc/sudoers`, `/etc/sudoers.d`, current alternatives, provider metadata, and existing stat overrides into a root-only timestamped directory under `/var/backups/syn/`.
2. Hash the backup and confirm it can be read from the root recovery session.
3. Arm the durable 15-minute Syn recovery timer.
4. Confirm its deadline locally and through `synctl doctor`.
5. Keep the root session open until the phase's test gate passes.

The backup is configuration recovery, not a live disk image. Imaging a mounted ext4 root volume would give false confidence and unnecessary risk.

## Phase 3 — build natively on the Pi

**Passed on 2026-09-04 UTC.** A clean build in a new Pi directory passed native lint, 29 tests, ELF/linkage inspection, and package-content checks. The dependency audit led to explicit runtime-library minimums in the package. [Evidence](validation/2026-09-04-phases-3-4.md).

Synchronize the repository into a new user-owned directory on the Pi. Exclude `.git`, `target`, `.build`, `dist`, private keys, and local test evidence.

Install only the dependencies confirmed missing by Phase 2. The expected list includes Rust/Cargo 1.85 or newer, Clang, pkg-config, CMake, and `libpam0g-dev`; inspect package candidates before installing them.

On the Pi:

1. Run the Rust unit tests and Clippy with warnings denied.
2. Build `syn_approval.so` natively against the Pi's libc and PAM.
3. Inspect exported sudo ABI symbols with `readelf` or `nm`.
4. Inspect dynamic dependencies with `ldd`.
5. Build the ARM64 Debian package with `scripts/build-deb.sh`.
6. Inspect package paths, owners, modes, maintainer scripts, and dependencies before installation.

Do not copy a macOS-built binary to the Pi or treat a cross-check as a native ABI test.

## Phase 4 — stage the package without touching sudo behavior

**Passed on 2026-09-04 UTC.** The freshly built package was installed without changing sudo/PAM contents, permissions, provider binaries, or alternatives. Fresh passwordless sudo was denied, and the normal Ubuntu-password path succeeded. Syn remains disabled and unpaired. [Evidence](validation/2026-09-04-phases-3-4.md).

Install the Debian package. Its post-install action must only create the locked `syn` account, directories, binaries, PAM file, and service definition.

Immediately prove:

- `/usr/bin/sudo` still resolves to the original `sudo-rs` provider.
- All original provider modes are unchanged.
- No Syn plug-in line exists in `/etc/sudo.conf`.
- No managed `NOPASSWD` rule exists.
- `syn-agent` is not active without completed configuration.
- Ordinary Ubuntu-password sudo still works.
- `synctl doctor` reports the missing setup accurately rather than claiming health.

If package staging changes sudo behavior, remove the staged package and fix the package before continuing.

## Phase 5 — prove transport and approval without sudo

**Passed on 2026-09-04 UTC.** Live synthetic Touch ID approval, repeated fresh approval, explicit Deny, and actual system Cancel all passed. The stable signed app restarted and reconnected without another Keychain permission prompt; 22 Swift tests pass. Luis confirmed the notification hid command contents and Review reopened the closed Syn window; the Pi verified the resulting denial. [Progress, fixes, and remaining gates](validation/2026-09-04-phases-5-6-progress.md).

Generate the target identity on the Pi and the approver identities in Syn.app. Transfer only public keys and the certificate-pinned profile through SSH.

Configure the agent for Nord Meshnet using the exact Pi address `100.99.102.171` and the Mac peer `100.70.150.245`. Confirm port `41781` is reachable only through the intended overlay path and that mutual TLS rejects an unpaired client.

Use Computer control to verify the native Mac flow:

1. Launch the locally built Syn.app.
2. Import the pinned target profile.
3. Confirm the menu-bar connection state identifies `pi-main`.
4. Run `synctl test approval` for synthetic `/usr/bin/true`.
5. Verify the notification hides command contents.
6. Open Review and verify target, user, run-as identity, working directory, executable, and separate argument rows.
7. Approve once with fresh system user presence.
8. Repeat with Deny and authentication cancellation.

No command is executed in this phase. A late, modified, wrong-target, or replayed decision must be rejected by both agent and requester.

## Phase 6 — load the plug-in without adding `NOPASSWD`

This shadow phase tests the real sudo ABI while ordinary password authentication remains in force.

**Passed on 2026-09-04 UTC.** The final rebuilt plug-in and Mac app passed real sudo approval: request `81676b340460eb02156c53bba27627a9` executed the original `/usr/bin/id -u` invocation, returning root UID 0 and exit 0. Denial, Ctrl-C, malformed reply, 30-second non-interactive expiry, interactive PAM fallback, relay reconnection, and actual Pi-local automatic recovery also passed. Afterward, original sudo/PAM/provider state was verified restored and fresh ordinary password sudo passed. [Evidence](validation/2026-09-04-phases-5-6-progress.md). Phase 7 is a separate authorization gate; Syn remains unarmed.

The guarded command is `synctl --json install --user ferrerluis --shadow` (preview), followed by `--apply --acknowledge-console-recovery` only after Phase 5 passes. It writes recovery state before touching sudo.conf and leaves the provider alternative unchanged. The timer uses the same recovery command for shadow and normal installation; shadow recovery archives its state so later runs start clean. Shadow apply, manual recovery, and automatic recovery are now live-validated.

1. Re-arm the recovery timer.
2. Select or invoke `sudo.ws` while preserving the original alternative in the install state.
3. Register the Syn approval plug-in in `/etc/sudo.conf`.
4. Do **not** create `/etc/sudoers.d/90-syn-managed-user`.
5. Validate `sudo.ws -V` and `visudo.ws -cf /etc/sudoers`.
6. Run harmless commands through `/usr/bin/sudo.ws` and verify the plug-in receives the final normalized intent.
7. Test approval, denial, malformed response, cancellation, and timeout.

This phase may require the Ubuntu password before Syn because classic sudo still performs normal authentication. That duplicate interaction is acceptable here; the purpose is proving the ABI before enabling passwordless policy coupling.

Restore the original sudo configuration after the shadow tests. Fix any crash, hang, missing field, or unexpected fallback before arming.

## Phase 7 — arm Syn with automatic rollback active

**Passed on 2026-09-04 UTC.** Guarded normal installation and all six immediate checks passed. Ordinary sudo approved a harmless command without the Ubuntu password; both alternate provider paths refused elevation. Actual Pi-local normal recovery restored the baseline and fresh password sudo, followed by successful reinstallation and a new approved, healthy diagnostic through ordinary sudo. At handoff Syn is armed with rollback deadline **2026-09-04 15:41:11 UTC (11:41:11 a.m. Eastern)**; recheck live state before Phase 8. The timer remains active, and permanent deployment is not yet validated. [Evidence](validation/2026-09-04-phase-7.md).

Prerequisites:

- Signed `/usr/bin/true` round trip completed within the previous 30 minutes.
- Root-run `synctl doctor` passes configuration, identity, socket, overlay, and classic-sudo checks. Before installation, missing armed state and the still-setuid alternate provider are expected; full armed health must pass immediately after apply.
- Root recovery session is open.
- Durable rollback timer is active and its deadline is visible.
- Current backups and provider modes match the captured baseline.

Run the installation plan without `--apply`, save the redacted JSON, and compare every proposed action with the expected list. Then run the guarded apply operation.

Immediately inspect in this order:

1. Managed `NOPASSWD` rule exists for only UID 1000/user `ferrerluis`.
2. Syn plug-in is loaded globally.
3. `/usr/bin/sudo` resolves to `sudo.ws`.
4. Alternate sudo-rs entry points have no setuid bit and have Syn-recorded stat overrides.
5. Agent is active as the unprivileged `syn` account.
6. `synctl doctor` reports all identity fingerprints and coupling as healthy.

Any unexpected result triggers local recovery immediately; do not diagnose while leaving an uncertain passwordless state armed.

## Phase 8 — run the authentication matrix

**Passed on 2026-09-04 UTC.** All authentication-matrix rows passed, including Mac password approval, fresh repeated/concurrent approvals, actual system cancellation, unavailable-agent/Mac behavior, signed-decision harness checks, live malformed replies, and missing-plug-in denial. Each fault was followed by restoration and a fresh ordinary-sudo approval. Final request `795aafa0ee12064c4d3ce2d6206580e4` returned root UID 0 and exit 0; doctor was healthy. Rollback remains enabled for **16:18:20 UTC (12:18:20 p.m. Eastern)**. This does not complete Phases 9–10 or permanently enable Syn. [Evidence and test-scope distinctions](validation/2026-09-04-phase-8.md).

Use commands with harmless effects until the security states pass:

| Test | Input | Required result |
| --- | --- | --- |
| Allow once | `sudo /usr/bin/true` | Mac password prompt during iteration, then exit 0 once |
| Reuse | repeat the same command | a new request and new authentication |
| Explicit denial | deny on Mac | deny immediately; no Ubuntu password |
| Mac cancellation | cancel system authentication | no execution; terminal explains that Mac authentication was canceled and that rerunning sudo creates a new request |
| Interactive absence | quit Syn.app, run with TTY | after 90 seconds, normal no-echo Ubuntu password prompt |
| Non-interactive absence | `sudo -n /usr/bin/true` | fail after expiry; no prompt |
| Terminal cancellation | Ctrl-C while waiting | request cancellation; late approval rejected |
| Local policy | `sudo -s`, `sudo -i`, configured shell/interpreter | hard deny before notification |
| Wrong/replayed decision | test harness | hard deny; no password fallback |
| Concurrent requests | two harmless invocations | separate reviews and fresh authentication |
| Agent crash | stop `syn-agent` | timeout path only; never implicit allow |
| Mac disconnect | stop Syn.app/network path | timeout path only |
| Alternate provider | invoke every sudo-rs path | no root elevation |
| Missing plug-in | temporarily move plug-in with root recovery open | managed sudo fails closed |

Re-arm the rollback timer before each destructive fault-injection subgroup. Restore the plug-in and service from the root session, then prove ordinary Syn approval before continuing.

## Phase 9 — verify the real user experience

**Passed on 2026-09-04 UTC.** Actual SSH installation and native Pi Codex reinstallation of `gh` both completed through ordinary sudo and fresh Mac approval. The native no-terminal path exposed a strict-parser bug; signed regression fixtures reproduced it, the parser was repaired without accepting missing required fields, and the actual Codex operation then exited 0. A final harmless command passed with user-confirmed Touch ID. [Evidence](validation/2026-09-04-phases-9-10.md).

After the harmless matrix passes:

1. From SSH, run a real narrowly scoped package operation such as installing `gh` if it is absent.
2. Confirm Syn displays `/usr/bin/apt` or `/usr/bin/apt-get`, `install`, and `gh` as separate fields.
3. Approve once and verify the original sudo process performs the installation.
4. Verify `gh --version`; do not treat the Mac approval alone as success.
5. Trigger the original scenario from Codex running on the Pi and verify it requires the same one-use Mac approval.
6. Ask Luis to approve one final harmless request with Touch ID and verify the command completes without using the Mac password.

The test must use ordinary `sudo`; no Syn wrapper, SSH forwarding, password injection, or privileged command endpoint is allowed.

## Phase 10 — upgrades, reboot, and recovery

**Passed on 2026-09-04 UTC.** Syn and both provider reinstalls, an actual armed Pi reboot with the unchanged absolute deadline, automatic relay reconnection, fresh approval, post-reboot recovery/password sudo, and guarded reinstallation passed. Two consecutive post-reboot approvals and interactive/non-interactive 90-second fallback checks passed. After explicit confirmation, cancellation itself passed through healthy Syn-controlled sudo; doctor remained healthy without a timer and a fresh permanent-state approval returned UID 0. [Evidence and limits](validation/2026-09-04-phases-9-10.md).

Only after the complete matrix passes:

1. Reinstall the Syn package and confirm configuration/keys are preserved.
2. Reinstall or upgrade `sudo` and `sudo-rs`; confirm stat overrides and plug-in coupling remain effective.
3. Verify the recovery timer survives a Pi reboot without extending its deadline.
4. Reboot the Pi and prove actual outage, new boot ID, SSH recovery, agent restart, Mac reconnection, and a fresh approval.
5. Run `synctl recover --restore-local-sudo --apply` from the Pi-local timer or root session.
6. Confirm `NOPASSWD` is removed first, providers and alternatives are restored, the agent is disabled, sudoers validates, and ordinary password sudo works.
7. Re-arm Syn once more using the same guarded path if the intended final state is enabled.

Do not cancel the final rollback timer until two consecutive approvals and one password fallback have passed after reboot.

## Failure and iteration loop

For every failure:

1. If the privileged path is uncertain, recover first.
2. Record the smallest redacted evidence that proves the failure.
3. Classify it as code, configuration, packaging, host assumption, UI, or test-harness failure.
4. Add a regression test before or with the fix where practical.
5. Patch on the Mac, rerun the complete local suite, resynchronize, and rebuild natively on the Pi.
6. Repeat the failed phase and every later security-dependent phase; do not skip ahead because a nearby check passed.

If recovery cannot be proven, the install state is missing while `NOPASSWD` exists, an alternate provider still elevates, an integrity error reaches password fallback, or a secret appears in output, recover immediately and remain in the fix-and-retest loop. Those are design failures, not flaky tests, so later phases stay blocked until the cause is fixed and the failed checks pass.

## Final report

The final evidence report must state:

- Exact Mac and Pi versions and Git commit.
- Network path used.
- Package and provider versions/modes before and after.
- Each matrix result with timestamps.
- Recovery timer evidence and actual recovery outcome.
- Reboot and upgrade outcome.
- Remaining untested claims or accepted risks.

Do not label the privileged milestone complete until this report exists and all required outcomes passed on the Pi.
