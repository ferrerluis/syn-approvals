# Syn: simpler installation and updates

Plan only — revised 2026-09-05 with the decisions from our conversation. This replaces the earlier Ubuntu-first proposal; none of these changes is being claimed as implemented.

## 1. The experience we're building

**The Mac is where you install, connect and update Syn.** You shouldn't need to run an installation command on Ubuntu.

1. Download Syn from GitHub, put it in Applications and open it.
2. Choose whether to start at login — **Yes (recommended)** or **No** — and allow notifications.
3. Click **Add a machine**. Enter its hostname, SSH username and, if needed, SSH port.
4. Syn checks access, asks you to confirm the machine's identity and obtains administrator authorization.
5. Syn installs its matching remote component and exchanges pairing information over SSH. No copying keys, pairing links or certificates.
6. Complete the setup approval checks. Syn shows **Ready**, or explains what failed and how to retry.

SSH access and an account with sudo permission are prerequisites. Explain them in README and check them before making changes. Start with Ubuntu 26.04 ARM64 and macOS 15+ on Apple Silicon; use “remote machine” in product copy, with Raspberry Pi 5 as our tested example.

## 2. Connections and everyday approvals

Syn remembers the hostname you supplied. It resolves it when connecting and verifies the paired machine's identity. You provide the working network route: a home LAN, Tailscale, Meshnet or another suitable connection.

- Remove provider detection, provider selection and fixed Mac-IP restrictions. Syn must not manage VPNs or require a particular provider.
- Keep encrypted connections, paired-device certificates and signed one-use decisions. A reachable hostname is an address, not proof of identity.
- Listen only on the selected remote address, not automatically on every interface. Handle address changes and reconnects without silently trusting another machine or opening extra interfaces.
- **SSH is for setup and every update.** Ordinary approvals keep using Syn's existing persistent connection; no terminal or SSH tunnel needs to stay open.
- If the hostname cannot be reached, show **Disconnected** and retry. Do not guess which network service to enable.

Use the Mac's existing SSH configuration and agent where possible, including 1Password's SSH agent. Respect host-key verification, confirm new hosts and stop on changed identities. Do not forward the SSH agent, store remote passwords, or give Syn a general-purpose terminal interface. Installation uses fixed operations; usernames, hostnames and other inputs must never become executable shell text.

## 3. Versions and Mac-led updates

Every passing main build publishes both components as one experimental release, even if only one changed. Give the release one compact UTC timestamp, such as `20260905143022`, tied to its exact Git commit. Both components display that same ID; there is no major/minor release scheme.

Generate the ID once, prevent collisions and never replace an existing release's files. Platform packaging fields may need a compatible numeric format, but must map unambiguously to the same visible ID.

**Update Syn and connected machines** is the supported update action:

1. Show the release and affected machines; obtain the necessary authorization.
2. The Mac coordinates installing that exact release remotely over SSH.
3. Show each machine as **Updating**, **Ready**, **Disconnected** or **Update required**.
4. Only matching versions may process Syn approvals. Authenticate and enforce that match on the remote side too, not just in the Mac UI.
5. Offline or failed machines remain unavailable for Syn approvals until updated. Retry when reachable, requesting fresh credentials if needed; do not silently authorize future privileged work.

Opening a newly installed Mac version also detects mismatches and offers the required remote updates. There is no independent Ubuntu “upgrade to latest” user workflow. Keep local recovery and uninstall available if the Mac is lost; root can still manually change the machine, so identical installed versions cannot be guaranteed at every moment.

No cross-version approval compatibility matrix is required. The small SSH maintenance interface must still recognize older installed versions and recovery records so it can safely upgrade them. Do not add a privileged network updater.

## 4. Password access and safe updates

**Password access is a core interactive feature, not an optional update mode.** While a request is pending, show:

> Waiting for Syn approval. Press Enter to use this machine's password instead.

Enter cancels the pending Mac request and starts normal local password verification immediately.

Preserve the original command and complete it only once. Test Enter racing with approval, denial, timeout and cancellation. A completed denial or integrity/policy failure remains final for that invocation; Enter cannot override it. Non-interactive invocations do not prompt. Keep the 90-second wait when Enter is not used, and keep passwords out of Syn logs, network approval messages and test output. Update the existing fallback policy and documentation to make this interactive path standard.

A broken Syn plug-in could fail before displaying that prompt. Updates must therefore also protect password access independently:

1. Prepare and verify the candidate before changing sudo; preserve existing keys and settings.
2. Restore ordinary password sudo before replacing Syn.
3. Keep a local recovery timer and recovery tool that survive a disconnected Mac, interrupted installation or reboot.
4. Validate the candidate, re-enable Syn, then perform a real approval/health check.
5. Cancel recovery only after success. Otherwise restore password-only sudo and offer retry.

Users do not manage recovery timers. Keep the existing 15-minute recovery deadline separate from the 90-second command wait. Never remove another administrator's restrictions, weaken alternate-sudo checks or leave an ungated passwordless rule. Remove `NOPASSWD` first during recovery and add it last during activation. A hung update must not block recovery from running.

## 5. Downloads without a distribution platform

Use GitHub for downloads and builds. Public experimental publication is allowed without claiming production readiness or independent security review. Keep the app's existing signing identity, branding and Keychain access; Developer ID distribution signing and notarization are a separate [TODO 5](../TODOS.md#5-public-mac-signing-and-notarization), outside this delivery. This plan edit does not itself change repository visibility or publish a landing site.

Publish a Mac download and its exact matching remote source bundle after required tests pass. Keep previous releases and one working latest-experimental-release link. The Mac obtains the matching bundle and transfers it over SSH; build on Ubuntu as the ordinary user, with administrator permission only for necessary dependencies and installation.

Use anonymous GitHub downloads when public; while the repository is private, reuse GitHub's authenticated download tools rather than building a new account system. Do not forward GitHub credentials to the remote machine. Verify the bundle against trusted release metadata; a checksum fetched beside an untrusted file alone is not sufficient. Keep verification tied to the trusted Mac release where practical, rather than prescribing a new standalone signing service.

README should cover download, prerequisites, Add a machine, first approval, password access, settings, updates and recovery. Include honest private-access/signing limitations and real tested links. Do not disable macOS protections or add paid infrastructure without authorization.

## 6. Small Sol tasks, coordinated by Codex

I orchestrate and review; Sol agents implement bounded changes on separate branches/worktrees, starting from refreshed main and preserving existing work. Use Codex messages to coordinate ownership and dependencies — **no custom reservation service or ledger**.

| Chunk | Deliverable | Its own test gate |
| --- | --- | --- |
| 1. Releases | Shared timestamp, matching artifacts, GitHub builds/downloads | IDs and commits agree; incomplete or failed builds are not published; downloads verify. |
| 2. Connection and version checks | Hostname-based connections, no provider/IP dependency, enforced version match | Wrong identities and mismatches cannot approve; address changes and reconnects work. |
| 3. Password and maintenance | Enter-to-password plus safe install/update/recovery | No double execution; failed updates restore password sudo; keys and administrator restrictions survive. |
| 4. Mac SSH setup and updates | Add machine, secure authentication, pairing and exact-release installation | Isolated integration tests cover SSH failures, safe reruns and the interfaces shared with chunks 1–3. |
| 5. Onboarding and handoff | Startup choice, progress/retry screens, README | Automated UI/component tests cover choices and errors; hand over the documented flow to the final E2E owner. |

Split a chunk into smaller PRs where useful. Freeze shared interfaces before agents work on both sides; one owner edits each shared entrypoint. Implementation agents run component and isolated integration tests, not individual live E2E passes. After integration, assign one dedicated Sol agent to the entire sequential E2E suite. Only that agent uses Computer Use or changes the live Mac/Pi during acceptance; other agents receive failures and fix code in their own worktrees. If it stops unexpectedly, I check device state before handing control to a replacement.

Every handoff includes the diff, test results and remaining issues. I review and reproduce critical checks; a different Sol reviews security-sensitive changes. No phase is complete on an agent's assertion alone.

## 7. Component tests first; one sequential E2E pass

The [E2E test plan](onboarding-e2e-test-plan.md) defines **12 ordered cases**, with actions, expected results, recovery safeguards and evidence requirements. Related checks are bundled; exhaustive failure variants stay in automated component tests. One dedicated Sol agent owns the whole pass; I review its results.

- **Before E2E:** implementation agents pass Rust/Swift checks, ARM64 tests, protocol fixtures and isolated failure tests. Prepare genuine downloaded releases A and B so version changes are tested, not simulated by editing labels.
- **Before live changes:** the E2E owner inventories the Mac/Pi, verifies backups and proves independent administrator access. Preserve Secure Enclave keys and unrelated files. Coordinate the user-assisted window before uninstalling or interrupting services.
- **Clean installation is required:** actually uninstall Syn from the Pi and Mac, verify normal password sudo and absence of active Syn components, then reinstall from the browser and the Mac's Add a machine flow. Record retained Keychain identities separately; an install-over does not count.
- **Exercise the whole product:** startup, notifications, real approvals, Enter-to-password, denial/cancellation races, timeouts, hostname/LAN connections, matching-version updates, offline retry, interrupted updates and reboot recovery. Also test losing the Mac first, then finish with a working reinstallation on both machines.
- **One device owner:** no implementation agent independently launches UI tests or live approvals during this pass. Send fixes back through Codex messages; rerun failed cases and affected checks, then validate the required full sequence on the final artifacts.
- **Group human input:** run unattended preparation first and group fingerprints/password checks into the final coordinated window. Pause safely if the user leaves. Do not promise a single fingerprint or count simulated authentication as real acceptance.

Keep per-case pass/fail/blocked/not-run evidence, actual release IDs and observed command results. Missing LAN access or an unproven recovery route stays a blocker, not a waived pass. Screenshots and records must not expose secrets.

**Done means:** every required case passes on the final candidates, README matches the tested journey, no critical/high findings remain, and the user has one functioning Syn app and a healthy matching installation on the Pi. Timed auto-approval, credential adapters and public notarization remain separate; TODOs 3 and 4 are included.

Before coding SSH, settle its credential prompts and fixed maintenance calls in a small reviewed technical note. The existing [validation](live-pi-validation-plan.md), [hardening](p1-hardening.md) and [recovery-risk findings](security-review-followup-2026-09-04.md) are references, not proof that this new suite has passed.
