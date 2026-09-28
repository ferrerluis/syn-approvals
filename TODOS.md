# Syn roadmap

Product direction: enable agents to perform administrator actions on a remote machine with human control from a Mac. Manual work over SSH or a remote-desktop terminal should remain convenient with local password authentication; Syn must not depend on the terminal or remote-desktop application being used.

TODO 1 now has a candidate implementation and automated component coverage, but it is not accepted or live-proven. Every TODO 1 checkbox stays open until the complete [12-case E2E suite](docs/onboarding-e2e-test-plan.md) passes; the [UX map](docs/user-experience-map.md) distinguishes implemented candidate behavior from accepted behavior.

## 1. Mac-led distribution, installation and updates

Delivery plan: [Syn: simpler installation and updates](docs/distribution-onboarding-plan.md). The Mac-led candidate replaces the old remote-first installer and manual pairing proposal. TODOs 3 and 4 are included; checkboxes remain open until the full live suite passes.

### 1.1 Download and release identity

- [ ] Publish both components after every passing main build as one experimental release with a shared compact UTC timestamp and exact Git commit. No major/minor release scheme.
- [ ] Provide a stable latest-experimental-release link and immutable previous releases. Verify downloads and keep Mac/remote versions consistent even when only one component changed.
- [ ] Preserve Mac branding, app identity and Keychain access using the existing signing setup. Public Mac distribution signing/notarization is separate TODO 5, not a gate on experimental publication. Clearly state testing and independent-review status without claiming production readiness.
- [ ] Use GitHub hosting/builds within authorized limits, not a custom distribution service. Support anonymous public downloads and authenticated access while private; never ship credentials or silently substitute unsigned artifacts.

### 1.2 Install and pair entirely from the Mac

- [ ] Add **Add a machine**: hostname, SSH account/port, identity confirmation, access checks, administrator authorization, installation and pairing.
- [ ] Require existing SSH access and sudo permission; check OS, architecture, prerequisites and available space before changes. Initially validate Ubuntu 26.04 ARM64 and Apple Silicon macOS 15+.
- [ ] Reuse existing SSH configuration/agents where possible. Verify host keys, handle authentication securely, and avoid agent forwarding or stored remote passwords.
- [ ] Transfer the verified matching source bundle from the Mac and build as Syn's locked non-administrator build account. Request administrator access only for necessary dependencies and system changes.
- [ ] Exchange pairing information through authenticated SSH. No user-run Ubuntu installation command, manual key copying, pairing URL or separate pairing server.
- [ ] Preserve existing identities/settings, make retries safe, and distinguish **Connected** from **Ready**. Removing a Mac list entry must not imply that remote sudo has been restored.

### 1.3 Hostnames, not VPN providers

- [ ] Save and resolve the supplied hostname; the user provides its network reachability. Support ordinary LAN connections without requiring Tailscale or Nord Meshnet.
- [ ] Remove provider detection/selection and fixed Mac-IP restrictions. Preserve encrypted, authenticated connections and signed decisions; reachability is not identity.
- [ ] Listen on the selected address, handle address changes safely, and show disconnection/retry clearly. Do not automatically open all interfaces, configure VPNs or expose public ingress.
- [ ] Use SSH for setup and every update. Everyday approvals remain on Syn's existing direct connection, independent of SSH sessions and remote-desktop applications.

### 1.4 Matching-version updates and recovery

- [ ] Make **Update Syn and connected machines** the supported upgrade workflow. Show affected machines, obtain required authorization and install the Mac's exact release remotely over SSH.
- [ ] Detect mismatches when opening an updated Mac app. Block Syn approvals until versions match, with the rule authenticated and enforced remotely, not merely in the UI.
- [ ] Show offline/failed machines as disconnected or update-required and offer retry. Do not silently authorize later privileged work when credentials are unavailable.
- [ ] Remove the independent Ubuntu upgrade-to-latest workflow; retain local recovery/uninstall. Root can still alter the machine, so guarantee matching versions for approvals rather than identical installations at all times.
- [ ] Preserve keys/settings and restore ordinary password sudo before replacement. Keep automatic, local, reboot-persistent recovery armed through final activation checks; users do not manage timers.
- [ ] Remove `NOPASSWD` first during recovery, add it last during activation, and retain alternate-provider checks. Resolve ambiguous override ownership conservatively and ensure a hung updater cannot block recovery.
- [ ] Include TODO 3's immediate password escape and TODO 4's first-launch startup prompt in this delivery.

### 1.5 Documentation and validation

- [ ] README: Mac download → SSH/network prerequisites → Add a machine → first approval → password access → settings → update/recovery/uninstall. Use “remote machine”; keep Raspberry Pi 5 as a validated example.
- [ ] Explain the 90-second wait, Enter-to-password, explicit denial, sleep/offline behavior, SSH/Keychain prompts and private-signing limits. Never tell users to disable Mac protections globally.
- [ ] Use small Sol work packages and built-in Codex messages. Implementation agents test components; one dedicated final Sol agent owns the sequential E2E suite and all Computer Use or live Mac/remote-machine actions. The orchestrator reviews evidence and routes fixes without competing device use.
- [ ] Complete the [12-case E2E checklist](docs/onboarding-e2e-test-plan.md): actual uninstall from the Mac and remote machine, clean Mac-led reinstall, approvals/password escape, real LAN and hostname connections, matching-version upgrades, offline retry, and interrupted/reboot recovery. Keep exhaustive failure variants in automated component tests; group real authentication in the final coordinated window and finish with working installations on both devices. Use Raspberry Pi 5 as the tested remote-machine example, not as a requirement.

Acceptance: the actual downloaded release completes Mac-led setup, pairing and updates on the Mac and tested remote machine; only matching versions approve; interactive password access and failed-update recovery work; README matches the tested journey.

## 2. Time-limited “Always approve” and activity history

- [ ] Add **Always approve** with a duration dropdown: **5 minutes, 15 minutes, 30 minutes, 1 hour**. Make the finite duration visible; consider explanatory copy “Automatically approve for…” so “Always” is not mistaken for a permanent grant.
- [ ] Require fresh Mac system authentication to start or extend a window, show exactly which remote machine/account it covers, and make expiration and **Stop auto-approval** prominent. Recommended default: only the selected machine/account, not every connected machine.
- [ ] Automatically approve eligible requests within the chosen scope and period. Do not bypass invalid-message checks, local safety policy, revocation, explicit denial or expired requests.
- [ ] Keep an activity history in the Mac app for requests and decisions, including auto-approved ones. Record time, machine/account, request ID, a privacy-safe action summary, approval method and outcome when confirmed; show “unknown” when execution/delivery cannot be confirmed.
- [ ] Protect that history locally and define retention/clear-history controls. Do not persist passwords, environment values, pairing secrets or raw full argument lists; secret masking is not a complete logging boundary.
- [ ] Define cancellation/denial during an active window, concurrent requests, sleep, disconnect, Mac restart, remote restart, clock changes and late messages. Recommended initial behavior: require the Mac to stay awake and connected and end the window on restart; do not quietly introduce offline grants.
- [ ] Update the threat model, protocol, Secure Enclave design, engineering rules, UX map and tests before implementing this exception to per-request authentication. The existing approval key requires fresh presence; silently reusing an authentication context is not an acceptable shortcut.
- [ ] Ensure authorization is still enforced on the remote machine, not granted merely because its unprivileged relay says auto-approval is enabled. Define scope, expiry and revocation so a captured or replayed message cannot extend a window or approve another machine's work.

Tradeoff: this is an explicit change to Syn's current security contract. During the window, an agent can carry out eligible administrator actions without your inspecting each one; activity history is after-the-fact visibility, not prevention or undo. Keep **Approve once** as the default outside an explicitly enabled window.

Acceptance: after one authenticated opt-in, eligible requests in the selected scope auto-approve only until the chosen deadline or cancellation, appear in activity history, and require individual approval again afterward. Test every duration and failure case with shared protocol fixtures and adversarial tests.

## 3. Convenient password authentication for manual work

Included in TODO 1 as core interactive behavior, not human/agent detection or an optional update-only mode. No separate-account routing work is planned.

The Enter-to-password state machine and adversarial automated tests are implemented in the candidate. This remains unchecked until the live authentication, race, cancellation, and recovery cases pass.

### Press Enter to use the password now

- [ ] Implement an interactive wait prompt: **“Waiting for Syn approval. Press Enter to use this machine's password instead.”** Pressing Enter once should leave the pending Mac-approval path and start the protected remote password prompt immediately, without the 90-second wait.
- [ ] Cancel/invalidate the pending Mac request before starting password authentication; a late Mac approval must not create a second completion or authorize a later command. Preserve the original invocation instead of reconstructing or re-running a command from a string.
- [ ] Make this the standard path whenever interactive authentication is supported. No prompt for `sudo -n`, absent/closed terminals or redirected input masquerading as a user's terminal.
- [ ] Treat Enter as a request to authenticate, never as human-presence evidence or approval. An agent that simulates Enter still needs the actual account password.
- [ ] Keep explicit denials, integrity errors and local policy blocks final for the invocation. Specify and test the race between Enter, a Mac decision and timeout; no terminal input may turn a completed hard denial into password fallback.
- [ ] Keep the password in the normal protected authentication conversation: never send it to the Mac, put it in command arguments/environment, log it or expose it to model-visible output. Account for terminal ownership and agents that control their own terminal capture.
- [ ] Update the authentication/fallback contract before implementation: the current rules allow fallback only after ordinary unavailability/expiry, not early Enter. Migrate the old optional fallback setting so this interactive password path is standard; preserve hard-denial and non-interactive rules.

Acceptance: the supported manual-work path offers a password without an unwanted delay; Enter during a pending interactive request safely switches to that path. Successful authentication completes the original operation once; bad passwords, late decisions, Ctrl-C, non-interactive invocations and denial races never create an approval bypass.

## 4. First-launch startup preference

Included in TODO 1's Mac onboarding delivery.

The first-launch prompt, persisted choice, settings control, and component tests are implemented in the candidate. This remains unchecked until installed-app acceptance passes.

- [ ] On first opening Syn, ask **“Start Syn automatically when you log in?”** with **Yes (recommended)** and **No**.
- [ ] Explain the benefit: approval requests can reach this Mac without remembering to open Syn. It neither wakes a sleeping Mac nor approves requests automatically.
- [ ] Apply the chosen setting through macOS's supported login-item mechanism and verify success; show an actionable error if system policy blocks it.
- [ ] Remember the answer, do not repeat the prompt on ordinary launches or upgrades, and keep **Launch Syn at login** available for later changes.
- [ ] Test Yes, No, dismissal, registration failure, existing installs with a saved setting, relaunch and upgrade. Do not interpret a dismissed prompt or the recommended default as consent.

Acceptance: first launch offers the choice once, a successful Yes actually enables startup, No leaves it disabled for a new installation, and the existing settings control reflects the real macOS state.

## 5. Public Mac signing and notarization

Separate from TODO 1. This improves the download-and-open experience; it does not block publishing the repository, landing site or a clearly labeled experimental release.

- [ ] Set up Developer ID distribution signing and Apple's automated notarization in the Mac release build, with credentials stored securely outside the repository.
- [ ] Preserve the app's identity and test existing Keychain access when transitioning from the current signing setup.
- [ ] Package and notarize the DMG, attach Apple's approval ticket, and verify the actual browser download → Applications → first-open flow under normal macOS security settings.
- [ ] Until this passes, clearly document the experimental build's signing limitations and expected security prompts; do not instruct users to disable system-wide protections.

Acceptance: the downloaded DMG installs and opens through the normal macOS confirmation flow without a manual security override. Notarization is not a substitute for an independent security review.

## 6. Make the repository public

Separate from TODO 1 and from the landing site. Syn can remain explicitly experimental when the repository becomes public.

- [ ] Audit the repository and Git history for credentials, private machine details, test artifacts and other material that should not be published.
- [ ] Add or verify the public license, contribution guidance, security-reporting instructions and experimental-release disclaimer.
- [ ] Change the GitHub repository visibility to public without replacing existing releases, tags, issues or pull-request history.
- [ ] Verify anonymous clone access and anonymous downloads through the README's latest experimental release link.

Acceptance: a signed-out user can inspect the repository, clone it and download the documented experimental release without receiving a private-repository error.

## 7. Public landing site

Separate from repository visibility and Mac signing/notarization. Use free hosting where practical.

- [ ] Build a concise product site explaining what Syn does, who it is for, its Mac and remote-machine requirements, and the approval/password-recovery experience.
- [ ] Link directly to the latest experimental Mac download, GitHub repository, installation guide, security model and known limitations.
- [ ] Include current product screenshots or a short feature-first walkthrough covering download, setup, approval, updates and recovery.
- [ ] Publish it on a stable public URL and verify that download and documentation links remain current as new releases ship.

Acceptance: a new user can understand Syn, confirm that their setup is supported, download it and reach the installation instructions from one public page.
