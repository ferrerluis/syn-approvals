# Syn onboarding E2E results — September 14–21, 2026

This file records the exact candidate used by each live case. It does not
replace component or release evidence and does not claim installation, pairing,
PAM, or real Mac user-presence coverage unless a case says so.

## Evidence scope and final-candidate transfer

The 12 case IDs passed as a **hybrid** suite: live cross-device behavior is
combined with final-tree component checks for deliberately injected races and
tampering. It is not a claim that every variant below ran live on release 05ac.
The final audit table names the composed boundary.

Final production release `20260921060301` is commit
`05ac9146709f2cfc06814bde21207eed07575ef0`, tag
`experimental-05ac9146709f2cfc06814bde21207eed07575ef0`. Its tree hash
`85fffc55fe708ddfd222b0d2515a01ee78116b6b` exactly matches PR #23 head
`64212914ca58978d6357914ce720635f18a7e885`, whose [CI run
35300346068](https://github.com/ferrerluis/syn-approvals/actions/runs/35300346068)
passed release metadata, Rust, Ubuntu ARM64 and macOS jobs. That run includes:

- Rust formatting, warnings-as-errors clippy, AArch64 plug-in clippy, protocol
  golden-vector equality, workspace tests, log-privacy checks and release/E2E
  tooling tests. The exact substituted-bootstrap-helper test passed there.
- A native Ubuntu 26.04 ARM64 offline source/package build with release identity
  and helper-loader verification.
- 148 Swift tests, including notification privacy/Review routing, hostname and
  endpoint handling, provisional update routing, startup choices and transport
  identity checks.

The [main push run
35566801291](https://github.com/ferrerluis/syn-approvals/actions/runs/35566801291/attempts/1)
is red because GitHub artifact storage quota rejected `release.json` upload.
Its independent Rust job passed; downstream ARM64/macOS jobs were skipped by
that infrastructure failure. This is disclosed rather than described as a green
merge run. The identical PR tree supplied the full green prerequisite evidence,
and the published final ZIP/source were independently downloaded and verified.

The older live cases transfer to 05ac through this checked lineage:

- **E02, E06–E09 and E11:** ran on fixed B `af3a9e4`, an ancestor of
  05ac. Later production changes are confined to startup/login-item handling;
  SSH, transport, decision, PAM, sudo and uninstall paths are unchanged.
- **E04 update routing:** ran on ancestors `c2bf844` and `a0f0533`. The only
  later Linux runtime change before af3 is the E10 recovery-service fix. Update
  routing and version binding are unchanged, and final production installation
  re-exercised the same Add-machine/coordinator path.
- **E10 reboot recovery:** ran from fixed A `b0028d7` to fixed B `af3a9e4`.
  The tested recovery worker and unit files are unchanged from af3 to 05ac.
- **Notification preview and Review:** ran live on ancestor `4bf642d`. The
  final notification body, actions, posting/removal and response routing retain
  that implementation; the later change only extracts the `SynNotifying` test
  seam. Final-tree Swift tests also cover privacy and Review routing.
- **E01 removal baseline:** ran on the legacy package, then E11 repeated
  supported removal on af3. E12 installed and verified final 05ac from ordinary
  sudo.

Scope disclosures:

- The final private-repository asset was obtained with authenticated `gh` and
  matched the published SHA-256. A logged-out Chrome visit to the exact final
  GitHub release URL returned GitHub's expected private-repository 404. An
  earlier authenticated browser pass exercised the unchanged README download
  link, but this report does not claim that the final ZIP itself was downloaded
  through the browser.
- Production 05ac exercised **Yes (recommended)** and real SMAppService
  persistence. The **No** choice was exercised only in the isolated UI/component
  path; a live production No→relaunch→enable-in-Settings sequence was not run.
- Bootstrap-helper hash substitution and denial/late-decision races are
  final-tree component coverage, not separate live fault injections. The live
  cases prove the normal bootstrap, denial and Enter-to-password paths.
- One Touch ID approval succeeded in the first production attempt before the
  second request expired. Luis explicitly authorized a full retry, whose two
  Touch ID approvals completed setup: three successful Touch ID authentications
  total, two in the accepted attempt. Mac login-password fallback was waived
  and is not claimed as live-tested.

The [original internal assessment](../security-assessment-2026-09-04.md) found
two P1 issues; both fixes are ancestors of 05ac. Its [adversarial
follow-up](../security-review-followup-2026-09-04.md) found no additional
demonstrated P0/P1, the [test-harness
re-review](2026-09-12-test-harness-review.md) found no residual P0/P1/P2 in
that bounded scaffold, and this E2E run found no new P0/P1. A final adversarial
static review of exact commit `05ac914` found no demonstrated P0/P1/P2 across
sudo/PAM coupling, restricted maintenance, recovery ordering, pairing,
transport, version binding, Secure Enclave use, and test-harness exclusion.
This is an internal evidence statement, not the independent security review
required before a public security claim.

## E02 — setup errors are recoverable

Status: **passed** against final fixed B `20260915232455` at
`af3a9e46dd8f2af899dda767e57b8850a85513c7`, with harness
`04294fdd0579f2fa956fb96113cff174985197f6`. Cancellation was scoped to Syn's
in-progress SSH check; no physical macOS, Keychain, Touch ID, 1Password, or
remote-password dialog was invoked or canceled.

- The [browser-download record](2026-09-11-browser-download-recovery.md)
  proves that authenticated Chrome followed the README's stable
  `releases/latest/download/Syn-macOS-latest-experimental.zip` link and produced
  bytes matching GitHub. That README line is unchanged in 05ac. The exact final
  private asset was instead downloaded through authenticated `gh`, verified by
  hash, and installed; logged-out Chrome returned the expected private-repo 404.
  This is composed download/setup evidence, not a claim that final 05ac itself
  was fetched in the browser.
- The exact app at
  `/private/tmp/syn-e10-fixed-b-af3a9e4-04294fd/SynE2E.app` was launched with
  profile `org.syn-approvals.SynE2E.case-e02-final-af3` under fresh owned
  mode-0700 root `/private/tmp/syn-e02-final-af3.yax8Eg`. Its executable
  SHA-256 was
  `72f57fc200c2e745409c0b190c4f44ec4bf66cf699dfda1dc069eb051cf196b1`.
- On first launch, **Not now** left launch-at-login off for the isolated app.
  `syn-e02-unreachable.invalid` then produced the visible error **SSH access
  could not be verified. Check the address, host identity and SSH
  credentials.** The form remained editable and **Check connection** remained
  available.
- A check to the unroutable documentation address `203.0.113.1` visibly entered
  **Checking SSH access and Ubuntu compatibility...** and exposed **Cancel**.
  Cancel returned immediately to the editable form and **Check connection**.
- Retrying with the existing `pi` SSH alias and account `ferrerluis` succeeded.
  The app visibly reported **A Syn installation was found. Update required.**
  **Install or update Syn** was not clicked.
- Before and after the case, the Pi retained boot ID
  `b5023d24-9765-4613-b7bf-3f060ae7b560`, final fixed-B release and commit,
  active/enabled agent, inactive/disabled recovery timer, unarmed recovery, and
  `/usr/bin/sudo -> /usr/bin/sudo.ws`. The exact mode, owner, size and mtime of
  `/usr/bin/synctl` and `syn-agent.service` were unchanged.
- `~/.ssh/config` stayed at mtime/size `1788373153:333`, and
  `~/.ssh/known_hosts` stayed at `1788318157:20888`. The isolated profile
  contained only its three mode-0600 signing/profile files and empty mode-0700
  state/inbox directories; it contained no target or password file.
- After the evidence was captured, the exact test app was terminated and the
  verified isolated root was removed. The production app, login item, final E12
  profile and Pi were not changed.

## E01 — uninstall both devices safely

Status: **passed**. Actual removal and protected recovery state were verified on
both devices; no temporary administrator account or real Mac approval was used.

- Luis supplied the existing Pi credential for this personal test run and
  authorized immediate ordinary-sudo bootstrap. It was used only at no-echo
  remote TTY prompts and was not written to a file, command argument or evidence.
  No temporary administrator account was needed and no 1Password work resumed.
- The installed legacy PAM first waited for Syn approval. With no real Mac
  approval used, the documented 90-second path exposed the Ubuntu password
  prompt. `/usr/bin/synctl recover --restore-local-sudo --apply` then exited 0,
  removed `/etc/sudoers.d/90-syn-managed-user`, restored the pre-Syn
  `sudo.conf` and sudo provider/stat state, disabled `syn-agent.service`, and
  reported ordinary password sudo restored with keys retained.
- A fresh `sudo -k /usr/bin/id -u` prompted for the Ubuntu password and exited
  0 with UID `0`. This is the required actual password-sudo proof, not an
  inference from reaching the legacy Syn wait.
- Before package removal, a root-only mode-0700 backup was created at
  `/var/backups/syn-e2e-e01-20260914`. It contains 37 protected files including
  sudo/PAM, Syn state, service/package and root SSH state plus a mode-0600
  checksum manifest.
- The legacy supported uninstall command exited 1 with `No such file or
  directory` after the successful recovery had removed its install-state file.
  The safe post-recovery fallback `dpkg --remove syn-approvals` then exited 0.
  This legacy idempotency failure is recorded rather than hidden by the final
  removal result.
- Final protected verification found the package, `/usr/bin/synctl`, systemd
  unit, managed sudo rule, `sudo.conf` Syn plug-in and maintenance config absent;
  `syn-agent` and the recovery timer were inactive, TCP port 24874 had no
  listener, no Syn `NOPASSWD` entry was found, and `visudo -c` passed.
- The Mac legacy app, active profile and preferences were copied to the
  mode-0700 backup `~/Library/Application Support/Syn E2E Backups/20260914-e01-preuninstall`.
  The copied app passed strict deep signature verification. Secure Enclave and
  Keychain identities remained in place and non-exported. The Mac-only E2E
  backup was retained during recovery testing, then permanently removed during
  the final audited cleanup; it is not a Pi recovery backup.
- With Luis's action-time confirmation, the visible production switch changed
  from **Launch Syn at login: on** to **off**. Syn then quit normally. The app,
  active profile and preferences were moved into that protected backup rather
  than deleted, leaving `/Applications/Syn.app` and the active support/preference
  paths absent. Final checks found no Syn process or launch service. This was an
  actual reversible uninstall, not an install-over or deletion of identities.

Candidate B `20260913222755` at
`8ba152ca2eae80a7a2e91b758d6857fe8e2382dd` has passed CI and its matching
mock-approval app is ready; release preparation no longer blocks testing.

## E03 — fresh Mac-led installation

Status: **passed with final production release 05ac**. The earlier isolated
installation and paired relaunch below passed, and the accepted production
retry completed with two distinct real Touch ID approvals.

- Release `20260916180742` at `0663e9880c50f1a6a2e45bfa308a378ee93c49c5`
  exposed the missing first-launch sheet recorded below. It was replaced
  reversibly by final release `20260921060301` at
  `05ac9146709f2cfc06814bde21207eed07575ef0`, published as tag
  `experimental-05ac9146709f2cfc06814bde21207eed07575ef0`.
- The final Mac ZIP independently matched SHA-256
  `90efd9e8fa16dadd3126a96e77d16bbad8dd2af69b58efbeeb714b417ac76fe7`;
  archive validation and strict code-signature verification passed. The exact
  app replaced 0663 at `/Applications/Syn.app`. The former app was temporarily
  retained for rollback and later removed in the audited validation cleanup.
- With no `targets.json`, no saved `syn.startupChoice.v1`, and the login item
  still off, 05ac visibly showed **Start Syn automatically when you log in?**
  with **Not now**, **No**, and **Yes (recommended)**. Testing paused before
  **Yes (recommended)** because that click changes the macOS login-item setting
  and requires action-time confirmation. The Pi remained on ordinary password
  sudo and was not changed.
- Luis then authorized **Yes (recommended)**. The production app stored the
  `yes` choice, showed **Launch Syn at login** on, and retained that state after
  a normal quit and relaunch, providing the required real login-item persistence
  proof. Fresh **Add machine** with SSH alias `pi` found the compatible target,
  and the trusted bootstrap PTY returned protocol 1 with `applied:true` without
  exposing the machine password.
- The final-tree Rust test
  `bootstrap_copy_rejects_substituted_helper_with_trusted_hash` replaced the
  incoming helper with same-length untrusted bytes and observed the exact
  fail-closed hash/size error. It passed in PR #23's green Rust job. The normal
  hash-pinned helper ran live; helper substitution itself was not injected into
  the live Pi setup.
- The first configure attempt failed closed before activation because three
  retained E2E public trust files did not match the production Mac identities.
  The package post-install script cannot recreate those files, and the request
  journal remained at `package_built`. Supported `synctl unpair
  --restore-local-sudo --apply` removed exactly the approval key, denial key,
  approver CA and two public proof files while preserving the valid target and
  TLS private/public pairs. The same production flow then retried without an
  uninstall or another bootstrap.
- The retry built final 05ac and produced the first distinct
  `/usr/bin/true harmless_preflight` request for target
  `target_464df0038c5d413c93ed87b2074b5b48`. Luis clicked **Approve once** and
  completed real Touch ID; the signed decision was consumed, the agent started,
  and recovery armed. A second distinct final-health request then appeared, but
  expired before **Approve once** or LocalAuthentication was invoked.
- That expiry failed closed and restored ordinary sudo automatically. Recovery
  reported `not_armed`, the agent was inactive and disabled, the managed
  `NOPASSWD` rule was absent, and `/usr/bin/sudo` resolved to sudo-rs. No retry
  was attempted under the two-prompt budget. E05/E12 paused at that point
  pending Luis's next decision.
- A gate-2-only retry was not technically possible after safe rollback because
  the final-health check requires the live sudo gate that rollback removes.
  Luis therefore authorized one full supported retry. It reused the matching
  production identities and restricted maintenance key, created a fresh
  operation, and required no unpair, uninstall, bootstrap or Pi password.
- That accepted retry produced two distinct request-bound
  `/usr/bin/true harmless_preflight` approvals. Codex clicked **Approve once**
  for each so the macOS system prompt was visible; Luis completed both with
  Touch ID. The second was not completed with the Mac login password. Luis
  waived a separate password attempt, so this run does not claim live coverage
  of LocalAuthentication's Mac-password option.
- Setup completed, saved exactly one production target, and a normal quit and
  relaunch returned `pi — Connected`. Release `20260921060301`, launch at login
  and the production target record persisted.

### Historical E03 attempts — superseded

The following failed and diagnostic attempts explain the fixes incorporated
into the passing final lineage. Status language here is historical; none of
these paragraphs overrides E03's final status above.

- Exact-A SynE2E resumed with fresh isolated profile
  `org.syn-approvals.SynE2E.case-e03` under the owned mode-0700 root
  `/private/tmp/syn-e03-live-be4dc921.KcEMXT`. The first-launch startup choice
  was visibly set to **No**; this in-memory test-app choice is not claimed as
  real macOS login-item proof.
- The app checked the real `pi` SSH alias as `ferrerluis` and visibly reported
  **Compatible remote machine found. Syn is not installed yet.** It staged the
  signed A bootstrap helper and displayed the expected hash-pinned one-time
  administrator command. The app did not ask for or transmit a Pi password.
- Computer Use refused access to Terminal. A subsequent attempt to execute the
  exact app-copied bootstrap through strict-known-host SSH was rejected by the
  execution safety reviewer because clipboard contents would be run with sudo
  and install persistent privileged SSH maintenance access. No workaround was
  attempted.
- Read-only validation then decomposed the displayed command against A's
  embedded source and bytes. The staged helper is 2,099,712 bytes with SHA-256
  `165a4d2ea8255a2c468703af8e1f3acfcfadc893df6b5421a298e8e9755ddf19`;
  its Ed25519 maintenance public-key fingerprint is
  `SHA256:zzODpLaZucuIMbwkxxLGaR6jhrKmHv/LxmSg0zR/ZJs`. The fixed installer
  manages UID 1000 `ferrerluis`, retains root-owned code/config only under
  `/var/lib/syn/maintenance`, and appends one exact `restrict,no-user-rc`
  root key entry forced to `/var/lib/syn/maintenance/synctl --json maintenance
  serve`. That dispatcher accepts only the bounded protocol-v1 maintenance
  vocabulary. A typed, fixed-path/argv execution sequence was then submitted
  with create-new-directory, root ownership/mode, exact size/hash and key
  fingerprint checks. The execution reviewer still rejected the persistent root
  SSH maintenance side effect because it requires explicit approval after that
  risk was disclosed. No directory, key or other Pi state was created. E03 was
  blocked until Luis explicitly approved that disclosed side effect.
- After Luis explicitly authorized the disclosed restricted root maintenance
  bootstrap, the fixed-path retry reached the signed A helper. An operator
  transcription first passed the public `.pub` comment as part of `--public-key`;
  the helper failed closed with **maintenance key must be one Ed25519 public key
  without a comment** before installing maintenance access. This was not an app
  defect: exact-A normalizes the generated command to the two-token
  `ssh-ed25519 <base64>` key.
- The corrected, app-equivalent retry passed the root directory, helper
  ownership/mode, size, SHA-256 and key checks, then failed with **/bin is not a
  protected root-owned directory**. On the Ubuntu ARM64 target, `/bin` is the
  standard root-owned usrmerge symlink to `usr/bin`, while `/usr/bin` is a
  root-owned non-group-writable directory. Exact-A validates the configured root
  shell `/bin/bash` with `symlink_metadata` and rejects the `/bin` parent before
  resolving that standard layout. No maintenance key was installed. The
  root-owned mode-0700 bootstrap directory and mode-0500 hash-verified helper are
  retained at `/var/tmp/syn-bootstrap.e03a20260914` pending controlled cleanup
  with the fixed helper.
- Candidate A was refreshed to release `20260914201728` at
  `71fe22da3ce871d3c2ebf08b6770fcdd7b0db8c5`. Its exact SynE2E app visibly
  reported that release, preserved the E03 maintenance identity, staged the
  2,099,712-byte helper with SHA-256
  `a87b37553f6fd559d9f7c16c37253623aeb67c9940bdcde2e5e0a6f34e449b26`,
  and displayed the normalized two-token public key. The earlier failed helper
  residue was identity/hash-checked and removed before this retry.
- The corrected helper passed the Ubuntu usrmerge root-shell check, then failed
  with **/root/.ssh/authorized_keys is not a protected root-owned file**. The
  installer uses a general protected-file validator that rejects zero-length
  files before reading or appending an authorized-key entry. The retained helper
  and maintenance config are written before that validation. Root-only evidence
  confirmed `/root/.ssh/authorized_keys` is a pre-existing regular empty
  root:root mode-0600 file under mode-0700 root directories; it was not changed
  and contains no maintenance entry. The partial state is the root:root
  mode-0700 maintenance directory, a 372-byte mode-0600 config, and the
  2,099,712-byte mode-0500 retained helper. The one-time `/var/tmp` copy was
  removed by its trap. E03 remained failed; this diagnostic run was not a pass
  for the corrected candidate, and the empty authorized-keys file was not
  altered to evade the defect.
- A locally built diagnostic helper containing the focused empty-file fix was
  then exercised only to de-risk the next release. After exact cleanup of the
  A71 partial files, its hash-checked bootstrap returned `applied: true`. The
  installed restricted identity accepted exactly `syn-maintenance
  --protocol-version 1 probe` and returned protocol 1 for `ferrerluis`. It
  rejected a missing command, an extra argument, the old `syn-maintenance-v1`
  spelling, and protocol version 2 with exit 1. A requested local forward could
  open only its local listener; attempting to use it was reset by the server,
  and the test listener was then closed. This proves the focused fix and forced
  SSH boundary diagnostically, but it was not a released-candidate E03 pass.
- The diagnostic identity was removed through its supported retained-helper
  `maintenance revoke --apply` path after exact root-only config, helper and key
  checks. Revoke returned `applied: true`, removed the exact config/helper and
  sole forced key entry, and restored the pre-test empty root:root mode-0600
  `authorized_keys` file. The now-empty root:root mode-0700 maintenance directory
  remained intentionally for the final released-candidate retry; no unrelated
  root key existed or was removed.
- Final corrected candidate A `20260914203908` at
  `c0a751e36ff2b55fd6f42dbea7fa257ca3e231f6` passed the one-time bootstrap
  from its exact published app/helper and installed the restricted maintenance
  identity without spending a Mac approval. The immediately following normal
  app step failed twice, visibly and deterministically, with **Syn could not
  create the client certificate.** The focused production OpenSSL generation
  test passed on this Mac, and no matching E03 transport certificate was present
  in Keychain, so this was not evidence of a stale certificate collision. No Pi
  package/service activation or pairing completed; E03 remained failed at the
  client-certificate boundary with the final-A maintenance key installed.
  Read-only inspection found the hand-built SynE2E bundle is ad-hoc, lacks a
  Team ID and entitlements, and fails strict deep signature verification because
  resources were added after its executable was signed. That test-app packaging
  defect had to be corrected and retried before attributing the certificate error
  to shipping production code.
- After the test bundle was properly ad-hoc signed and passed strict deep
  verification, the certificate failure reproduced once unchanged. The
  remaining cause is harness-only label expansion: fresh setup uses a
  `target_` plus 32-hex target ID, while SynE2E prepends the full E03 profile ID
  to the certificate common name, taking it beyond OpenSSL's common-name length
  limit. Shipping Syn's short `Syn` prefix remained within the limit. The harness
  needed a short deterministic profile-isolated prefix and the same signed-app
  flow before E03 could continue.
- The signed short-label retry did create the certificate, eliminating the
  OpenSSL failure, but the production guard then correctly reported **The
  transport identity does not match this target.** The onboarding request
  contract requires the exact production label `Syn <target ID> transport`;
  the harness's custom prefix could not satisfy it. Harness isolation instead had to
  rely on its fresh random target ID and separate target/profile stores while
  retaining the production label contract. No remote install phase began.
  The failed mismatch attempt left one precisely inventoried test certificate,
  alias `E2236ea4792eb1 target_d47a2080b4e444b29525ee076b73b7c0
  transport`, with certificate SHA-256
  `C4CA2A24F379BCE44824142001E258AE2863E73BC9B81504FEE4BC1883C1512E`.
  It was retained only for exact identity cleanup; no production-label item was
  queried or removed.
- With the contract-correct signed harness, certificate creation and the exact
  request-label guard passed and setup advanced through **Copying verified
  release** to **Building on the machine**. The build then failed with **The
  machine could not complete setup. No remote diagnostics were retained.** The
  maintenance probe still succeeded, while the package, `/usr/bin/synctl` and
  `syn-agent.service` remained absent/inactive. Unprivileged staging still held
  the exact final-A source archive (SHA-256
  `d07864259132b38a6ffd998067fcea8746b86364a064d3091a910c273499bb5d`),
  request and bootstrap helper for operation
  `1b3f3c594dce4ed199f0a66642ca479d`; root-only operation state needed inspection
  before cleanup or retry. E03 remained failed before activation or mock signing.
- Root-only inspection confirmed the build failure's exact cause. Candidate A
  calls `ensure_build_account()` before `ensure_build_root()`; on a fresh host,
  `adduser --home /var/lib/syn-build/home` creates `/var/lib/syn-build` as
  root:root mode 0755 and the build home as `syn-build:syn-build` mode 0750.
  The following guard correctly required the build root to be exactly mode 0711
  and failed instead of silently changing existing state. The protected request,
  source, helper and journal remained under the exact operation, with no package
  or build work directory. The new locked `syn-build` account/root are tracked
  test resources; neither was changed to hide the ordering defect.
- After the build-root was deliberately normalized to the intended mode as a
  diagnostic, the preserved operation built final A successfully. A normal UI
  retry then created operation `3e2459087f4c452a7ec3bb5d7e1e3ddf`, built and
  installed package `syn-approvals 20260914203908`, and failed with the same
  generic no-diagnostics message before configuration/activation. The installed
  `/usr/bin/synctl` is root-owned mode 0755 (2,102,168 bytes) and the unit file
  exists, but the service is inactive and disabled, the target config/private
  key were not visible to the unprivileged account, and no listener is present.
  That visibility check alone does not prove the root-only files absent. The
  maintenance probe remained healthy. Root-only operation evidence was required
  to identify this next configure/pre-activation blocker; this diagnostic path
  was not an E03 pass.
- After the retained production pairing was backed up and removed through the
  supported unpair path, a fresh diagnostic operation completed build/configure
  far enough to enable and start the service on the Meshnet address. The Mac
  then failed with **Network.NWError -65554 - NoSuchRecord**. The request stored
  input hostname `pi` and listen IP `100.99.102.171`; production code passes the
  SSH alias itself as the later WebSocket hostname. OpenSSH resolves `pi` through
  the user's SSH config, but Network.framework cannot resolve that local alias.
  This is a production alias-to-transport handoff defect, not a pairing or build
  failure. The service was active/enabled for the diagnostic operation, but E03
  remained failed before the mock approval/health checks.
- Exact Keychain cleanup inventory for the contract-correct diagnostic attempts
  is retained by target label and certificate SHA-256: `Syn
  target_c3455afe7c724f3b983346380fc6ec57 transport` / `50350ACD...6689`,
  `Syn target_3bf98c1581624ba5a2d6c1a50ebbde3d transport` / `70C54A55...5A5B`,
  and active diagnostic `Syn target_0b5d9e3a45db44b4b5223b23a618a46a
  transport` / `3DF76A08...DF16`. Cleanup had to remove each exact certificate
  and associated test private key only; no broad `Syn` label deletion was safe.
- The approved fresh-baseline cleanup completed through the supported c0 paths.
  `unpair` removed the five active public pairing/proof files; `uninstall`
  restored the ordinary `sudo-rs 0.2.13` password provider, passed `visudo`,
  stopped/disabled the agent, removed `syn-approvals 20260914203908`, and
  revoked only the exact maintenance entry while preserving unrelated
  `authorized_keys` content. Target-signing and TLS-private-key hashes were
  unchanged. No additional user approval was consumed.
- The test-created `syn-build` account/group and live `/var/lib/syn-build` are
  absent after proving no process owned by that UID. The complete diagnostic
  build root was moved reversibly to root-owned mode 0700 backup
  `/var/backups/syn-e2e-buildroot-20260914-pre-rootfix`. The now-inactive Mac
  identity `Syn target_0b5d9e3a45db44b4b5223b23a618a46a transport` was deleted
  by its full certificate SHA-256
  `3DF76A0842F699ABFDEFC5F62AD3D325DE1FB6B72D8E470C4CDED1608274DF16`;
  an exact-label lookup confirmed it was absent. E03 was ready for a clean retry
  once the combined build-root/effective-SSH-HostName candidate is published.
- Fresh candidate `cac297eb26ccab8fa1fbbbea88cfa8755879bb64`
  (`20260914220436`) passed the clean build-root regression without manual mode
  normalization and reached its harmless activation preflight. The first mock
  approval was attempted before its exact one-use harness grant existed; the
  harness correctly failed closed, nothing was approved, and automatic recovery
  returned the UI to a retryable state. This operator sequencing error was not a
  candidate failure.
- The supported normal retry then exposed a distinct retry defect. Original
  operation `a58dfcb19fc6d37bf28a5d023c08bdf3` used target
  `target_e6f8579a20f2413fbebb712742016fc4`; retry operation
  `87229ab2a96893abe4c4ea82d70efc58` instead generated
  `target_beaba0ddbb7b4857a0c5d7af39bc6eff` and a new client-identity label.
  Exact root-only hash comparison proved approval and denial keys were identical
  across both requests and active state. The original client-certificate hash
  `2d65520e4652de820cf7eef8444c6eaaf735a11d0606936f3785474193791591`
  matched active state, while retry hash
  `c0a8fb5c99082ed910b4f74e56f77917df3bb272e88a7794a9e992de5b1dcf94`
  differed. The protected retry configure correctly failed with `retained
  pairing identity differs from this Mac`. This live evidence supersedes the
  earlier source-only assumption that installed status preserved the target ID;
  no diagnostic unpair was used to hide the retry failure.
- Correction: the preceding A-to-B/E04 harness concern came from inspecting the
  stale repository worktree instead of exact harness commit
  `5a9964cf7b120501e6ce1dc7c5186e3f3c151fd7` used to build candidate A. The
  exact harness already persisted its two raw test-only private keys as owned
  mode-0600 files, verifies them against the recorded public-key fingerprints
  on reload, and preserves them on normal quit. It removes the exact profile,
  per-process state, and inbox only when launched with
  `SYN_E2E_FINAL_CLEANUP=1`. A-to-B relaunch therefore had the required mock
  signer persistence; no new persistence redesign is justified.
- Retry-fixed candidate `ec404f2b7f14234c624e29b6f17ebf77a5f87eec`
  (`20260914224649`) completed normal build/configure. Its exact activation grant
  was present before approval, consumed once, and cleared before the completion
  gate. The UI then rejected the activation response as invalid, while protected
  journal operation `81d1fc7ada3fd1af18e87f0f0e6da90a` proved activation had
  persisted at `armed_pending_final_approval` with recovery still armed. Exact
  source shows first activation runs `sudo.ws -V` through an inherited-stdout
  child runner before emitting the final JSON envelope; that version output can
  pollute the single-value stdout contract that the Mac decodes strictly. This
  is a candidate response-contract failure, not a missing mock grant; completion
  was not attempted.
- Automatic recovery from that activation-response failure was independently
  observed at `not_armed` with valid inactive/disabled timer state, ordinary
  `/usr/lib/cargo/bin/sudo` selected, and the agent inactive/disabled. Supported
  unpair/uninstall then removed candidate `20260914224649` and only its five
  public pairing/proof files and exact maintenance entry; `visudo` passed,
  unrelated SSH keys and target/TLS private hashes were unchanged, and the
  already-proven build account/root remained intact. Exact inactive transport
  identity `Syn target_9f000e1b67484e03867ee4efd7faaa44 transport` (certificate
  SHA-256 `AD57020E1927151C29272334487DED66DB16D56B88A4972C11ECDC593B1572B5`)
  was deleted and verified absent. The obsolete local reset script is absent;
  the persistent 5a mock-signer profile remained for the corrected candidate.
- Production candidate `12d555daaae73bc3800065c6f6b8c6451fa30cea`
  (`20260914231518`) suppresses child-process output before emitting the strict
  activation JSON response. Test-only harness
  `083ac46f033dd831aeb4384fc26132b2372b1109` also rearms its cached signer only
  after one request-bound grant is consumed; its full Swift suite passed 140
  tests with no failures and one live-SSH skip. The exact signed A test app was
  `/private/tmp/syn-activation-final-a-12d-e2e-083ac46/SynE2E.app`
  (executable SHA-256
  `5b20723039aa8dac275bac20f212d723e63d6cb4496eec75645a2172a4e8cbea`).
- A fresh supported baseline retained the existing test-only signer profile and
  proven build infrastructure but removed the prior package, pairing and exact
  maintenance entry. The A bootstrap then installed the independently checked
  2,099,712-byte helper with SHA-256
  `e31a612cdfb23b3f4658d3e3558cbb4a8e115dbce5694494901bbaf33cc0ad8e`
  through the UI-generated two-token Ed25519 command; it returned protocol 1,
  managed user `ferrerluis`, and `applied:true`.
- The clean A flow built and configured without manual directory changes. Its
  activation request and a distinct completion request both used target
  `target_7d2a65cb52574ac093cda107c3aa5d8b`. For each gate, the exact fresh offer
  was validated, one request-bound mock grant was atomically published, the
  offer was removed before the click, and `Approve once` consumed the grant.
  The app completed with `Syn 20260914231518 is already installed
  (configured)`. A normal quit and relaunch using the same private profile then
  reported `pi — Connected`, proving the pairing and test signer survived the
  process boundary; no real Mac approval was used.
- The Pi reports `syn-approvals` installed at `20260914231518` with
  `syn-agent.service` active and enabled. Recovery service/timer state is
  inactive after completion. The final restricted key accepts exact
  `syn-maintenance --protocol-version 1 probe` and reports protocol 1/user
  `ferrerluis`; it rejects the legacy spelling, protocol 2, an extra argument,
  and `id` with exit 1. A direct-stream forwarding request exits 255 with
  `administratively prohibited`. The post-install startup switch remained off;
  OS login-item behavior is deliberately not claimed from this test-only app.

## E04 — offline update, then A to B

Status: **passed**.

### Historical E04 attempt — superseded

- Exact signed B test app
  `/private/tmp/syn-activation-final-b-5e1-e2e-083ac46/SynE2E.app` uses
  production commit `5e18b66687a12a72b094607849cb6973830e2f46`, release
  `20260914232618`, and the same rearmed test harness `083ac46f...`; its
  executable SHA-256 is
  `f695a8a0f0a76106ea3257e5b73c4e20f0a1fed5e8fb80bc76ad6ae78e9cb80b`.
- With A healthy, the isolated profile's saved target changed only from default
  SSH port 22 to verified-unreachable port 65000. Host `pi`, target identity,
  host trust and maintenance SSH on port 22 were preserved. B honestly showed
  `Disconnected` plus `Update required`; the real update action failed with
  `SSH access could not be verified` and produced no approval or execution.
  The app was closed and the exact original target record was restored
  byte-for-byte (SHA-256
  `42feb7985560af15759385e02ebedecef2d7a5ad56b471add3b258506a99c044`);
  its temporary backup was removed.
- On the restored route, B found installed A and entered the normal update flow
  through the already-authorized maintenance key without another bootstrap or
  password. After beginning the remote build it paused with `Retry needed` and
  `Secure connection setup was interrupted after certificate verification.
  Finish any Syn Keychain permission, then choose Retry. Automatic retries are
  paused.` No approval request or mock grant appeared, Retry was not clicked,
  and no real Mac approval was spent. This boundary is under exact
  app-signature/Keychain diagnosis and was not then classified as a production
  update failure.
- After Luis cleared the Keychain prompt, the same exact app resumed normally
  through **Building on the machine**. Operation
  `72a42e602721f70d905f3f14eb3dc3f8` installed B
  `20260914232618`, configured the preserved target
  `target_7d2a65cb52574ac093cda107c3aa5d8b`, and produced its harmless
  `/usr/bin/true` activation-preflight request. This proves the prior pause was
  the Mac Keychain boundary rather than a remote build or release mismatch.
- The fresh offer was an owned mode-0600 regular file for that exact target and
  request with one use and more than ten seconds remaining. The pinned grant
  helper SHA-256 was
  `22d321088425b25c81785cf5d016081a1396eaf933aceeaa6d7b909b0b79a632`;
  it created and verified one request-bound approval grant, then unlinked the
  offer before **Approve once**. The harness consumed the grant, but the app
  reported **Approval delivery could not be confirmed** and setup then failed
  at **Activating protected recovery**. No second offer or grant was created.
- Protected read-only inspection found the operation still at
  `paired_pending_approval` with no recovery deadline. The B package and
  root-owned `synctl` were installed, `syn-agent.service` was active and enabled,
  both recovery units were inactive, `/usr/bin/sudo` resolved to the ordinary
  provider, and `sudo -n` failed. The agent journal recorded the provisional
  approver connection closing without a WebSocket handshake; no activation or
  privileged command execution occurred.
- Exact-B source identifies the deterministic update-only routing defect.
  `markUpdateRequired` stops but retains the saved A connection, while approval
  delivery chooses that retained `connections[targetID]` before the active
  `provisionalConnections[targetID]`. Fresh E03 had no retained connection and
  therefore did not exercise this branch. A supported retry was stopped in the
  UI before its approval gate once it entered a new B build; no mock grant was
  issued. The already-started remote build may finish its protected package
  phase, but could not activate without the later request-bound approval. At
  that point E04 remained failed pending a focused connection-selection fix
  and a rerun of the affected update flow.

### Accepted corrected E04 rerun

- The corrected update was rerun with signed app
  `/private/tmp/syn-e04-final-a-c2b-e2e-083ac46/SynE2E.app`, production commit
  `c2bf844c9fb9bf9c057d2f4cd4fd114d7f9719eb`, release
  `20260915062228`, test-harness commit `083ac46f...`, and executable SHA-256
  `2f4ef9f8e3de0ec7efdb225a0811501db85633434f157a2a30517d92b91e4e25`.
  The restored hostname passed a fresh SSH check and the installed older state
  was identified as requiring an update. The update reused the established
  restricted maintenance key and did not request another bootstrap password.
- The corrected build produced two distinct `/usr/bin/true harmless_preflight`
  requests for target `target_7d2a65cb52574ac093cda107c3aa5d8b`.
  Each exact offer was validated; a separate request-bound, one-use mock grant
  was atomically published; the offer was removed before **Approve once**; and
  the grant was consumed. The first advanced to protected recovery activation
  and the second advanced to final verification. No real Mac approval was used.
- Syn then reported `pi — Connected` and
  `Syn 20260915062228 is already installed (configured)`. The Pi independently
  reported the exact release, `syn-agent.service` active and enabled, both
  recovery units inactive, `/usr/bin/sudo` resolving to `sudo.ws`, and the
  alternate `sudo-rs` binary without setuid. The retained key accepted
  `syn-maintenance --protocol-version 1 probe` and returned protocol 1 with
  managed user `ferrerluis`.
- The saved Mac record still contains the E03 target ID, display name, hostname,
  SSH user, host-trust source, pinned server certificate and client-identity
  label; only its installed release metadata advanced to c2bf. Successful mTLS
  reconnection and both Pi-verified decisions prove the preserved pairing keys
  remained usable. This corrected rerun supersedes the earlier failed attempt
  while retaining that failure as regression evidence for the routing fix.
- Root-owned post-update inspection confirmed the same target ID, managed user
  `ferrerluis`/UID 1000, 90-second timeout and expected listener. `synctl doctor`
  reported healthy coupling across the agent, plug-in, policy, paired identities,
  `sudo.ws`, non-setuid alternate provider and one-user sudo rule. Recovery was
  `not_armed`. Only public key identifiers were compared; no key material was
  copied into the evidence.

## E05 — real production Mac approvals

Status: **passed for Touch ID and production signing; Mac login-password
fallback explicitly not live-tested**.

- The [September 4 live record](2026-09-04-phases-5-6-progress.md) proves
  notification behavior on ancestor `4bf642d`: Luis confirmed
  the alert showed the machine/user without command contents and that **Review**
  reopened the closed Syn window; the Pi then verified the resulting denial.
  Final 05ac retains the same notification actions, body, posting and response
  routing, and its 148-test Swift run covers notification privacy and Review
  routing. This is explicit unchanged-code transfer, not a claim that 05ac
  displayed a second live banner during the final two-prompt budget.
- Final shipping release 05ac used the production Secure Enclave signer,
  production approval/denial identities and production transport identity. The
  activation request and later final-health request were separate, each bound
  to its own nonce, request ID and live `/usr/bin/true harmless_preflight`
  invocation for target `target_464df0038c5d413c93ed87b2074b5b48`.
- Codex opened **Approve once** for each request. Luis supplied fresh Touch ID
  twice; both signed decisions were consumed on the Pi and setup reached
  `complete`. The first armed protected recovery before sudo activation; the
  second verified the live gate and disarmed recovery.
- The earlier safely rolled-back attempt had already consumed one successful
  Touch ID approval before its second request expired. Luis explicitly
  authorized the full retry. The honest run total is therefore three successful
  Touch ID authentications, while the accepted attempt used the planned two.
- The accepted retry used no test signer or test trust. Final root doctor was
  `healthy:true`, with approval key ID
  `aef792627d4292ab38b42311d76ad7a066f7f6b878d3875253293234e9589eb2`,
  denial key ID
  `fc42c95d874029c57041ffbf5d47d15c1280977e36fcb5a556ca1c0e4480557e`,
  and target key ID
  `0cf62823e803de96967eb35b271e9a9b0d354fc990964036383b640fffa02345`.
- Luis reported that the second system prompt was also completed with Touch ID,
  not the Mac login password. He waived another live attempt. Apple's
  LocalAuthentication `userPresence` password option remains documented product
  behavior, but this result does not claim it as live-tested.

## E09 — Meshnet, disconnection and reconnect

Status: **passed**.

- The paired target used saved endpoint
  `wss://ferrerluis97-everest.nord:41781`. With the Mac test app stopped, the
  Pi remained reachable over Meshnet by ordinary SSH and `syn-agent.service`
  remained active, while no approval offer appeared and the harmless root-owned
  marker did not exist. No installer or maintenance SSH session was kept open.
- A normal `sudo /usr/bin/touch /tmp/syn-e09-reconnect-marker` invocation was
  left waiting in its own terminal. Relaunching the same app and isolated
  profile re-resolved the hostname, re-established the paired mTLS connection,
  displayed the exact pending `/usr/bin/touch` request for the preserved target
  ID, and created the request-bound harness offer.
- One exact one-use mock approval was published after validating the executable
  and marker argument; its offer was removed before **Approve once**. The grant
  was consumed, the original sudo process exited successfully, and the marker
  existed with UID 0. This proves the approval used Syn's direct paired
  connection rather than an SSH forwarding tunnel. The marker is tracked for
  final test cleanup.
- Physical-LAN behavior was not live-tested because the Mac and Pi were not on
  the same home LAN. The already-passed endpoint/component tests cover ordinary
  hostnames and provider-independent addressing; this live case proves the
  available Meshnet route, disconnection safety and reconnection behavior.

## E06 — denial and cancellation

Status: **passed**.

- A live interactive sudo invocation requested
  `/usr/bin/touch /tmp/syn-e06-deny-marker`. After validating that exact offer,
  the harness published one request-bound denial and removed the offer before
  **Deny**. The Pi immediately returned
  `Syn approval was denied or Mac authentication was canceled`, exited 1 and
  did not offer the password fallback; the marker remained absent.
- Test-only harness commit
  `04294fdd0579f2fa956fb96113cff174985197f6` extends the authoritative
  `083ac46f...` harness with a locked
  `unused -> authenticationCanceled -> consumed` state machine. It permits an
  exact canceled approval attempt to produce no approval signature and then
  permits exactly one independently bound denial signature for the same live
  request. Distinct requests cannot displace that pending denial, and replay,
  expiry, mismatch and concurrent attempts fail closed.
- The authoritative harness passed 143 Swift tests with one expected live-SSH
  skip. A separate Sol adversarial review of the exact commit found no P0, P1
  or P2 issue and confirmed that earlier persistence/cleanup hardening remained
  byte-for-byte unchanged. The exact c2bf app built with this harness passed
  deep/strict signing, no-symlink and embedded-release byte checks; its
  executable SHA-256 was
  `90b0a3f2f4637298b69eadfead3837df99d5825e01a62f08d43113dad7a02531`.
- A second live sudo request targeted
  `/usr/bin/touch /tmp/syn-e06-cancel-marker`. The exact
  `cancelAuthentication` grant made the approval signer return the same error
  as a canceled macOS identity check; Syn then sent the one signed denial. The
  UI cleared and showed `Approval canceled or unsuccessful. Nothing was
  approved`; the Pi exited 1 immediately and the marker remained absent. This
  system-dialog cancellation was mocked, not physically performed.

## E07 — interactive Enter-to-password escape

Status: **passed**.

- A live interactive request for
  `/usr/bin/touch /tmp/syn-e07-wrong-marker` displayed
  `Waiting for Syn approval. Press Enter to use this machine's password instead.`
  Pressing Enter canceled the pending Syn request before showing
  `Syn request canceled. Enter this machine's password to continue.` and the
  normal no-echo `Password:` prompt. One synthetic wrong value exited 1; the
  marker remained absent and no fallback approval or retry occurred.
- A separate live request for
  `/usr/bin/touch /tmp/syn-e07-correct-marker` followed the same Enter path.
  The real machine password was entered by the human in a separate PTY and was
  never provided to the test runner. The command exited 0 and created the
  marker as UID/GID 0, mode 0644.
- In both runs the Syn pending UI cleared immediately after Enter, no test grant
  existed, and only the exact canceled request's owned mode-0600 offer remained.
  Each residual offer was validated against its executable and marker argument
  before exact unlinking. A delayed recheck found no new offer or grant; the
  failed marker stayed absent and the successful marker was unchanged. This
  proves the password path first invalidates the remote request rather than
  treating Enter as an approval.
- This live case did not inject a late signed decision after PAM began. The
  final-tree plug-in test `enter_escape_wins_once_and_late_agent_bytes_stay_unconsumed`
  submits late agent bytes after Enter wins and proves that the completed
  exchange cannot consume them. E06's live explicit denial exited immediately
  with no password fallback; the final invocation was already closed, so later
  terminal input could not reopen it. These race assertions are the component
  half of the plan's hybrid E07 coverage, not additional live claims.

## E08 — timeout and non-interactive behavior

Status: **passed**.

- `sudo -n /usr/bin/touch /tmp/syn-e08-n-approved` received one exact
  request-bound mock approval. The original invocation exited 0 and created a
  UID-0 marker, proving non-interactive sudo can proceed only after a valid
  decision.
- A separate `sudo -n` invocation targeting
  `/tmp/syn-e08-n-timeout` received no decision for the full 90-second window.
  It reported `Syn approval unavailable; non-interactive sudo denied.`, exited
  1, never displayed a password prompt, and did not create the marker.
- A live interactive request for
  `/usr/bin/touch /tmp/syn-e08-interactive-timeout-marker` displayed the normal
  Syn wait message. The marker was absent before expiry and no password prompt
  appeared early. After the full configured wait it reported
  `Syn approval timed out. Enter your Ubuntu password to continue.` and showed
  the normal no-echo `Password:` prompt.
- The human entered the real machine password in a separate PTY; the test
  runner never received it. The command exited 0 and created the marker as
  UID/GID 0. The Mac pending UI cleared on expiry, no grant existed, and the
  exact expired mode-0600 offer was validated before unlinking. A delayed
  recheck found the marker unchanged and no late offer or grant.

## E11 — Mac lost, local access retained

Status: **passed**.

- The connected Syn E2E app was quit and removed from its live path before any
  remote recovery action. Its exact bundle was retained only in a reversible
  temporary backup for the following clean-reinstall case; the production
  `/Applications/Syn.app` path was already absent. The Pi agent remained active
  at this point and the restricted maintenance probe still worked, proving the
  Mac side disappeared before the remote side changed.
- With no approver app running, local
  `sudo /usr/bin/synctl uninstall --restore-local-sudo --apply` immediately
  offered the dedicated machine-password recovery prompt. The human entered the
  password in a separate PTY; it was not exposed to the test runner. The command
  exited 0 after removing Syn's NOPASSWD rule first, restoring the ordinary sudo
  provider, disabling recovery and the agent, revoking the exact maintenance
  entry, and removing `syn-approvals 20260915062228`.
- Post-removal inspection found the package absent, no exact `syn-agent`
  process, the service/recovery units inactive and no longer installed, port
  41781 closed, the managed sudoers rule absent, and `/usr/bin/sudo` restored to
  setuid `sudo-rs`. `sudo -n` was denied. The retained Mac maintenance private
  key could no longer authenticate as root, while ordinary SSH as the existing
  user still worked.
- A fresh `sudo -k; sudo /usr/bin/id -u` displayed the ordinary sudo password
  prompt after Syn had been removed. The human entered the password in the PTY;
  it returned `0` and exited successfully. Syn's protected pairing keys,
  recovery helper/backups and the Mac maintenance key remain intentionally
  retained for the supported clean reinstall and final recovery record.

## E12 — final clean reinstall and handoff

Status: **passed; final 05ac production handoff is complete**. The clean
fixed-B reinstall, repaired real startup choice, accepted two-approval retry,
Mac-absent password path, final health and exact test-resource cleanup passed.

- The prior active test profile was removed from use and temporarily retained
  as an exact private backup. That backup was permanently removed in the final
  audited cleanup. A fresh isolated profile launched the exact c2bf production
  app plus reviewed 04294fd test signer. The first-start question visibly
  offered **Yes (recommended)** and accepted it; because the E2E login-item
  service is deliberately in-memory, this was UI coverage only and was not
  the required macOS login-item proof.
- The first install attempt correctly failed closed after build because the E11
  uninstall had intentionally retained the previous pairing keys and the test
  sequence had not yet run E01-style `unpair`. No activation request or grant
  existed; ordinary sudo remained restored. This was an operator sequencing
  error, not accepted as a product pass. The failed profile was isolated, then
  supported `unpair` removed exactly the five public pairing/proof files and
  supported `uninstall` removed the inactive package and newly bootstrapped
  maintenance entry while retaining private keys/backups.
- The honest retry used SSH alias `pi`, whose evaluated OpenSSH route selects
  the dedicated local key and effective Meshnet hostname. Entering the literal
  hostname had instead selected the locked 1Password agent and timed out; that
  recoverable setup error made no remote change. The fresh bootstrap command
  was run in the trusted PTY with one ordinary machine-password entry, returned
  protocol 1 / `applied:true`, and kept the password outside the app and test
  runner.
- The clean B build/configure then produced two distinct `/usr/bin/true`
  preflight requests for new target
  `target_9befb9aa89654c7fbd34f5d35b5238a9`. Each exact offer was validated; a
  separate request-bound one-use mock grant was published and its offer unlinked
  before **Approve once**. Both grants were consumed, setup reported
  `Syn 20260915062228 is already installed (configured)`, and a normal quit and
  relaunch of the same profile visibly returned `pi — Connected`.
- A separate exact mock-approved `sudo /usr/bin/synctl --json doctor` ran on the
  ARM64 Pi and returned `healthy:true`: agent, plug-in, policy, identity
  coupling, socket, listener, sudo.ws provider, non-setuid alternatives,
  one-user sudo rule and install state were all valid; recovery was not armed.
  It also confirmed release c2bf/`20260915062228` and the listener on Meshnet.
- One final exact mock-approved `sudo /usr/bin/rm -- ...` removed the four
  root-owned E07–E09 marker files tracked by this run. A fresh `/tmp` inventory
  confirmed no `syn-e*` marker remained. Test trust, test app/profile, retained
  backups, production startup registration and the intended production identity
  remained at that point for the post-E05 handoff.
- For the later final-production attempt, the fixed-B test pairing and package
  were removed through supported `unpair` and `uninstall`. A fresh ordinary
  password-sudo PTY returned UID 0; the package, agent, managed rule, plug-in,
  and exact maintenance entry were absent, and sudo resolved to sudo-rs. The
  retained target-signing and TLS-private-key hashes were respectively
  `a63e90d80877ff6c2d5833ce746b31d30df4c2c250104dc312509e22c59da8de` and
  `6239a3c72ee3524c281a8c991f936324870751df991bee89632013f7e39ee3a6`.
  Production release 0663 was installed on the Mac, but its missing
  first-launch startup sheet stopped that run before login-item registration,
  Add machine, bootstrap, or either real E05 approval.
- Final release 05ac/`20260921060301` replaced 0663 from its hash-verified
  published ZIP. **Yes (recommended)** enabled the real login item and remained
  on across a normal relaunch. Fresh Add-machine/bootstrap succeeded. Retained
  E2E public trust caused one correct fail-closed configure; supported unpair
  removed it while preserving the Pi identity, and the production retry reached
  two distinct final checks. Real Touch ID approved the first. The second
  expired before LocalAuthentication, after which Syn automatically restored
  sudo-rs, removed the managed rule, stopped and disabled the agent, and
  disarmed recovery.
- Luis authorized one full supported retry because protected rollback makes a
  gate-2-only retry impossible without reactivating the sudo gate. The retry
  reused the production maintenance identity, created a fresh operation, and
  completed both distinct checks with Touch ID. A normal relaunch visibly
  returned `pi — Connected`, release `20260921060301`, and **Launch Syn at
  login** on. Exactly one production target is stored.
- With production Syn fully quit and no Syn process present, an interactive
  `sudo /usr/bin/synctl --json doctor` showed the Enter-to-password escape,
  canceled the remote request, accepted the Pi password in the trusted no-echo
  PTY and exited 0 with `healthy:true`. Relaunch returned Connected with no
  stale pending item. This proves Mac-absent local administration separately
  from the real Mac approvals.
- Final Pi audit found the agent active/enabled, Meshnet listener reachable,
  `sudo.ws` active, both sudo-rs executable paths resolved to root-owned mode
  0755, recovery `not_armed`, and no E2E account, unit, `/tmp` resource or
  maintenance/build process. Protected target/TLS keys, recovery backups and
  the active restricted maintenance identity remain intentionally.
- On the Mac, exact E2E transport identities for targets `7d2a…`, `957e…` and
  `9bef…` were removed by full certificate hash. Re-enumeration leaves only
  production target `464df…` with certificate hash `66169A…`. No SynE2E app,
  process or active test preference remains. The first cleanup pass moved its
  then-known resources recoverably to `~/.Trash/Syn-E2E-cleanup-GOwn13`, but a
  later independent audit correctly found additional validation-owned artifact,
  cache and worktree paths plus `BUILD-RECORD.md` and the Mac-only
  `Syn E2E Backups` folder. All 32 omitted items were identity-checked and moved
  to `~/.Trash/Syn-validation-cleanup-6bfCAc`. After an exact ownership/content
  audit, both validation-only Trash bundles were permanently removed; neither
  remains. Re-enumeration found
  no remaining `/private/tmp` path explicitly named in the validation ledger and
  no `syn-final-a-*`, `syn-final-b-*` or `syn-retry-final-*` path. The unrelated
  icon-build roots and current `syn-final-e2e-evidence` root were preserved as
  instructed; production `Syn/targets.json` and Pi recovery backups were not
  changed.

## E10 — interrupted update and reboot recovery

Status: **passed after fixing the automatic-recovery service**.

- Starting from healthy release A c2bf/`20260915062228`, the supported Mac
  update flow built and configured exact release B a0f/`20260915063410`. The
  first request-bound `/usr/bin/true` activation preflight was mock-approved.
  The Pi then reported recovery armed with absolute deadline `1789509769`
  (`2026-09-15T22:02:49Z`). At the second, distinct final-health request, no
  grant existed and the Mac test app was terminated to inject the planned
  interruption.
- The deadline remained exactly `1789509769` after the interruption. The one
  authorized reboot changed the boot ID from
  `ce2cac47-6854-46b3-b798-dc0e86c59ffa` to
  `a590c4b3-a67f-4deb-979a-36f87bc4b7ae`; port 22 was observed down and then
  reachable again over Meshnet. After boot the same deadline remained armed,
  active and enabled. The Mac app remained stopped throughout.
- At the original deadline, `syn-auto-recover.service` started without the
  Mac but failed five times. The journal recorded
  `root : unable to open /etc/sudoers : Operation not permitted`, followed by
  `synctl: /usr/bin/sudo.ws failed with exit status: 1`. The service unit runs
  with `NoNewPrivileges=yes`; the failing validation is the fixed
  `/usr/bin/sudo.ws -V` call immediately after the emergency path removes the
  Syn managed rule and plug-in registration.
- The failure was safe with respect to privilege: `sudo -n /usr/bin/true`
  exited 1, proving the passwordless rule no longer granted access. Manual
  recovery then restored ordinary password sudo. The reviewed fix changes the
  root-owned, fixed-path recovery unit to `NoNewPrivileges=no`, because Ubuntu
  otherwise prevents its required restored `sudo.ws` validation from opening
  `/etc/sudoers`. Fixed A b0028d7/`20260915231505` and fixed B
  af3a9e4/`20260915232455` both installed that unit; fixed A passed a
  mock-approved root doctor check with `healthy:true` before the rerun.
- In the fixed rerun, the supported A → B flow mock-approved only the first
  exact B activation request. At the distinct final-health request no grant
  existed, and terminating the Mac app left recovery armed at absolute
  deadline `1789548289` (`2026-09-16T08:44:49Z`). The deadline remained exact
  after interruption and after the one authorized reboot. Port 22 was observed
  down and back up over Meshnet, and the boot ID changed from
  `a590c4b3-a67f-4deb-979a-36f87bc4b7ae` to
  `b5023d24-9765-4613-b7bf-3f060ae7b560`; the Mac app remained stopped.
- At the original deadline, automatic recovery ran once and exited success
  without retry. It disarmed and disabled the timer, disabled the agent,
  removed the managed rule and plug-in registration, restored both sudo
  providers to mode 4755 with no Syn stat overrides, and selected ordinary
  `sudo-rs`; `sudo -n` was denied. A fresh PTY then displayed the ordinary sudo
  password prompt and returned root UID 0 after the human entered the password
  outside the test runner.
- The supported Mac flow then reinstalled exact fixed B. Two separately bound
  mock grants completed activation and final health verification. The UI
  reported `pi — Connected` and release `20260915232455`; a separate
  mock-approved root doctor returned `healthy:true` with recovery not armed.
  The target ID, target public key, server certificate pin, transport label,
  Meshnet endpoint and SSH settings match the pre-fault record; only the saved
  release ID and commit advanced to fixed B. No second reboot or real Mac
  approval was used.

## Final acceptance audit

Status: **12 of 12 cases passed within the documented scope**.

- **E01:** Passed — supported removal and ordinary-sudo recovery.
- **E02:** Passed — setup errors, cancellation and retryability. The final
  private asset used authenticated `gh`, not a browser.
- **E03:** Passed — final Mac-led install, real Yes/startup persistence and
  reconnect. No and substituted-hash variants are isolated/component coverage.
- **E04:** Passed — offline update and matched A-to-B release.
- **E05:** Passed — two real Touch ID approvals in the accepted retry, three
  total across both attempts. Mac login-password fallback was waived and was
  not live-tested.
- **E06:** Passed — denial and authentication cancellation.
- **E07:** Passed — live Enter-to-password escape plus final-tree denial and
  late-decision race coverage.
- **E08:** Passed — 90-second timeout and non-interactive behavior.
- **E09:** Passed — Meshnet disconnect and reconnect.
- **E10:** Passed — interrupted update, reboot and unattended recovery.
- **E11:** Passed — Mac-lost uninstall and local administration.
- **E12:** Passed — final production handoff and permanent removal of
  validation-only cleanup bundles.

The accepted live state is production release `20260921060301` at commit
`05ac9146709f2cfc06814bde21207eed07575ef0`: one Mac app, one paired target,
`pi — Connected`, launch at login on, healthy Pi coupling and recovery
`not_armed`. Test identities and active test resources are absent. Production
keys, the restricted maintenance key, target/TLS keys and protected recovery
backups remain intentionally.
