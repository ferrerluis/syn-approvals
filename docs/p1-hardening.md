# P1 fixes: same approval flow, narrower hidden authority

Branch: `codex/fix-p1-security-gaps`, based on `4b452c7`.
Addresses SYN-SEC-001 and SYN-SEC-002 in the [security assessment](security-assessment-2026-09-04.md). The assessment remains the historical record of the original code; these changes are not a claim that the deployed Pi has already been upgraded.

## What stays the same

- Ordinary `sudo apt install gh` and equivalent package-install commands use the same notification, review, fresh system authentication, and one-use decision.
- The 90-second wait and eligible Ubuntu-password fallback are unchanged. Explicit denial, unsafe environments, and integrity failures do not fall back.
- Mac UI, signing keys, pairing, transport, request/decision schema and golden vectors are unchanged. No additional prompt, tunnel, agent wrapper, or approval cache is introduced.
- Environment values stay local; Syn validates but never rewrites sudo's final environment, executable, or argv.

There is a necessary security restriction: preserving arbitrary hidden settings with `sudo -E`, custom search paths, loader/interpreter hooks, and unrecognized environment variables is no longer permitted. Keeping all such behavior unchanged would keep the second P1 open. Normal Ubuntu terminal/locale/GUI metadata and the supported package-install settings remain allowed; this is not a promise of compatibility with every custom sudo environment.

## SYN-SEC-001: persistent provider protection

`synctl` now inventories canonical alternate providers, including known direct Ubuntu entry points, regardless of their current setuid bit. It rejects unprotected provider files/parents, unresolved paths and an unexpectedly empty inventory.

An alternate provider without an override gets Syn-owned persistent protection whether its current mode is `4755` or `0755`. An existing compatible root-owned administrator override is recorded separately, verified against live permissions, and preserved during recovery; incompatible or inconsistent overrides block installation.

The complete inventory, persistent overrides and live modes are checked after protection, immediately before adding `NOPASSWD`, and by installed-coupling diagnostics. Missing/new providers, missing overrides and restored setuid modes fail these checks. This is not continuous monitoring: a future package that moves its setuid provider to a new path requires a fresh audit before upgrade; Syn cannot retroactively block direct execution at that path. The installer still adds passwordless access last; recovery removes it first and syncs the directory before restoring ordinary sudo.

New installation records use schema 2 so older recovery binaries cannot silently discard administrator-override ownership metadata. New recovery code accepts legacy schema-1 records, whose recorded overrides were all Syn-owned. A legacy installation is not reported as having passed the new coupling check merely because it previously passed the old one.

## SYN-SEC-002: bounded final environment

The exact managed sudoers rule now specifies `NOSETENV`, `env_reset`, `!setenv`, and a fixed system search path. The trusted plug-in checks the final environment before reading the signing key or contacting the relay.

The compiled policy:

- Rejects unknown names, duplicates, malformed entries, NULs and execution hooks such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5OPT`, `NODE_OPTIONS`, `APT_CONFIG` and custom configuration/editor hooks.
- Requires the fixed Ubuntu system search path and checks that existing directories and their resolved ancestors are root-owned and not group/world-writable. Missing optional directories are allowed only with protected existing ancestors; dangling links are rejected.
- Checks `HOME`, `SHELL`, `USER`, `LOGNAME` and `MAIL`, when present, against the target account from reentrant NSS lookup. Sudo's invoking-identity fields must match the invocation. This requires the run-as UID to have a resolvable account.
- Validates sudo 1.9.17p2's generated `SUDO_HOME` against the invoking account's NSS home directory, not the run-as account's `HOME`.
- Allows constrained terminal/locale settings and ordinary `DISPLAY`/`XAUTHORITY` metadata, without granting a general `XDG_*` or arbitrary-variable exemption.
- Preserves `DEBIAN_FRONTEND` (`noninteractive`, `dialog`, `readline`, `teletype`), `DEBIAN_PRIORITY` (`low`, `medium`, `high`, `critical`) and `NEEDRESTART_MODE` (`a`, `i`, `l`). Their names are explicitly permitted in sudoers; their values are checked by the plug-in.
- Replaces both `env_keep` and `env_check` with explicit managed-user lists. Sudo discards unsupported inherited defaults such as `LS_COLORS`, `XDG_CURRENT_DESKTOP`, `TZ` and shell prompts before approval, rather than letting them break an otherwise ordinary invocation. Custom `SUDO_PS1` and unexpected values introduced by a root-owned PAM/environment configuration still fail the final check; they are not granted a broad exemption.
- Emits only fixed error categories. Unsupported names and values are not copied into errors, logs, network requests or password prompts.

There is deliberately no configuration switch to allow arbitrary hidden environment variables. A separately approved command can still explicitly perform root-equivalent operations, including invoking `env` with visible assignments in argv; this is not containment. Never put a secret in visible command arguments as a workaround—credential brokering remains outside this sudo alpha.

## Validation and deployment boundary

Validation uses Mac tests and an isolated, unprivileged source copy on the existing Ubuntu ARM64 Pi. It includes malformed/hostile environment fixtures, source-derived synthetic sudo 1.9.17p2 environment and managed inheritance cases, current NSS account defaults, real `visudo` syntax checking on a temporary rule, complete-provider inventory cases, simulated missing/restored override states, and explicit read-only checks of the Pi's real provider protection and search directories. Source-derived fixtures are not an end-to-end execution of sudo's policy normalizer.

Verified on 2026-09-04:

| Check | Result |
| --- | --- |
| Mac Rust workspace tests | 52 pass; one Pi-only check skipped here |
| Ubuntu ARM64 Rust workspace tests | 64 pass; two opt-in checks run separately |
| Pi provider and search-path read-only checks | Both pass |
| Swift approval/protocol tests | 25 pass, warnings treated as errors |
| Rust formatting and strict clippy | Pass on Mac and native ARM64; ARM64 plug-in cross-check also passes |
| Cross-language golden vectors | Regenerated bytes match both committed fixture copies |
| Privacy-checker tests | 4 pass |

The optional read-only target checks are intentionally excluded from generic CI hosts:

```sh
cargo test --workspace --locked read_only -- --ignored
```

They inspect existing metadata and override records; they neither run sudo nor add/remove an override. No attack library, privileged test command, live installer/recovery cycle, package upgrade or additional biometric prompt was executed for this branch. Full privileged deployment acceptance remains pending; passing these tests does not waive independent recovery access or the public-release review gate.

Deployment must be a separate guarded operation: retain independent root recovery access, restore ordinary password sudo before replacing/re-arming the coupled installation, install the new binaries, and follow the existing fresh preflight and timed-recovery procedure. Retain paired keys; do not manually replace just the sudoers rule or downgrade recovery tooling against schema-2 state. Revalidate normal approval, explicit denial, timeout, non-interactive behavior and uninstall recovery before canceling the recovery timer.

The [adversarial follow-up](security-review-followup-2026-09-04.md) records the additional compatibility correction and remaining limits. The hosted Swift toolchain mismatch (SYN-SEC-006) is also fixed by explicitly selecting Xcode 26.2 and treating Swift warnings as errors. The other original P2 findings remain open.
