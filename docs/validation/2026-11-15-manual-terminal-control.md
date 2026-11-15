# Manual terminal control — 2026-11-15

## Change and scope

The screenshot's `sudo /usr/bin/python3 -I <script>` failed before Syn offered authentication. Executable and sudo-mode restrictions now select remote approval eligibility: excluded invocations require fresh local PAM in an interactive canonical terminal. The default policy therefore supports Python scripts, direct shells, `sudo -s`, and `sudo -i` without a remote wait.

Configuration, identity, final environment, and typed invocation validation precede this path. The plugin does not infer human presence from a terminal, reuse a sudo timestamp, send a remote request, or reconstruct the command. Wrong/canceled passwords and PAM errors do not permit execution. Remote denials, integrity errors, and replay checks remain final.

This is a source change, not an installed-plugin update. PAM outcomes are mocked in automated tests; no account password is read and no privileged command is executed. Live sudo/PAM acceptance with independent recovery access remains pending. A root shell permits further commands until it exits.

## Product acceptance catalog v1

Prerequisites: Linux, Rust 1.85, libpam development library, normal pseudoterminal and local socket access. Run `cargo test --workspace --locked --offline`. Tests use the default policy, synthetic invocations, real pseudoterminals, and synthetic PAM outcomes.

| ID | Repeatable test/action | Expected result | Status |
| --- | --- | --- | --- |
| TC01.1 | `manual_python_script_requires_fresh_password_for_each_invocation` | The Python command's executable and separate arguments are preserved; each invocation authenticates afresh, and only success permits it | Passed |
| TC01.2 | `manual_shells_and_restricted_modes_use_local_password` | Shells/interpreters and restricted sudo modes require local authentication even with timeout fallback disabled | Passed |
| TC01.3 | `manual_password_failure_or_error_denies` | Wrong/canceled password or PAM failure does not authorize the command | Passed |
| TC02.1 | `restricted_commands_without_interactive_terminal_never_authenticate` | Noninteractive sudo, missing/invalid terminal, regular file, pipe, and raw terminal are denied without calling PAM | Passed |
| TC02.2 | `eligible_commands_keep_remote_approval_path` | Eligible commands retain remote approval; an explicit administrator policy remains respected | Passed |
| TC03.1 | Existing plugin tests: environment validation, decision binding/denial/integrity, recovery, cancellation, and pending Enter escape | Existing authorization checks and cancellation behavior continue to pass | Passed |

Current product acceptance: **3/3 cases and 6/6 sub-tests passed**. Coverage: TC01 (3 sub-tests), TC02 (2), TC03 (1). The catalog does not count build, reporting, or housekeeping checks as product acceptance.

## Validation evidence

Base revision: `93693e4`; tested code is the working-tree change described above. Generated logs, exact source hashes, machine-readable results, and the original screenshot are kept in the ignored `test-runs/manual-terminal/` directory.

- Initial test compilation exposed ambiguous byte-buffer conversions in the new assertions; corrected to explicit byte slices before running acceptance.
- The sandboxed attempt passed the new tests but blocked existing socket operations and changed filesystem ownership observations. Those failures are infrastructure failures, not acceptance passes. The full suite was rerun outside the sandbox as the normal user; all 27 active plugin tests passed. The separate read-only command-search-path audit also passed (28 plugin tests total).
- The workspace run passed 140 unique tests and failed 3 in unchanged installer code. Two shell fixtures passed with standard `umask 022`; the process-cleanup test passed in isolation without code changes (the initial cause is not established). With those targeted reruns, all 143 regular workspace tests have current passing evidence. The additional directory audit brings the unique passing total to 144; the unrelated live provider audit remains ignored.
- Rust formatting, warning-free Clippy across all workspace targets on native ARM64 Linux (also the ARM64 type-check), Rust doctest compilation, four log-privacy tests, and cross-language fixture parity all passed. Commands and evidence are recorded in `test-runs/manual-terminal/results.json` and the adjacent logs.
- Swift tests are unavailable on this Linux host (`swift: command not found`); macOS CI remains required.
- No wire format, signing keys, installer ordering, provider audit, or running machine configuration changes.

## Rollback

Revert this source change before deployment. The currently installed plugin is unchanged by this work.
