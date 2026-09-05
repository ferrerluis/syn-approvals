# Syn security assessment — 2026-09-04

## Verdict and scope

**Findings: no P0 identified, two P1, and four P2.** This review does not establish that Syn is vulnerability-free or satisfy the independent-review release gate. Fix the P1 findings before treating the approval display and installer as a dependable security boundary.

Assessed commit: [`888e63665b0ad63b788e4d6af431952e091876ae`](https://github.com/ferrerluis/syn-approvals/tree/888e63665b0ad63b788e4d6af431952e091876ae), pushed to `origin/main` before this assessment. The repository was verified private. This report is a subsequent documentation change, not a claim to have reviewed future commits or dependency-update branches.

Scope: Rust protocol, sudo approval ABI and PAM fallback, relay authentication and routing, configuration, installation/recovery, Debian scripts, native Mac verification/signing/display/transport, tests, CI, and locked Rust dependencies. Assessment methods were source tracing, existing tests, isolated synthetic probes, public advisory lookup, and read-only inspection of the Pi's provider configuration.

No installed application, key, sudoers rule, provider mode, service, or recovery configuration was changed. No attack command was executed as root. Synthetic signing tests used only the repository's published fixture key or newly generated in-memory keys, never installed identities.

### Severity definitions

- **P0 — critical:** demonstrated, readily exploitable root execution without an intended approval or password in the supported configuration. None identified; absence of a finding is not proof of absence.
- **P1 — high:** a plausible root-authorization bypass under specified conditions, or a substantial gap between the harmless action a person reviews and its privileged effect.
- **P2 — medium:** approval-display ambiguity, request-lifecycle failures, or a broken security-validation gate. These require correction but are not evidence of an unauthenticated root exploit.

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| SYN-SEC-001 | P1 | Already non-setuid alternate providers receive no persistent upgrade protection | Confirmed source path; current Pi checked separately |
| SYN-SEC-002 | P1 | Implicit SETENV permits privileged behavior controlled by hidden environment values | Confirmed rule, adapter and UI path; upstream sudo semantics |
| SYN-SEC-003 | P2 | Different command bytes can render identically; some invisible/bidi characters remain unescaped | Executed against actual Swift renderer |
| SYN-SEC-004 | P2 | Mac rejects valid signed requests above its accidental 4 KiB byte-string limit | Rust-to-Swift signed-fixture reproduction |
| SYN-SEC-005 | P2 | A duplicate valid decision hard-denies unrelated pending requests | Executed relay state-machine reproduction |
| SYN-SEC-006 | P2 | GitHub CI cannot run the Mac security tests with its selected Swift toolchain | Failed CI log for the assessed commit |

## P1 findings

### SYN-SEC-001 — Alternate-provider protection depends on its current setuid bit

**Location:** [`installer.rs:203–234`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/synctl/src/installer.rs#L203), particularly lines 216–218; [`check_installed_coupling:420–429`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/synctl/src/installer.rs#L420).

`apply` enumerates sudo alternatives, but immediately skips a provider whose current mode lacks setuid. That skip occurs before inspecting persistent `dpkg-statoverride` state, adding a protective override, or recording the provider for subsequent coupling checks.

**Failure scenario:** an alternate provider is temporarily `0755`, with no persistent override—for example, an administrator previously used plain `chmod`. Syn accepts that state and eventually installs `NOPASSWD: ALL`. A later package reinstall/upgrade can restore the provider's packaged setuid mode; the managed account can then invoke that provider directly against the passwordless rule without loading Syn's classic-sudo plug-in.

This is a delayed approval bypass, not merely an inaccurate status message. The coupling check examines only recorded overrides, so the skipped provider is also absent from that check. The exploit requires this initial provider state and a subsequent mode-restoring package operation; it is not a claim that all installations are currently bypassable.

**Current Pi evidence:** read-only inspection found `/usr/bin/sudo` resolving to `/usr/bin/sudo.ws`; classic sudo is `4755`; `/usr/lib/cargo/bin/sudo` is `0755` with a persistent `root root 755` override. Therefore the specific missing-override condition was **not present** on the inspected Pi. No mode changes or package-upgrade exploit were performed.

**Recommended correction:** audit and persist protection for every alternate provider regardless of its current mode. Distinguish pre-existing administrator overrides from Syn-created overrides, record the complete provider inventory, and validate it again before adding `NOPASSWD`. Recovery must preserve administrator-owned restrictions and restore only Syn-owned changes.

**Regression tests:** cover `4755` without override, `0755` without override, an existing protective override, an incompatible override, and provider inventory changes. In an isolated installer fixture, simulate a package reinstall restoring packaged permissions; either the override must preserve `0755` or arming must be refused. Do not run that bypass experiment against the live Pi.

### SYN-SEC-002 — Hidden environment values can turn a benign-looking approval into arbitrary root code

**Locations:** [`managed_rule:433–435`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/synctl/src/installer.rs#L433); [`linux.rs:228–252`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/syn-sudo-plugin/src/linux.rs#L228), [`388–421`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/syn-sudo-plugin/src/linux.rs#L388); [`Views.swift:99–104`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Sources/Syn/Views.swift#L99).

The generated rule ends in `NOPASSWD: ALL`, without `NOSETENV`. In sudoers, matching `ALL` implies `SETENV`; command-line environment assignments then bypass the usual environment restrictions. This is documented in the [upstream sudoers manual source, SETENV/NOSETENV section](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.mdoc.in#L2012).

Syn accepts the resulting final environment, signs its digest, and displays only variable names and the digest. Its risk markers inspect the executable basename and argv, not environment-driven code loading; the UI cannot reveal the hidden values or distinguish their safety.

**Attack prerequisite:** a managed Pi process controls a command-line environment assignment, and the person approves the resulting request. For example, it can request `/usr/bin/id -u` with `LD_PRELOAD` pointing to a user-controlled shared object. On a normal dynamically linked Linux execution with the target root identity, the loader can execute that object's initialization code with root privileges before the displayed utility runs.

The UI still shows the trusted `/usr/bin/id`, ordinary arguments, and an `LD_PRELOAD` name whose value is opaque. An environment digest proves the bytes were not changed in transit; it does not let a person judge their effect. This is an **informed-approval failure**, not a signature forgery or an approval-free exploit. It differs from knowingly approving an explicitly root-equivalent package manager because the dangerous code-loading instruction is hidden outside the visible argv.

**Evidence boundary:** confirmed by the generated sudoers rule, upstream semantics, and adapter-to-renderer data flow. No malicious library was loaded and no live root exploit was attempted during this review.

**Recommended correction:** make `NOSETENV` explicit and enforce a conservative final-environment policy inside the trusted adapter. Reject dangerous loader/interpreter configuration unless a separately specified policy explicitly permits it; classify permitted environment changes and their risks without transmitting secrets. Merely adding a red label beside an opaque digest is insufficient, and `NOSETENV` alone is not a sandbox for arbitrary approved programs.

**Regression tests:** use policy fixtures with command-line `LD_PRELOAD`, `LD_LIBRARY_PATH`, execution-affecting interpreter variables, and hostile search paths. Confirm rejection occurs before notification for disallowed environments, a normal minimal environment still works, and allowed secret-bearing values remain absent from requests/logs. Root execution testing belongs in an isolated harness, not routine live validation.

## P2 findings

### SYN-SEC-003 — The approval renderer is ambiguous and misses unsafe Unicode

**Locations:** [`SafeDisplay.swift:9–35`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Sources/Syn/SafeDisplay.swift#L9); [`Views.swift:101–120`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Sources/Syn/Views.swift#L101).

The renderer emits textual escape sequences without escaping literal backslashes. It also uses ordinary strings as invalid-byte and empty-value labels, so distinct inputs can produce identical displayed strings.

Executed probes against the actual source returned equality for all three pairs:

| First input | Different second input | Shared display |
| --- | --- | --- |
| A newline byte (`0A`) | Literal bytes spelling `\u{A}` | `\u{A}` |
| Invalid UTF-8 byte `FF` | Literal ASCII `hex:ff` | `hex:ff` |
| Empty byte string | Literal ASCII `(empty)` | `(empty)` |

The same probe confirmed that U+00AD (soft hyphen), U+034F (combining grapheme joiner), and U+061C (Arabic letter mark) pass through unescaped. Environment names additionally bypass `SafeDisplay` entirely and are joined directly into the UI.

**Impact:** a process controlling argv can create misleading filenames or arguments and obscure the exact bytes a person is approving. Signature binding remains intact; this is a review-interface defect, not proof that these examples alone produce root compromise.

**Recommended correction:** use an unambiguous byte representation, escaping the escape character itself and separating format/type labels from content. Handle the full set of relevant control, bidi, and default-ignorable characters rather than a short hand-maintained list; retain a raw-byte inspection option. Apply safe rendering consistently to environment names and other request-controlled text.

**Regression tests:** add the three collisions above and the omitted Unicode scalars. For the canonical byte-display mode, property-test that different inputs cannot render identically, including invalid UTF-8, literal escape syntax, empty strings, and mixed Unicode.

### SYN-SEC-004 — A 4 KiB decoder limit rejects valid requests well below 64 KiB

**Locations:** [`CBOR.swift:49–50`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Sources/Syn/CBOR.swift#L49), [`142–148`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Sources/Syn/CBOR.swift#L142), [`178–181`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Sources/Syn/CBOR.swift#L178); [`SynProtocol.swift:20–28`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Sources/Syn/SynProtocol.swift#L20); [`syn-protocol:192–205`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/syn-protocol/src/lib.rs#L192).

`Decoder.count` applies the 4,096-item collection limit to byte strings and text as well as arrays/maps. The entire signed request is carried inside a byte string, so the effective Mac limit is roughly 4 KiB for the complete request, not the advertised 64 KiB wire maximum or Rust's 8,192-byte per-argument limit.

**Executed cross-language reproduction:** start from the published request fixture, append a synthetic argument, sign it with the published test key using the real Rust protocol library, verify it in Rust, then feed it to the actual Swift verifier and wire decoder.

| Added argument | Signed request | Wire message | Rust | Swift signature/wire parsing |
| --- | ---: | ---: | --- | --- |
| 3,000 bytes | 3,492 bytes | 3,501 bytes | Accepts and verifies | Accepts |
| 6,000 bytes | 6,492 bytes | 6,501 bytes | Accepts and verifies | Both reject: `CBOR collection is too large` |

**Impact:** valid long invocations cannot be reviewed or approved. The rejection closes the Mac transport; the target can subsequently reach its normal 90-second unavailable/expiry path, which means password fallback for an eligible terminal or failure for `sudo -n`. That downstream fallback consequence was traced in source, not exercised live for this probe; this does not enable execution without approval or password.

**Recommended correction:** separate collection-item limits from string-byte limits. Bound total input and allocations, then apply schema-specific field limits consistently in Rust and Swift. Do not simply remove all decoder bounds.

**Regression tests:** publish signed cross-language vectors immediately below/above 4,096 bytes, near the 8,192-byte argument limit, and near the 64 KiB wire limit. Valid messages must agree across languages; invalid ones must reject without crashes or unbounded allocation.

### SYN-SEC-005 — A stale decision from a second approver connection denies unrelated work

**Locations:** [`syn-agent:312–334`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/syn-agent/src/lib.rs#L312), [`453–458`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/syn-agent/src/lib.rs#L453), [`497–539`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/crates/syn-agent/src/lib.rs#L497).

The relay permits multiple authenticated approver connections and delivers pending requests to each. After one connection decides a request, the relay removes it but does not broadcast completion/cancellation to the others. A later valid decision from a stale window is rejected as having no pending request; the network handler then calls `hard_fail_pending`, draining **all** other pending requests.

**Executed reproduction:** create two independently signed, valid requests for one synthetic target; approve A; confirm no completion event was emitted; submit A's same valid decision again; apply the actual network-handler error transition. The receiver waiting for unrelated request B gets `IntegrityFailure` rather than retaining its own approval window.

This can arise from two running copies of Syn or overlapping reconnects without compromising any key. The user previously observed duplicate app instances, but that UI history is not being presented as a live reproduction of the cross-request failure; the failure itself was reproduced in an isolated relay test.

**Impact:** unrelated commands are hard-denied, stale windows remain actionable, and users may be prompted for decisions that can no longer affect the command. No duplicate root execution was demonstrated: rejecting the replay remains correct.

**Recommended correction:** publish an authenticated/request-bound completion lifecycle to all clients and remove stale UI actions. Reject duplicate/late decisions without reviving the completed invocation or indiscriminately denying unrelated valid requests. Keep strict handling of genuinely forged or mismatched approvals; a bounded record of completed IDs is for replay rejection, never an approval cache. Single-instance app behavior is an additional UX guard, not a substitute for correct relay routing.

**Regression tests:** two authenticated connections reviewing A while B waits; approve/deny A in one client; attempt a stale decision from the other; verify A never runs twice, B remains independently reviewable, and both clients clear A. Repeat across cancellation, expiry, reconnect, and reordered delivery.

### SYN-SEC-006 — The hosted Mac security tests do not execute

**Locations:** [`.github/workflows/ci.yml:29–33`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/.github/workflows/ci.yml#L29); [`macos/Package.swift:1`](https://github.com/ferrerluis/syn-approvals/blob/888e63665b0ad63b788e4d6af431952e091876ae/macos/Package.swift#L1).

The workflow selects `macos-15` but does not select a compatible Xcode/Swift toolchain. For the assessed commit, the [CI run failed before compiling the tests](https://github.com/ferrerluis/syn-approvals/actions/runs/33935241522): the package requires Swift tools 6.2.0, while the runner used 6.1.0.

**Impact:** automated verification of Mac signature parsing, authentication cancellation, TLS pinning, and notification privacy is unavailable on main. This is an assurance/release-gate finding, not a runtime exploit. The 25 tests passed locally with the available newer toolchain; that does not make the hosted CI run green.

**Recommended correction:** explicitly select a runner/toolchain that supports the package, print the selected versions, run Swift with warnings treated as errors, and require the resulting checks before changes reach main. Do not lower the package version or suppress failures without verifying language/runtime compatibility.

**Regression criterion:** a fresh CI run on the resulting commit must compile and execute the full Mac test suite and pass. Successful dependency-bot jobs are not substitutes for the actual `CI` workflow.

## Dependency and additional review observations

The public package names and exact versions for all **155 registry entries** in `Cargo.lock` were queried against the OSV batch API. One match was returned: `rustls-pemfile 2.2.0`, [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html). RustSec classifies it as **informational: unmaintained**, not a demonstrated exploitable vulnerability, so it is not counted as an additional P0–P2 vulnerability here.

Migrate to the maintained PEM support in `rustls-pki-types` and test certificate/private-key parsing behavior. The advisory lookup is point-in-time and does not audit dependency internals, bundled C cryptography, system packages, GitHub Actions code, or undisclosed issues.

Additional questions for the independent review, **not counted as confirmed exploits**:

- **Crash/concurrency safety:** recovery unlinks the passwordless rule before restoring `sudo.conf`, but does not explicitly sync the sudoers directory at that transition. Install/recovery also lack a shared transaction lock. Verify durability and timer/install interleavings on the supported filesystem with fault-injection fixtures; source-level ordering alone is not a power-loss proof.
- **Executable content identity:** Syn binds executable path and argv, not immutable file contents, scripts, libraries, or every later file the approved program reads. Document the treatment of writable executables and sudo's execution-by-file-descriptor behavior; do not imply that a signature on a path attests to all code executed through it.
- **Connection startup ordering:** the relay snapshots pending requests before subscribing to broadcasts (`syn-agent:415–431`). A request arriving in that interval can miss delivery on that connection. Add a deterministic concurrency test and subscribe/snapshot reconciliation.
- **Supply-chain release gate:** immutable action references, enforced lockfiles, package signing, notarization, comprehensive fuzzing and an independent review remain separate work. This assessment neither performs nor waives them.

## Verification record

| Check | Result in this assessment |
| --- | --- |
| Remote main | Verified at the assessed full SHA before report creation; repository private |
| Rust workspace tests, Mac | 37 pass outside the sandbox |
| Rust workspace tests, Ubuntu ARM64 Pi | 47 pass, including 10 Linux plug-in/cancellation tests |
| Swift tests, Mac | 25 pass with warnings treated as errors |
| Rust formatting | Pass |
| Rust clippy, workspace/all targets on Mac | Pass with warnings denied |
| ARM64 Linux plug-in clippy/type-check | Pass with warnings denied |
| Privacy-checker unit tests | 4 pass; no new live log-capture experiment |
| Long signed Rust-to-Swift fixture | Confirms SYN-SEC-004 |
| Actual Swift byte renderer | Confirms SYN-SEC-003 collisions and omitted scalars |
| Duplicate-decision relay test | Confirms SYN-SEC-005 cross-request hard failure |
| Locked-dependency advisory query | 155 entries checked; one informational unmaintained advisory |
| Hosted CI for assessed SHA | Fails Mac job: Swift 6.1 runner versus 6.2 package |

The first sandboxed Mac Rust run failed the inert-file setuid metadata test; the same unchanged tests passed when run outside the sandbox. A full Mac-to-Linux workspace cross-check was blocked by a missing Linux C cross-compiler for the TLS dependency; native unprivileged Pi tests and the narrower ARM64 plug-in clippy check supplied Linux coverage instead.

Pi tests used a source archive of the exact assessed commit in an isolated temporary directory, not changes to the deployed service. Local probes also used a temporary archive and printed only synthetic fixture metadata. Temporary build outputs are not deployed artifacts.

### Reproducing the focused probes safely

For SYN-SEC-003, compile `CBOR.swift`, `SynProtocol.swift`, and `SafeDisplay.swift` with a small test entry point, or add a temporary `@testable import Syn` test. Compare the three input pairs listed in the finding, then assert whether each listed unsafe scalar survives unchanged.

For SYN-SEC-004, load `tests/fixtures/protocol-v1.json`, decode and verify `signed_request_hex` with its published target key, append an argument containing 3,000 or 6,000 ASCII `x` bytes, and sign again using the fixture's documented `[1; 32]` test private key. Verify in Rust, wrap with `WireMessageV1::new(REQUEST, ...)`, and feed both signed and wrapped forms into Swift. Do not use installed target keys or open a network connection.

For SYN-SEC-005, add a temporary test inside the relay module so it can exercise its private routing functions. Generate two requests with the same fresh target key and distinct IDs/nonces, attach separate response channels, route a valid signed decision for A, then route it again and run the handler's `hard_fail_pending` error branch. Assert that B receives `IntegrityFailure` and that A's first completion emitted no broadcast event.

No privileged reinstall, power-loss simulation, live hostile environment, or further biometric/password exercise was performed. Those are explicitly untested here, not silently marked as passing.

## Recommended order

1. Fix SYN-SEC-001 and SYN-SEC-002, preserving the remove-passwordless-first/add-passwordless-last invariant and environment privacy.
2. Fix the ambiguous renderer and cross-language size mismatch, adding shared negative and boundary fixtures.
3. Fix request completion/routing and restore a working required Mac CI check.
4. Resolve the maintenance advisory and complete crash/concurrency, executable-identity and independent-review work before publication.

The existing signature, nonce/request binding, local verification, cancellation, and separate approval/denial keys are meaningful protections. These findings do not justify removing them, adding passwordless exceptions, trusting the relay's verdict, or treating an approved package manager as contained.
