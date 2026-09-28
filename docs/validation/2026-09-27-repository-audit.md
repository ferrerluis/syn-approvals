# Repository audit and cleanup — September 27, 2026

## Scope and result

The audit branch starts at current `origin/main` (`7182e5e`) plus the two
existing ghost-branding commits (`ba1901f`, `c8360e5`). Published history,
release tags, open pull requests, installed applications, pairing identities,
sudo policy and services were not rewritten or changed. Local main was
fast-forwarded from `19fccb2` to `7182e5e`; all six existing checkouts were
verified clean after saving the superseded work below.

**No credentials were detected in the scanned history or working source.**
This is a point-in-time scanner result, not a guarantee that there are no
unknown credentials or exploitable bugs. Older revisions still contain
previously fixed vulnerabilities. Changing their commit messages, deleting
branches, or squashing new work cannot make those revisions safe to install.

## Reviewable commit sequence

1. `6ffdd76`: recover the unpublished public-repository and landing-site
   roadmap from the old onboarding checkout, without reverting newer plans.
2. `94008ff`: remove command-display collisions, with regression tests.
3. `b3fd44a`: require and lock patched Rustls 0.23.45.
4. `682fa2d`: add checksum-pinned full-history/staged-index secret scanning,
   scanner integration tests, generated-file exclusions and current contributor
   validation commands.
5. This audit record: evidence, local recovery inventory and remaining limits.

These commits extend the existing history; there is no force push, main merge,
visibility change, release replacement or deployment in this cleanup.

## Secret and dependency audit

- Refreshed remote branches/tags and inventoried open PRs, stashes, reflogs and
  every registered worktree. The starting full revision set contained 100
  commits including reflogs; empty/merge commits mean this differs from a
  scanner's count of commits with patches.
- Used official Gitleaks 8.30.1, verified against its published SHA-256 before
  execution. Scanned all refs/reflogs with `--full-history -m`, so merge-parent
  diffs were included. No inline `gitleaks:allow` bypass was honored and no
  test/documentation exclusion was added.
- Scanned tracked and non-ignored untracked files from the primary, old review,
  onboarding and branding checkouts. The second onboarding tree was verified
  byte-identical outside generated/build directories. These snapshots were
  scanned before moving any work into recovery stashes.
- Extracted and scanned every local Git blob and commit object individually,
  including unreachable objects: approximately 54 MB, no findings. An earlier
  concatenated-object-stream pass reported a possible token; the candidate
  was verified to be a real Git blob object ID. The upstream rule accepts
  40-character hexadecimal IDs near its keyword. Object-separated scanning
  avoids this artificial cross-object context; no suppression was added.
- Re-scanned the new commits, staged changes and recovery stashes after cleanup:
  no findings. Historical sensitive-key filenames and tracked ignored files
  were also checked; no matching credential files were found.
- Queried the public names/versions of all 155 registry packages in `Cargo.lock`
  against OSV. Rustls 0.23.43 matched
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
  The patched version is 0.23.45; only that locked package and its minimum
  manifest requirement changed. The repeat query no longer matched it.
- The remaining match is `rustls-pemfile` 2.2.0:
  [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html),
  an informational **unmaintained** advisory, not a reported exploit. Its
  migration remains follow-up work, not silently classified as resolved.

No account credentials were retrieved, tested against a service or placed in
reports. Build caches, installed identities, Keychain, ignored local test-run
data, GitHub-hosted release binaries and the internals of every dependency
were not comprehensively audited. The new workflow is a reviewable local
change; a hosted successful run/required branch-protection check is not claimed.

## Security correction and boundaries

`SafeDisplay` previously rendered raw invalid UTF-8 as `hex:...` and empty
bytes as `(empty)`, colliding with literal text. Its Unicode escapes also
collided with literal backslash sequences, and some invisible characters
passed through unchanged (historical SYN-SEC-003).

Valid UTF-8 is now quoted, quotes/backslashes are escaped, and every scalar
outside printable ASCII is shown explicitly. Invalid UTF-8 remains unquoted
hex. Tests distinguish empty/text/hex/escape/normalization/homoglyph cases,
exercise invisible characters, and check all 65,793 zero-, one- and two-byte
inputs for distinct output. Non-ASCII names in notification metadata also
use explicit escapes. This is display-only, never a shell reconstruction;
typed request fields, signatures and authorization decisions are unchanged.

The TLS advisory concerns handshake encryption-level boundaries. It does not
by itself demonstrate an attacker can forge Syn approvals; upgrading is still
required. Mac and ARM64 builds/tests validated the patched dependency.

The following existing concerns remain explicit rather than being erased from
the storyline:

- SYN-SEC-004: the Mac CBOR decoder still applies its 4,096-item bound to byte
  strings, rejecting some otherwise valid larger signed requests. No decoder
  bounds were loosened in this cleanup.
- SYN-SEC-005: `route_decision` rejects an already-completed request and its
  caller still invokes `hard_fail_pending`; stale decisions can deny unrelated
  work. This remains an availability issue, not permission to accept replays.
- The administrator/provider-override concurrency limitation and future
  relocated-provider caveat in the
  [adversarial follow-up](../security-review-followup-2026-09-04.md) were not
  resolved or re-proven through privileged fault injection here.
- Fresh independent review of the sudo/PAM, installer/recovery, parser, pairing,
  transport and macOS key-access boundaries remains the public security gate.
  Historical internal-review statements are not blanket approval of all code.

## Verification

Production-source validation used exact commit `b3fd44a`. Subsequent changes
are scanning/ignore/contributor documentation and this record; runtime source
and dependency inputs are unchanged.

| Check | Result |
| --- | --- |
| Swift, warnings as errors, serial execution | 149 tests pass |
| Display injectivity regression | All 65,793 zero-/one-/two-byte inputs distinct |
| Mac Rust formatting and workspace/all-targets clippy | Pass, warnings denied |
| Mac Rust workspace tests | 100 pass; one existing ignored live-provider check |
| Native Ubuntu ARM64 formatting and workspace/all-targets clippy | Pass, warnings denied |
| ARM64 plug-in target clippy/type-check | Pass, warnings denied |
| Native Ubuntu ARM64 workspace tests | 116 pass; two existing ignored privileged/live checks |
| Rust-generated protocol-v2 vectors, Mac and ARM64 | Equal to committed fixtures; Swift fixture also equal |
| Privacy checker | Four tests pass |
| Release/helper/E2E tooling | 32 tests pass |
| Real secret-scanner integration tests | Four pass: clean, staged token, deleted historical token, shallow clone rejection |
| New workflow YAML and shell syntax | Parse/check pass |
| Git whitespace checks and final source/history scans | Pass |

ARM64 tests used an isolated temporary directory and ordinary user privileges.
They did not install Syn, activate sudo coupling or exercise a new live
approval/PAM/recovery rollout. Existing ignored privileged tests were not
counted as passes. Hosted CI/package publication was not run for this branch.

## Local-only preservation and cleanup

The old `b3b3` and `d612` worktrees contained identical obsolete code and notes;
newer committed implementations were retained. Unique old validation drafts
and generated artwork were preserved locally rather than mixed into production
source. The older `917b` roadmap/UX drafts were also superseded by current main.

Recovery stashes are shared by this repository, not part of the audit branch:

| Original checkout/content | Stable recovery stash ID |
| --- | --- |
| Primary generated artwork | `48fad5e4337a88fd9d6666147d6d19b4ec9749bb` |
| `b3b3` onboarding working copy and notes | `afbb6f015a411cfe40879ad04e660e30531d7a9d` |
| Duplicate `d612` working copy and notes | `426803da5444a7c0c1ce842846f9ce76fef66eda` |
| `917b` superseded review notes and artwork | `367f72ca3f92f4b3d7227f14b9590e7305bdd0b9` |

The pre-existing `d6f297d49a440aa71d796436ec98e67d6fd931e1` stash was not
dropped. Restore a snapshot only into an appropriate isolated checkout of its
original base using `git stash apply <stable-ID>`; inspect conflicts and do not
apply obsolete source over this audit branch. Untracked content is retained in
the stash's third parent. None of these local recovery refs should be pushed
as public development branches.

A verified full-history/reflog recovery bundle and the original worktree
inventory are retained locally under `.git/audit-backup.0SEYVL/`. Forty-four
stale registrations were pruned only after verifying their checkout directories
were already absent and every recorded HEAD was covered by the backup revision
set. No existing checkout directory or branch was deleted. All six remaining
checkouts were verified with empty `git status --porcelain` output.

Changing published history would also change release identities and cannot
erase existing clones, forks, downloaded releases or PR references. Any future
history rewrite or publication must be a separate explicit operation; this
cleanup makes no promise that every historical revision is safe to run.
