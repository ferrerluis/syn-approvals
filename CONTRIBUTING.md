# Contributing

Syn is private until an independent security review is complete. During the private alpha, changes should be small, reviewable, and tied to one documented threat or acceptance criterion.

## Before opening a change

1. Read `docs/threat-model.md`, `docs/protocol.md`, and the relevant ADR.
2. State which trust boundary changes, if any.
3. Add a regression or adversarial test before changing privileged behavior.
4. Update `docs/implementation-status.md`; compilation is not deployment proof.

## Required checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo clippy -p syn-sudo-plugin --target aarch64-unknown-linux-gnu --locked -- -D warnings
swift test --package-path macos -Xswiftc -warnings-as-errors --no-parallel
cargo run --quiet --locked -p syn-protocol --example golden_vectors > /tmp/syn-protocol-v2.json
cmp tests/fixtures/protocol-v2.json /tmp/syn-protocol-v2.json
cmp tests/fixtures/protocol-v2.json macos/Tests/SynTests/Fixtures/protocol-v2.json
sh scripts/check-secrets.sh
```

The secret check requires Gitleaks 8.30.1 on `PATH` (or an explicit
`GITLEAKS_BINARY` path). The separate `Secret scan` workflow verifies the
downloaded scanner checksum, scans full fetched history, and does not upload
artifacts. Before committing, stage only reviewed files and run the check;
it also scans the proposed index. Tests and documentation are not excluded.
Deleting a credential in a later commit does not remove it from history:
revoke it first, then coordinate history cleanup. Never post an unredacted
scanner report. A clean scan is not a guarantee against undiscovered secrets
or vulnerabilities; retain the independent security-review gate.

Linux plug-in, PAM, package, and installer changes also require a recoverable Ubuntu 26.04 ARM64 test record covering allow, deny, timeout, non-interactive expiry, replay, cancellation, missing plug-in, direct alternate-provider invocation, interrupted install, and recovery.

## Review

At least two reviewers should approve changes to privileged or cryptographic code. One should review the threat model and failure behavior rather than only code style.
