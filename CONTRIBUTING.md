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
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p syn-sudo-plugin --target aarch64-unknown-linux-gnu
swift test --package-path macos
cmp tests/fixtures/protocol-v1.json macos/Tests/SynTests/Fixtures/protocol-v1.json
```

Linux plug-in, PAM, package, and installer changes also require a recoverable Ubuntu 26.04 ARM64 test record covering allow, deny, timeout, non-interactive expiry, replay, cancellation, missing plug-in, direct alternate-provider invocation, interrupted install, and recovery.

## Review

At least two reviewers should approve changes to privileged or cryptographic code. One should review the threat model and failure behavior rather than only code style.
