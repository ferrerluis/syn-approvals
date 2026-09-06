# Syn engineering rules

These rules apply to the whole repository.

- Treat every change to the sudo ABI, PAM, pairing, cryptography, installer, recovery, transport authentication, or Secure Enclave code as security-sensitive.
- Syn gates an invocation already accepted by sudo policy. Never add a network command string, shell reconstruction, generic executor, approval URL, bearer-token approval endpoint, or arbitrary adapter renderer.
- Preserve executable, argv, working directory, identities, and environment digest as typed fields. Raw command bytes must never be joined into a shell command.
- The unprivileged agent may relay only target-signed requests and approver-signed decisions. It must never possess the target private authorization key or gain a command-execution API.
- Approval is one request, one nonce, one target, and one live invocation. Do not add caches, grace periods, batch approval, patterns, or standing grants without a new threat model and explicit product decision.
- Integrity failures, replays, unsupported schemas, malformed messages, local policy blocks, and explicit denials fail closed. Ordinary unavailability/expiry, or an explicit Enter-to-password selection while an interactive request is still pending, may enter PAM. Cancel the pending request before that selection takes effect; completed hard denials cannot be reopened.
- Keep passwords, environment values, private keys, pairing secrets, full argv, and TLS material out of Syn logs and test snapshots.
- Any installer change must preserve the ordering invariant: remove `NOPASSWD` first during recovery and add it last during installation.
- Never weaken or remove the alternate-provider setuid audit to make installation easier.
- Add or update cross-language golden vectors for protocol changes. Run Rust formatting, clippy with warnings denied, Rust tests, Swift tests, and ARM64 Linux type-checks.
- Do not call a privileged milestone complete until it has passed on the stated Ubuntu ARM64 target with independent recovery access.
