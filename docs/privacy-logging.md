# Privacy and logging

Syn's own logs contain request ID, target ID, adapter/schema, UID/run-as UID, command digest, result category, authentication path, latency, key fingerprint, and error category.

Syn does not log:

- full argv or executable text;
- environment values;
- passwords or PAM replies;
- private keys, certificates, pairing secrets, or signatures;
- full signed request or decision payloads.

The Mac notification hides command content by default. The detail window necessarily receives executable and argv over the pair-encrypted channel so the user can review them; suspected secret-like arguments are masked initially.

The host's existing sudo/auth configuration may record full commands independently of Syn. Syn does not weaken or silently rewrite that policy.

There is no telemetry in the private alpha.
