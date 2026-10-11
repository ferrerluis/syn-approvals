# Permission history and silent update verification

## Scope

Each Mac-connected machine has selectable, persistent permission history, newest first, with request ID, request and completion times, and outcome. The sender records its own observations in the persistent `syn-agent` journal. History begins with newly observed requests; reconnecting does not fetch missed activity. Each machine keeps its own observations.

The Mac retains up to 1,000 completed records per device in a private, atomically replaced Application Support file. Only identifiers, timestamps, numeric user IDs, hashes and fixed categories are saved. Command text, arguments, environment values, credentials and signed permission payloads are excluded.

Display-only result receipts bind to the target, request ID, request hash and exact release. Confirmed outcomes are Approved, Denied or Timed out; cancellation, failures and uncertain delivery are represented explicitly. A failed send is never a confirmed decision. Receipts and history cannot authorize anything, and existing one-use signatures, authentication, deadlines and password fallback remain in force.

## Added update behavior

An already-paired machine update performs silent, signed health checks before activating sudo and before disarming automatic recovery. These use a separate, short-lived challenge with no command or approval action. The Mac signs with its existing device/denial key, never its user-presence approval key. Both the relay and root helper validate the identity, nonce, exact release, paired approval public key and deadline. The Mac allows up to one second of target clock lead; the target and relay still enforce the original ten-second deadline.

Retain protected pairing evidence and save a separate fresh health proof; do not relabel background verification as a user approval. Derive eligibility from the remote machine's protected existing pairing, never a caller-controlled flag. First-time setup retains its authenticated checks. Keep independent recovery access, remove NOPASSWD first on recovery, add it last on activation, and preserve the alternate-provider setuid audit.

## Verification and release

Build matching Mac and ARM64 Linux candidates in the isolated worktree while retaining the previous installed release. Run Rust formatting, clippy with warnings denied, Rust tests, Swift tests, shared protocol vectors, ARM64 checks and privacy checks. Cover persistence, device separation, duplicate delivery, expiration, cancellation, uncertain delivery and secret-free history. Health checks must reject wrong identity, release, nonce, key, signature and deadline; neither health traffic nor a receipt may authorize sudo.

Verify the actual update finishes without fingerprint requests and that failed verification preserves recovery. Run the following real cases sequentially over SSH with a TTY using `/usr/bin/sudo -n /usr/bin/true`:

| Order | Action | Required result |
|---|---|---|
| 1 | Computer Use clicks Deny | SSH nonzero; Mac and Pi show Denied |
| 2 | Leave untouched for the 90-second deadline | SSH nonzero; Mac and Pi show Timed out |
| 3 | Computer Use clicks Approve, then user authenticates | SSH zero; Mac and Pi show Approved |

Match the two histories by request ID, then restart the Mac app and verify all three records remain visible. Only the final approval case should require user presence. Logging failures must remain visible without affecting permission behavior.
