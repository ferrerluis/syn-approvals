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

## Permission history

Selecting a machine in the Mac sidebar shows the requests observed by this Mac,
newest first. `~/Library/Application Support/Syn/request-history.json` is written
atomically with mode 0600 and retains 1,000 completed requests per target plus
live requests. It contains only target/request identifiers, hashes, release
identifiers, numeric UIDs, timestamps, and fixed status categories. It never
contains executable text, arguments, usernames, directory names, environments,
nonce values, signatures, or signed payloads. History survives disconnection and
app restart. Unfinished records become Unconfirmed after restart.

The Pi emits `event=request_history` start/result records to the existing
persistent system journal. Read them with `journalctl -u syn-agent --no-pager`
and filter for `request_history`; retention follows the host's journal policy.
Request IDs correlate the Mac and Pi records. Approved and Denied mean the
relay returned a validated permission decision; they do not report command
completion or its exit code. The Mac displays delivery attempts separately
until a receipt arrives. A locally observed timeout is labeled accordingly.

History cannot authorize requests. A Mac storage error is shown in the history
view and does not change approval behavior; corrupt history is preserved
instead of being overwritten. Journal persistence errors are handled by the
host's existing journald monitoring, not by changing an authorization result.
