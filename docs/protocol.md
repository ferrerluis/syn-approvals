# Syn protocol v2

Status: implemented candidate wire contract with shared Rust/Swift golden vectors. Numeric map keys are part of the protocol; live Mac-led E2E acceptance is still pending.

Version 2 requires a 300-second TTL and the exact compiled release ID and Git commit in the hello, signed request, and signed decision. Version 1 and mixed-release messages fail closed even when their signatures are otherwise valid.

## Encoding

- Deterministic CBOR with definite lengths and integer map keys.
- COSE Sign1 tag 18 using ES256 (`alg = -7`).
- Empty external AAD.
- P-256 public keys use uncompressed ANSI X9.63/SEC1 representation.
- Key IDs are SHA-256 of that 65-byte public-key representation.
- ECDSA signatures in COSE are the fixed 64-byte `r || s` form.
- Receivers verify signatures over the received protected header and payload bytes before decoding trusted fields.
- Decoded payloads are re-encoded and compared to reject non-canonical encodings.

## Hello and release binding

Each direct mTLS connection starts with a canonical hello body:

| Key | Field | Type |
| --- | --- | --- |
| 0 | minimum protocol version | unsigned, exactly 2 |
| 1 | maximum protocol version | unsigned, exactly 2 |
| 2 | target ID | text, must match the pinned target |
| 3 | release ID | 14-digit compact UTC timestamp |
| 4 | release commit | 40 lowercase hexadecimal characters |

Both peers require the target ID, protocol range, release ID, and release commit to match their local pinned or compiled values. A mismatch is **Update required**; there is no downgrade, dynamic schema download, or signature-only compatibility exception.

The all-zero development release ID and commit are reserved for debug builds. Release builds must receive valid identity metadata at compile time.

## Approval request

The Rust type remains named `ApprovalRequestV1`, but its wire `protocol_version` is 2. The CBOR map is:

| Key | Field | Type |
| --- | --- | --- |
| 0 | protocol version | unsigned, must be 2 |
| 1 | request ID | 16-byte bstr |
| 2 | nonce | 32-byte bstr |
| 3 | target ID | text |
| 4 | target key ID | 32-byte bstr |
| 5 | adapter kind | text, initially `org.syn-approvals.sudo` |
| 6 | adapter schema | unsigned, initially 1 |
| 7 | issued at | signed Unix milliseconds, display only |
| 8 | TTL | exactly 300000 milliseconds |
| 9 | sudo intent | `SudoIntentV1` map |
| 10 | release ID | exact compiled release ID |
| 11 | release commit | exact compiled Git commit |

`SudoIntentV1` binds:

- invoking UID/GID/name;
- PID/parent PID;
- TTY and non-interactive status;
- working directory bytes;
- run-as UID/GID/name/group;
- sudo mode;
- resolved executable bytes;
- exact argv byte strings;
- sorted security-relevant command-info entries;
- SHA-256 of the complete framed execution environment;
- sorted environment names only;
- policy version and sudo provider;
- typed risk markers.

Byte strings are intentional because Unix argv and paths need not be valid UTF-8.

The sudo map has twenty required keys (0–20 except 5). Key 5 is the optional TTY string and is omitted, not encoded as null, when no terminal exists. Unknown fields and missing required fields fail closed; golden fixtures cover an absent TTY for both interactive-flag values.

## Decision

`DecisionV1` is a CBOR map:

| Key | Field | Type |
| --- | --- | --- |
| 0 | protocol version | unsigned, must be 2 |
| 1 | request ID | 16-byte bstr |
| 2 | request payload hash | 32-byte bstr |
| 3 | target ID | text |
| 4 | decision | 1 = approve once, 2 = deny |
| 5 | decided at | signed Unix milliseconds, diagnostic only |
| 6 | approver key ID | 32-byte bstr |
| 7 | authentication class | 1 = system user presence, 2 = device authenticated |
| 8 | release ID | approver's exact compiled release ID |
| 9 | release commit | approver's exact compiled Git commit |

An approval must use authentication class 1 and the Secure Enclave approval key. A denial must use class 2 and the paired device-decision key. The decision must match the request ID, payload hash, target ID, release ID, and release commit; other combinations fail closed.

## Transport messages

Every WebSocket binary frame contains a canonical `WireMessageV1` map whose wire protocol version is 2:

| Key | Field |
| --- | --- |
| 0 | protocol version |
| 1 | message kind |
| 2 | body bstr |

Kinds are hello, request, cancel, decision, result, ping, pong, error, and unavailable. Frames larger than 64 KiB are rejected.

The root plug-in uses the same envelope over a Unix stream prefixed by a four-byte network-order length. Requests, decisions, unavailable/errors, signed display-only results, and update health traffic are valid locally. The unprivileged relay can verify and relay messages but has no command-execution API and never holds the target authorization private key.

## Observational permission receipts

The existing `result` kind carries a target-signed COSE Sign1 envelope with a
canonical eleven-key CBOR map: target ID (0), 16-byte request ID (1), 32-byte
request payload hash (2), release ID (3), release commit (4), request time in
Unix milliseconds (5), completion time (6), outcome (7), invoking UID (8),
run-as UID (9), and domain `org.syn-approvals.permission-result.v1` (10).
Outcomes are 1 approved, 2 denied, 3 timed out, 4 canceled, 5 failed, and
6 unconfirmed. The privileged sender signs its own observation after independently
validating the decision, expiry, cancellation, or failure. This is a permission
outcome, not a command execution receipt or an authorization.

The sender reports through a separate local connection with a 100-ms delivery
budget, including after its original connection closes at timeout. Reporting
failures are visible and never change approval, denial, deadlines, or PAM.
The relay verifies the target signature and exact release before relaying the
receipt; it never has the signing key. Its journal distinguishes `observation=relay`
from `observation=target`. Relay-only observations cannot confirm Mac history.

The Mac verifies the paired target signature and all request bindings before
marking an entry confirmed. A cancellation notice only removes pending UI and
leaves the outcome Unconfirmed until a signed result arrives. Neither receipts
nor history can create requests, sign decisions, enter PAM, or execute commands.
Reconnect does not fetch missed receipts. Identical results are harmless;
conflicting confirmed results are rejected. Old unsigned relay confirmations
are downgraded to Unconfirmed when loading history.

## State machine

```text
created -> target-signed -> relayed -> pending
pending -> approved -> verified -> original invocation executes
pending -> denied -> verified -> hard rejection
pending -> Enter on an interactive terminal -> cancel pending request -> PAM password
pending -> unavailable/expired -> interactive PAM password | non-interactive rejection
pending -> cancelled -> rejection
any integrity/protocol/policy error -> hard rejection
```

The target plug-in owns one monotonic deadline covering connection, writes, frame headers, frame bodies, and decision verification. Partial progress cannot restart or extend it.

Enter is accepted only as an empty line from the controlling interactive terminal while the request remains pending. The plug-in cancels that request before PAM begins, and a late approval cannot authorize the current or a later invocation. Redirected input, explicit denial, invalid decisions, local policy failures, and non-interactive use cannot select password fallback.

A complete decision is signature- and binding-checked before expiry handling. Truncated frames are malformed; an empty disconnect is ordinary unavailability.

## Compatibility

Update health checks use wire kinds 10 (`health_check`) and 11 (`health_response`), only between identical releases. Their canonical CBOR payload has eight keys: 0 text domain `org.syn-approvals.update-health.v1`, 1 target ID, 2 fresh 32-byte nonce, 3 issue time in milliseconds, 4 fixed 10,000-ms TTL, 5 release ID, 6 release commit and 7 approval public-key SHA-256. The root helper signs the challenge with the target key; the Mac verifies it and signs the identical payload with its device/denial key. The relay and root helper verify the response against the live challenge and deadline.

This text-domain payload cannot decode as a request or decision and never enters the sudo decision queue. It creates no permission-history entry or notification and grants no command authority. It proves the paired device can validate and return signed traffic, not that a user has authenticated or that the approval private key can sign. Routine updates retain protected original pairing evidence and record a separate private, release-bound health proof; they never fabricate or refresh user-presence approval evidence. First-time setup keeps its authenticated preflight checks.

- A schema change requires a new protocol version unless every supported decoder can safely ignore it.
- Unknown adapter kinds or schemas cannot be rendered or approved.
- The current hello requires exactly version 2; it does not negotiate with version 1.
- The Mac and all remote binaries must share the exact release ID and commit before approvals resume.
- There is no dynamic schema or renderer download.

## Additional devices

Each root-owned additional approver record binds one client TLS leaf certificate to that device's separate approval and denial public keys. The relay checks the signed decision against the keys bound to the authenticated TLS peer. The sudo plug-in independently checks the current trusted registry and all existing request/action/authentication-class/deadline/release rules. Legacy primary Mac pairing remains supported. Duplicate device IDs, signing keys, or client certificates are rejected.

The first valid decision resolves one invocation. The relay broadcasts its existing `CANCEL` message to remove the request from other apps. Bounded terminal request hashes distinguish a legitimate competing response from malformed input; they never authorize another invocation.

Envelope kinds 10 and 11 are update health checks and responses. Syn has no push registration message. Codex attention prompts are outside this protocol and cannot authorize an invocation.
