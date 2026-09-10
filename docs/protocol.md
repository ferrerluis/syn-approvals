# Syn protocol v2

Status: implemented candidate wire contract with shared Rust/Swift golden vectors. Numeric map keys are part of the protocol; live Mac-led E2E acceptance is still pending.

Version 2 requires a 90-second TTL and the exact compiled release ID and Git commit in the hello, signed request, and signed decision. Version 1 and mixed-release messages fail closed even when their signatures are otherwise valid.

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
| 8 | TTL | exactly 90000 milliseconds |
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

The root plug-in uses the same envelope over a Unix stream prefixed by a four-byte network-order length. Only request, cancel, decision, and unavailable/error messages are valid locally. The unprivileged relay can verify and relay messages but has no command-execution API and never holds the target authorization private key.

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

- A schema change requires a new protocol version unless every supported decoder can safely ignore it.
- Unknown adapter kinds or schemas cannot be rendered or approved.
- The current hello requires exactly version 2; it does not negotiate with version 1.
- The Mac and all remote binaries must share the exact release ID and commit before approvals resume.
- There is no dynamic schema or renderer download.
