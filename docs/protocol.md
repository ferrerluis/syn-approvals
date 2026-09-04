# Syn protocol v1

Status: private-alpha wire contract. Numeric map keys are part of the protocol.

## Encoding

- Deterministic CBOR with definite lengths and integer map keys.
- COSE Sign1 tag 18 using ES256 (`alg = -7`).
- Empty external AAD.
- P-256 public keys use uncompressed ANSI X9.63/SEC1 representation.
- Key IDs are SHA-256 of that 65-byte public-key representation.
- ECDSA signatures in COSE are the fixed 64-byte `r || s` form.
- Receivers verify signatures over the received protected header and payload bytes before decoding trusted fields.
- Decoded payloads are re-encoded and compared to reject non-canonical encodings.

## Approval request

`ApprovalRequestV1` is a CBOR map:

| Key | Field | Type |
| --- | --- | --- |
| 0 | protocol version | unsigned, must be 1 |
| 1 | request ID | 16-byte bstr |
| 2 | nonce | 32-byte bstr |
| 3 | target ID | text |
| 4 | target key ID | 32-byte bstr |
| 5 | adapter kind | text, initially `org.syn-approvals.sudo` |
| 6 | adapter schema | unsigned, initially 1 |
| 7 | issued at | signed Unix milliseconds, display only |
| 8 | TTL | exactly 30000 milliseconds in the alpha |
| 9 | sudo intent | `SudoIntentV1` map |

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

Byte strings are intentional. Unix argv and paths are not required to be valid UTF-8.

## Decision

`DecisionV1` is a CBOR map:

| Key | Field | Type |
| --- | --- | --- |
| 0 | protocol version | unsigned, must be 1 |
| 1 | request ID | 16-byte bstr |
| 2 | request payload hash | 32-byte bstr |
| 3 | target ID | text |
| 4 | decision | 1 = approve once, 2 = deny |
| 5 | decided at | signed Unix milliseconds, diagnostic only |
| 6 | approver key ID | 32-byte bstr |
| 7 | authentication class | 1 = system user presence, 2 = device authenticated |

An approval must use authentication class 1 and the Secure Enclave approval key. A denial must use class 2 and the paired device-decision key. Other combinations fail closed.

## Transport messages

Every WebSocket binary frame contains a canonical `WireMessageV1` map:

| Key | Field |
| --- | --- |
| 0 | protocol version |
| 1 | message kind |
| 2 | body bstr |

Kinds are hello, request, cancel, decision, result, ping, pong, and error. Frames larger than 64 KiB are rejected.

The root plug-in uses the same message envelope over a Unix stream prefixed by a four-byte network-order length. Only request, cancel, decision, and unavailable/error messages are valid locally.

## State machine

```text
created -> target-signed -> relayed -> pending
pending -> approved -> verified -> executed
pending -> denied -> verified -> rejected
pending -> expired -> interactive PAM fallback | non-interactive rejection
pending -> cancelled -> rejected
any integrity/protocol/policy error -> hard rejection
```

The target plug-in owns the monotonic deadline. Neither the agent nor the Mac can extend it with wall-clock values.

The plug-in uses that same absolute deadline for local-socket connection, writes, frame headers, and frame bodies. Partial progress does not restart the wait. A complete decision is signature- and binding-checked before expiry handling: an invalid decision or signed denial never opens password fallback. A valid but late approval cannot authorize execution; only the existing expiry fallback may proceed. Truncated frames are malformed, while an empty disconnect is ordinary unavailability.

## Compatibility

- A new optional field requires a new schema version unless every v1 decoder can safely ignore it.
- Unknown adapter kinds or schemas cannot be rendered or approved.
- Protocol negotiation may select only a version implemented by both endpoints.
- There is no dynamic schema or renderer download.
