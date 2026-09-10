# Threat model

Status: design authority for the private alpha.

## Security objective

For one configured Linux UID, an invocation already accepted by sudoers must not execute unless either:

1. the paired Mac produces a fresh, valid, request-bound approval signature; or
2. the caller successfully completes Ubuntu PAM authentication in an interactive terminal after pressing Enter while the request is pending, or after the 90-second remote window expires.

Syn never turns a network-provided command into a root process. Sudo retains the original argv/environment and performs execution after the approval plug-in returns success.

## Trust boundaries

| Component | Privilege | Trusted for |
| --- | --- | --- |
| `sudo.ws` and sudoers policy | setuid root | authorization, normalized execution plan, execution |
| `syn_approval.so` | inside setuid process | intent construction, target signing, decision verification, fallback selection |
| target signing key | root-readable only | proving a request came from the enforcement plug-in |
| `syn-agent` | dedicated unprivileged user | availability and message relay only |
| Reachable LAN or private network | network substrate | reachability, not Syn authorization |
| Mac transport identity | ordinary Keychain item | connecting the paired Mac and signing denials |
| Mac approval key | Secure Enclave, user-presence gated | signing one-use approvals |
| macOS account | user-controlled | correct review and local user-presence authentication |
| Ubuntu PAM stack | root process | password authentication after pending Enter selection or eligible timeout |
| Restricted maintenance SSH key | Mac-readable only | authorizing fixed privileged Syn installation operations |
| Retained maintenance dispatcher | root-owned | verifying selected helper bytes and routing fixed lifecycle operations |

## Attacker models

### Coding agent or user process on the Pi

Assume it can invoke `sudo`, control argv and environment, open ordinary network connections, read its own files and processes, and produce arbitrary terminal output. It does not know the Ubuntu password and cannot read root files.

It must not be able to create approval requests directly, substitute a different command after approval, replay a decision, or invoke another setuid sudo provider against the managed `NOPASSWD` rule.

First setup requires a trusted administrator session outside that agent's control. The bootstrap verifies the root-owned helper copy and pins the Mac's restricted maintenance key. Thereafter no administrator password is sent through the managed account's shell; modified incoming files fail protected hash checks. A stolen maintenance key or compromised Mac can authorize privileged installation and is outside this attacker model.

### Compromised transport agent

Assume the `syn` service account and agent memory are compromised. The attacker can observe request metadata, drop or reorder messages, and fabricate availability failures.

It must not be able to sign target requests or approver decisions. Its maximum authorization impact is denial of service or forcing the documented 90-second password fallback.

### Tailnet participant or administrator

Assume another tailnet node can discover the port and an administrator can change DNS/ACL routing. Mutual TLS pins the paired endpoints; request and decision signatures remain the authorization boundary.

### Compromised Mac login or Pi password

These are explicitly outside the protection claim. Apple system user presence permits the Mac account password, and the Ubuntu password is a deliberate fallback. Possession of either corresponding password can authorize its respective path.

## Invariants

- Approval is bound to protocol version, target, adapter, nonce, request ID, request hash, execution intent, and live local deadline.
- The enforcement plug-in verifies the approval; it does not trust the agent's verdict.
- Unknown protocol and adapter versions fail closed.
- Explicit denial, invalid signatures, malformed data, policy blocks, replay, wrong targets, and user cancellation never reach password fallback.
- Absence or ordinary expiry can reach fallback only after 90 seconds and only with an interactive terminal.
- No approval cache, batching, remembered command, or pattern grant exists.
- Environment values are not sent to the Mac; their framed digest is bound to the request.
- Syn logs hashes and result metadata, never passwords, private keys, pairing secrets, environment values, or full argv.

## Root-shell policy limitation

Syn blocks obvious interactive root shells and interpreters as an accident guard. This is not containment: an approved package installer or file-writing command can install a service, modify sudoers, or otherwise obtain persistent root authority.

## Residual risks

- A malicious package or approved root-equivalent command.
- Terminal password phishing by the invoking process.
- A flaw in sudo, PAM, Rust/C FFI, cryptographic libraries, macOS frameworks, or package installation.
- Full command text already recorded by the host's existing sudo logging policy.
- Mac sleep prevents direct notification delivery because the alpha has no APNs relay.
- Denial of service at every non-root transport boundary.
