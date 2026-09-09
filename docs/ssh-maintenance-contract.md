# SSH maintenance contract

Updated September 9, 2026 for the approved one-time bootstrap.

## User journey and trust

The Mac checks the hostname and ordinary SSH account, stages the bundled helper, and displays one command. The user runs it in a trusted administrator session on the remote machine, then clicks **I've run the command — continue**. Later setup and updates stay in Syn.

That first terminal must be outside the agent's control. An already compromised user shell can intercept a password typed locally too. Use a separate trusted administrator session or console for bootstrap; Syn cannot create initial trust from a hostile account.

Syn never asks for the remote administrator password or sends it over SSH. Ordinary SSH is used for read-only inspection and transfer of untrusted staging files. Its output cannot approve privileged installation. Everyday approvals continue through the direct paired mTLS connection.

## Restricted maintenance identity

- Each remote hostname/account has a separate Ed25519 key on the Mac, in a user-owned mode-0700 directory under Application Support/Syn/Maintenance; the private key is mode 0600. It is never transferred to the remote machine, added to an agent, or included in target profiles or evidence.
- Bootstrap copies the bundled helper to a root-owned private directory and checks that copy against the Mac's exact size and SHA-256 before executing it.
- The helper retains itself and a one-user configuration under /var/lib/syn/maintenance, then installs one root authorized_keys entry with a forced Syn dispatcher, no forwarding, no PTY and no user startup hooks. Existing unrelated keys are preserved.
- The machine must already permit forced root public-key commands. Syn checks SSH policy and the root shell; it never weakens that policy to make setup succeed.
- The Mac resolves the existing SSH routing settings locally, then uses an isolated SSH configuration containing only the maintenance identity. Hostname, port, proxy routing and known-host settings are preserved; other identity files, agents, certificates, forwarding and command hooks are excluded. A unit test checks OpenSSH's actual evaluated configuration, including that exactly one identity is listed.
- This key authorizes privileged installation of Syn components. It is an administrator credential, not a containment boundary against a compromised Mac or stolen maintenance key. Keep it separate from agent-accessible credentials.
- Local `maintenance revoke --apply` removes only the recorded Syn entry. A new key requires explicit revocation first. Recovery and uninstall remain available without the Mac.

## Fixed protocol

The SSH key is forced to execute:

```text
/var/lib/syn/maintenance/synctl --json maintenance serve
```

It parses SSH_ORIGINAL_COMMAND as an exact bounded token vocabulary, never as executable shell text:

| Request after syn-maintenance-v1 | Purpose |
| --- | --- |
| probe | Confirm protocol 1 and the configured managed username. |
| retain OP HASH SIZE | Copy the fixed incoming helper into protected storage, verifying the copy before use. |
| prepare OP REQUEST_HASH SOURCE_HASH | Verify and retain the exact request/source using the protected helper. |
| cleanup OP | Remove bootstrap staging after protected preparation. |
| build OP | Build the selected source using the locked build account. |
| configure OP | Install and pair the exact release. |
| activate OP | Arm recovery and activate the sudo gate after preflight approval. |
| complete OP | Require final approval and verify health before canceling recovery. |
| recover | Use retained recovery code to restore local sudo. |

OP is exactly 32 lowercase hexadecimal characters; hashes are exactly 64. Extra tokens, paths, shell syntax and unknown operations fail. The dispatcher launches only fixed helper paths with fixed argv and a clean environment. The managed account comes from root-owned configuration, never the incoming SSH environment.

The ordinary account stages source.incoming, request.incoming and synctl-bootstrap.incoming under .cache/syn-setup. Those files remain untrusted until the privileged helper verifies protected copies against hashes sent through the authenticated maintenance connection. Modifying staging can cause failure, not substituted root execution.

No command-execution API is added to syn-agent. The approval channel and maintenance SSH identity are separate.

## Recovery and release changes

An A-to-B update preserves target and pairing identities. The maintenance channel restores ordinary password sudo before replacing the package. Protected operation journals support retries; changing an existing operation's verified inputs fails.

The retained maintenance dispatcher survives package replacement and understands its versioned protocol. Candidate operations run the selected protected helper; recovery uses retained trusted code. Each release must test this boundary with genuine A/B artifacts.

Recovery removes NOPASSWD first. A root-owned worker lease and process identity checks contain interrupted activation; the reboot-persistent deadline remains until health checks pass. Completion stops both timer and queued recovery service, then rechecks the sudo configuration before recording success.

## Acceptance

Unit tests cover token injection, key shape, unsafe files, copied-byte substitution, SSH identity isolation, secret-free setup, phase failures and recovery ordering. The dedicated E2E session must run all [12 cases](onboarding-e2e-test-plan.md), including trusted bootstrap, rejected unrestricted SSH commands, key revocation, update without password transfer, and final clean reinstall. Component results do not count as live acceptance.
