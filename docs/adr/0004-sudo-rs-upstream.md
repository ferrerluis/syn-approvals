# ADR 0004: Upstream hook before a sudo-rs adapter

Status: accepted.

The desired sudo-rs seam is after sudoers authorization/executable resolution and before PAM authentication. A provider may approve one invocation, continue to PAM, deny, or report unavailable, but cannot change the execution plan.

The preferred design is a bounded root-owned Unix-socket interface implemented by sudo-rs, not an arbitrary dynamic library inside the setuid process. Syn will submit an upstream RFC and test a feature-gated reference patch only behind the same proven recovery gates used for privileged alpha testing.
