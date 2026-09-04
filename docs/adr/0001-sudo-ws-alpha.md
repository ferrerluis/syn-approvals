# ADR 0001: Use `sudo.ws` for the first alpha

Status: accepted.

Ubuntu 26.04 defaults to sudo-rs, which currently has no external approval hook carrying a normalized execution intent. Classic sudo exposes an approval plug-in after sudoers policy acceptance and before execution.

Syn will use classic sudo's documented approval ABI for the alpha. Installation must disable other setuid sudo providers that share the managed `NOPASSWD` rule. The protocol and transport do not depend on the C ABI, allowing a later sudo-rs adapter.

Syn will not maintain a production sudo-rs fork.
