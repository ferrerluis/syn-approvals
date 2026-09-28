# Security policy

Syn is pre-release privileged software. Public source and experimental builds are available, but there are no supported releases yet.

Do not publish proof-of-concept exploits before coordinated disclosure. Report suspected vulnerabilities privately to the repository owner with:

- the affected revision;
- the trust boundary crossed;
- reproduction steps using a disposable target;
- whether arbitrary approval, command substitution, secret disclosure, or denial is possible.

The public-release gate requires independent review of the sudo ABI boundary, PAM fallback, installer transaction, protocol parsers, TLS pairing, and macOS key access controls.

Syn does not claim to protect a machine after its root account, managed Ubuntu password, approver Mac account, or approved root command is compromised. See [docs/threat-model.md](docs/threat-model.md).
