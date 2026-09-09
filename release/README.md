# Release artifact contract

Every experimental release has one `YYYYMMDDHHMMSS` UTC release ID and one
exact lowercase 40-character Git commit. `release.json` is the shared identity:

```json
{"schema_version":1,"release_id":"20260905143022","commit":"0123456789abcdef0123456789abcdef01234567"}
```

Release builds compile the same values through `SYN_RELEASE_ID` and
`SYN_RELEASE_COMMIT`. The JSON is also copied to:

- `Syn.app/Contents/Resources/release.json`;
- `/usr/share/syn/release.json` in the Debian package; and
- `release/release.json` in the remote source archive.

The source archive is named `syn-remote-source-RELEASE_ID.tar.gz`. It contains
one equally named top-level directory, the exact committed source, vendored
Cargo dependencies, and an offline Cargo configuration.

`remote-source.json` records the source archive's exact name, SHA-256 and byte
size. It is added to the Mac app before code signing. The Mac-led installer may
therefore trust this descriptor only after verifying the app's expected signing
identity; a neighboring download checksum is not a substitute.

`release-index.json` lists the final Mac ZIP and source archive for publication.
It is transport metadata. It cannot authenticate either artifact by itself.
The release archiver rejects ad-hoc signatures and signatures without hardened
runtime; its explicit ad-hoc override exists only for the CI packaging smoke test.

The visible timestamp is not placed directly in `CFBundleVersion`. Apple limits
that field to three numeric components of at most 4, 2 and 2 digits. CI supplies
a separate monotonic `SYN_MAC_BUILD_NUMBER`; the app displays the full release
ID from signed `release.json`.
