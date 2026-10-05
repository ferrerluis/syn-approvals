# Syn mobile

React Native UI on Expo SDK 57. The local `syn-native` module links a reproducibly built Swift security framework. Pairing, SSH/TLS checks, target request verification, device keys and request-bound signing stay native. JavaScript receives typed display state and calls `approve(requestID)` or `deny(requestID)`; there is no generic signer or executor.

## Local build

Use Node 22+, Xcode 26.6, CocoaPods with the `xcodeproj` Ruby gem, and a local iPhone simulator. No Apple enrollment is needed for simulator acceptance.

```sh
cd mobile
npm ci
npm run native:build
npx --no-install expo prebuild --platform ios --no-install
pod install --project-directory=ios
npm run acceptance:build
```

Generated `mobile/ios` and `mobile/android`, framework/build output and screenshots are ignored. Shared native sources remain under the repository's separate `ios` and `macos` directories. Debug simulator builds use an explicitly labeled development signer; production builds use Secure Enclave and fresh user presence. Expo Go cannot supply this module.

The acceptance build embeds JavaScript and runs with Metro stopped. Remote JavaScript updates are disabled. Matching target/app release metadata is checked before bundling. Non-development metadata requires a clean checkout at the exact commit. Device compilation must use Release and real metadata; it cannot use the simulator signer or zero metadata:

```sh
SYN_RELEASE_METADATA=/absolute/path/release.json SYN_SETUP_ARTIFACTS=/absolute/path/artifacts npm run device:compile
```

Matching-release builds require a directory containing `remote-source.json`, its source archive, `remote-helper.json`, and its Linux ARM64 helper. The build verifies their release, hashes and sizes before embedding them.

This regenerates the native workspace with the separate production app identity. Before returning to simulator work, rebuild the Debug native core and regenerate/preinstall the Debug Expo workspace.

## Checks and simulator tools

```sh
npm run typecheck
npm test
npx --no-install expo-doctor
npx --no-install agent-device --help
```

`agent-device` is pinned locally. Use its semantic snapshots, accessibility assertions, screenshots and replayable flows against the local simulator so Meshnet remains accessible. Live approval screenshots may include safe command display data; do not record private enrollment keys, signing bytes or arbitrary argv in snapshots. Maestro flows supplement the local acceptance steps.

## Alerts and platform scope

See [`docs/codex-approvals.md`](../docs/codex-approvals.md). Codex alerts require a connected host and phone permissions. They cover Codex-initiated work only; a reply cannot authorize anything, and expiry remains 90 seconds. Real phone alert delivery and physical Secure Enclave proof are outside this milestone.

Android can reuse the typed native interface and UI, but currently has no native approval backend. Implementing its platform key protection and trusted transport is a separate milestone.

## Candidate status

The Swift rollback candidate is commit `12e207ddbfd710f7828ec85f8cfdabfde8da85b5`. Expo simulator build and real Pi acceptance are still being validated. Phone-led installation/update requires its own administrator-authorized maintenance path and isolated ARM64 validation before a real Pi installation is changed.

To repeat the SSH setup check without authorizing installation, supply the hostname and a fingerprint already verified through an independent administrator session:

```sh
npx --no-install agent-device test flows/setup-ssh.yaml --maestro --platform ios \
  --udid A0231B4A-C845-463B-BE74-8E5CBD9F2A04 \
  --env HOST=your-machine-hostname --env FINGERPRINT=SHA256:verified-fingerprint \
  --artifacts-dir artifacts/setup-ssh
```

The native review fixture at `macos/Tests/SynTests/Fixtures/mobile-review.json` is consumed by both Swift and JavaScript tests. It checks display fields and redaction; it never authorizes an invocation. Signed wire verification continues to use the protocol-v2 golden vectors.

Use `agent-device install` when updating a simulator app that has a paired identity. The local install check preserved the public device UUID. Do not use `reinstall` for pairing/update acceptance without first proving that its data-reset behavior is acceptable.

`flows/review-pending.yaml` reviews a fresh `/usr/bin/true` request on an independently verified target. Start and retain the original sudo process, then run the flow with `TARGET_ID`, `SOURCE_USER`, `SOURCE_UID` and an absolute `SCREENSHOT` path. Check the original process exit status afterward; an empty request list alone is not approval evidence. Close a manual agent-device session before `test`, which creates its own simulator session.

`flows/setup-context.yaml` extends the SSH setup check with a rejected hostname. It verifies that a failed check removes the previous fingerprint and bootstrap controls. Supply the same `HOST` and independently verified `FINGERPRINT` variables as the setup flow.

## Phone-led setup and updates

Enter the direct hostname, SSH port and Linux account. Independently verify the displayed SSH fingerprint. A trusted administrator verifies the matching release's ARM64 helper and stages it as root-owned `/var/tmp/syn-bootstrap.mobile/synctl` (directory 0700, helper 0500), then runs the displayed `maintenance install-mobile` command. Debug simulators additionally require the explicit development grant shown in that command.

The phone key is restricted to its own enrollment/profile, three hash-bound uploads and the fixed installer/recovery phases. Uploads permanently drop root UID, GID and supplementary groups before user-directory writes. Updates preserve target and Mac identities; a fresh phone-first installation records the phone's primary identity. Review and approve the two signed setup requests in Syn. A failure after the protected transition triggers local sudo recovery.

An administrator can revoke only a phone's setup authority with `synctl maintenance revoke-mobile --device-id PHONE_UUID --apply`; Mac setup access is retained. Revoking an enrolled additional approver with `synctl approvers revoke` also removes its setup authority. Real-Pi acceptance and final cleanup remain required; unit checks alone do not prove installation.

The isolated Ubuntu ARM64 installation, automatic relay update and final-denial rollback are now verified at code candidate `d381856eb1a4b2b3d85cefb947572787b3f4cbc8`; real-Pi acceptance remains pending. See [`the validation record`](../docs/validation/2026-10-05-expo-progress.md) for exact results and limits.

`flows/setup-activation.yaml` repeats the full setup/update test after a trusted administrator has granted this phone's fixed setup key. Supply `HOST`, `PORT`, independently verified `FINGERPRINT`, `TARGET_ID`, `SOURCE_USER`, `SOURCE_UID`, `SCREENSHOT_PREFIX`, `FINAL_DECISION` and `RESULT`. Use `FINAL_DECISION=approve` with `RESULT=Setup complete`, or `FINAL_DECISION=deny` with `RESULT=Restoring local sudo after incomplete setup`; independently check the actual sudo rule and provider restoration afterward. Run only on an authorized isolated target with recovery available. Equal-release enrollment on an already armed target uses `flows/connected.yaml` instead of repeating activation.
