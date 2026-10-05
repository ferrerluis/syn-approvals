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
SYN_RELEASE_METADATA=/absolute/path/release.json npm run device:compile
```

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
