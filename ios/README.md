# Syn native iOS security sources

The product app now lives in [`mobile`](../mobile/README.md). This directory retains the Swift candidate, native security sources, and a separate SwiftUI test harness; it is not the Expo generated native project. Raspberry Pi acceptance and hardware Secure Enclave testing remain distinct from local harness results.

The iPhone connects to the same target agent directly over pinned TLS with its own client certificate. It shares canonical CBOR, signed request verification, safe byte display, decision binding, and release identity with macOS. **Approve** still applies to one live invocation. The first valid approval or denial resolves the request and cancels its display on other connected devices.

On a physical iPhone, approval keys use the Secure Enclave and fresh system user presence; denial keys require device authentication. Debug simulator builds explicitly use an isolated software signer. They must be enrolled with `--allow-development` and do not prove Face ID or hardware-backed protection. Debug and Release use separate app identities and Keychain access.

## Build and test

Open `SynIOS.xcodeproj` in Xcode 26. Select **SynIOS** and an iPhone simulator, then run. Deployment requires iOS 18 or later. The source uses Apple's Swift NIO SSH and Swift Certificates libraries; exact resolved dependencies are checked in.

```sh
xcodebuild -project ios/SynIOS.xcodeproj -scheme SynIOS -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -derivedDataPath /tmp/syn-ios test
```

Simulator development builds use all-zero release metadata. Physical-device and Release builds require `SYN_RELEASE_METADATA=/absolute/path/release.json`, a clean checkout at that exact commit, and the same release installed on the target. The build refuses development metadata outside a Debug simulator. Unsigned device compilation does not require Apple enrollment. Installing a standalone app on physical hardware requires suitable signing; hardware testing is outside simulator acceptance.

## Pair an additional iPhone

The Expo app supports first installation and matching-release updates through its fixed native setup flow. Its bundled helper and source are checked against the app’s release; initial administrator authorization remains necessary.

1. Choose **Add a machine**, enter its reachable SSH hostname and port, and choose **Check machine**.
2. Compare the SSH host fingerprint through independent trusted access before choosing **Trust verified machine**. Changed host keys stop setup.
3. Run the displayed authorization command once in a trusted administrator terminal. The iPhone does not collect a remote administrator password.
4. Continue in the iPhone app. It sends only public enrollment material through a forced SSH command, receives its public target profile, then connects directly to the target. Existing Mac pairing is retained.

The maintenance key permits enrollment of that device, its public target profile, fixed bounded artifact uploads, and the existing fixed installation/update/recovery phases. It cannot supply a command, shell, arbitrary path, or an approval decision through SSH. Setup waits for the pinned direct connection before requesting its two signed approval tests. A matching package left after recovery does not skip reactivation. Root enrollment changes the trusted approver registry used independently by both the agent and sudo plug-in. Revoke a device through trusted administrator access:

```sh
/usr/bin/sudo /usr/bin/synctl approvers revoke --device-id DEVICE_UUID --apply
```

Advanced pairing can export the phone's public enrollment and import an independently trusted profile. Public enrollment contains the public signing keys and client certificate; private keys remain in the device Keychain. Identity labels from imported profiles are ignored.

## Codex alerts

Syn-owned APNs registration, delivery, and entitlements have been removed. See [`docs/codex-approvals.md`](../docs/codex-approvals.md) for Codex attention instructions and external notification requirements. A Codex reply cannot approve a request.

## Controlled visual test

`Tests/Support/run_direct_target.py` is a test-only pinned-mTLS target on loopback. Install its Python requirements in a temporary environment. Prepare the simulator identity, obtain its public `Library/Application Support/Syn/enrollment.json` through `simctl get_app_container`, and start the harness using the built `syn-sim` binary. Import the generated public profile through Advanced pairing, then approve both fresh requests with Computer Use. Its status file records connection and verified approval counts without recording signed messages or command data.

The harness does not validate sudo, Pi recovery, Meshnet, Codex phone delivery, Secure Enclave, or the mobile SSH setup path. Those remain distinct acceptance checks.
