# Syn for iPhone

This is an implementation candidate. It has passed a visible simulator-to-local-target approval round trip, including a second request needing a second tap. Raspberry Pi acceptance, real APNs background delivery, and physical iPhone Secure Enclave tests remain incomplete. The local harness never executes a command.

The iPhone connects to the same target agent directly over pinned TLS with its own client certificate. It shares canonical CBOR, signed request verification, safe byte display, decision binding, and release identity with macOS. **Approve** still applies to one live invocation. The first valid approval or denial resolves the request and cancels its display on other connected devices.

On a physical iPhone, approval keys use the Secure Enclave and fresh system user presence; denial keys require device authentication. Debug simulator builds explicitly use an isolated software signer. They must be enrolled with `--allow-development` and do not prove Face ID or hardware-backed protection. Debug and Release use separate app identities and Keychain access.

## Build and test

Open `SynIOS.xcodeproj` in Xcode 26. Select **SynIOS** and an iPhone simulator, then run. Deployment requires iOS 18 or later. The source uses Apple's Swift NIO SSH and Swift Certificates libraries; exact resolved dependencies are checked in.

```sh
xcodebuild -project ios/SynIOS.xcodeproj -scheme SynIOS -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -derivedDataPath /tmp/syn-ios test
```

Simulator development builds use all-zero release metadata. Physical-device and Release builds require `SYN_RELEASE_METADATA=/absolute/path/release.json`, a clean checkout at that exact commit, and the same release installed on the target. The build refuses development metadata outside a Debug simulator. Provisioning and APNs entitlements require an eligible Apple development team; no private signing inputs belong in this repository.

## Pair an additional iPhone

Syn must already be installed on the target at the app's matching release. This candidate adds independent iPhone identity and pairing; it does **not yet implement** the Mac app's entire first-install/update workflow.

1. Choose **Add a machine**, enter its reachable SSH hostname and port, and choose **Check connection**.
2. Compare the SSH host fingerprint through independent trusted access before choosing **Trust this host**. Changed host keys stop setup.
3. Run the displayed authorization command once in a trusted administrator terminal. The iPhone does not collect a remote administrator password.
4. Continue in the iPhone app. It sends only public enrollment material through a forced SSH command, receives its public target profile, then connects directly to the target. Existing Mac pairing is retained.

The maintenance key permits exactly two operations: enroll that same device ID and read its public target profile. It cannot submit an executable, argv, shell, arbitrary file, or an approval decision through SSH. Root enrollment changes the trusted approver registry used independently by both the agent and sudo plug-in. Revoke a device through trusted administrator access:

```sh
/usr/bin/sudo /usr/bin/synctl approvers revoke --device-id DEVICE_UUID --apply
```

Advanced pairing can export the phone's public enrollment and import an independently trusted profile. Public enrollment contains the public signing keys and client certificate; private keys remain in the device Keychain. Identity labels from imported profiles are ignored.

## Background alerts

The Pi sends a generic alert directly to Apple APNs. The phone opens a direct connection to retrieve and verify the actual request. Push messages carry no executable, arguments, environment, request ID, nonce, decision, approval URL, or bearer approval credential. An alert cannot authorize anything. The 90-second request lifetime continues while the app is suspended; opening an expired alert does not revive a request.

An eligible Apple team, provisioned bundle ID, and APNs provider key are required. On the Pi, provision the `.p8` provider key as root-owned and readable only by root and the agent's trusted group; never store it in the repository. Add the optional agent configuration:

```toml
[apns]
team_id = "TEAMID1234"
key_id = "KEYID12345"
topic = "org.syn-approvals.SynIOS.Debug"
environment = "development"
signing_key = "/etc/syn/apns.p8"
state_file = "/var/lib/syn-notifications/tokens.json"
```

Use the production topic `org.syn-approvals.SynIOS` and environment `production` for the Release app. The agent accepts a token only from an authenticated enrolled iPhone connection. Systemd creates its private notification-state directory. APNs keys are separate from the target's authorization key; the unprivileged agent never obtains that target private key. Push setup or delivery failure does not disable the direct approval transport.

## Controlled visual test

`Tests/Support/run_direct_target.py` is a test-only pinned-mTLS target on loopback. Install its Python requirements in a temporary environment. Prepare the simulator identity, obtain its public `Library/Application Support/Syn/enrollment.json` through `simctl get_app_container`, and start the harness using the built `syn-sim` binary. Import the generated public profile through Advanced pairing, then approve both fresh requests with Computer Use. Its status file records connection and verified approval counts without recording signed messages or command data.

The harness does not validate sudo, Pi recovery, Meshnet, APNs receipt, Secure Enclave, or the mobile SSH setup path. Those remain distinct acceptance checks.
