# Recoverable Pi alpha runbook

This short runbook is for a recoverable Ubuntu 26.04 ARM64 target. It does not require spare hardware, but it does require a Pi-local timed rollback and a preserved root path before sudo behavior changes.

Use the detailed [live Pi test-and-iterate plan](live-pi-validation-plan.md) for the real Raspberry Pi. The steps below remain a compact reference and must not override its recovery gates.

## 1. Build and stage

Build the Debian package on Ubuntu ARM64 with `scripts/build-deb.sh`, inspect it with `dpkg-deb --contents`, and install it from a console-capable session. Package installation creates the locked `syn` service account and stages files, but it does not alter sudo behavior or add `NOPASSWD`.

Generate the target authorization key and initialize the exact one-user policy:

```sh
sudo synctl keys generate-target
sudo synctl policy init --user luis --uid 1000 --apply
```

Copy the example agent and plug-in configurations, replace every placeholder, and verify `synctl doctor`. Never bind the relay to `0.0.0.0`.

## 2. Establish the manual alpha identities

In the Mac app, generate the approver identities and copy the public JSON. Stage those public keys on the Pi with a dry run first, then `--apply`:

```sh
sudo synctl pair accept-approver \
  --approval-x963-base64 VALUE \
  --denial-x963-base64 VALUE
```

Create the Mac transport identity with `scripts/create-mac-client-identity.sh`. Transfer only its public certificate to the Pi, then create the target TLS material with `scripts/create-target-tls.sh`; keep all private keys on their owning device.

The Mac script uses a short-lived PKCS#12 wrapping password passed only through stdin to OpenSSL and a native import helper. Private temporary files are confined to a private directory and removed afterward; the permanent transport key is imported into Keychain with access assigned to Syn.app. The helper currently uses Apple's legacy per-app Keychain ACL APIs. Ad-hoc rebuilding changes the app identity and may require renewed Keychain permission; do not grant Syn access to unrelated Apple signing keys. A stable developer signing identity is preferable for repeated UI validation.

The app selects the labeled **certificate**, resolves its matching private key, and verifies that the resulting identity contains exactly that certificate. Do not replace this with an identity query filtered only by label: live macOS testing showed that query returning an unrelated identity.

The native transport uses Network.framework with TLS 1.3, exact certificate pinning, per-connection trust anchors, hostname/validity checks, and a 64 KiB message limit. It does not add system trust entries or disable ATS for other traffic. See Apple's [manual server-trust guidance](https://developer.apple.com/documentation/Foundation/performing-manual-server-trust-authentication) for the URLSession/ATS restriction and [identity import documentation](https://developer.apple.com/documentation/security/importing-an-identity) for the nonempty PKCS#12 password requirement.

After configuring and starting `syn-agent`, create the exact pinned Mac profile:

```sh
sudo synctl --json pair profile \
  --target-id pi-development \
  --display-name 'Development Pi' \
  --web-socket-url 'wss://pi-development.tailnet.ts.net:41781' \
  --client-identity-label 'Syn pi-development transport'
```

Import only the `data` object from that JSON envelope into the Mac app. This profile must move over an authenticated channel because the current manual flow has no QR secret exchange.

## 3. Prove the non-executing round trip

With the agent and Mac app connected, run:

```sh
sudo synctl test approval
sudo synctl test approval --record-preflight
sudo synctl test fallback
```

The approval test presents a synthetic `/usr/bin/true` request and never executes it. The fallback test is read-only in the current build; therefore the real PAM path remains unproven and installation must not proceed until the live plan's recovery timer and root path are proven.

## 4. Inspect, arm, and recover

Complete the live plan's shadow phase before normal activation. Use `install --user NAME --shadow` with the same preview, signed-preflight, timer, and recovery acknowledgment requirements. This loads the plug-in for direct `/usr/bin/sudo.ws` tests while leaving the default provider and ordinary password authentication unchanged. Recover afterward; only then consider the normal installation below.

On the recoverable Pi, prove and arm the timed rollback before inspecting the install plan:

```sh
sudo synctl recovery prove --seconds 2 --apply
sudo synctl recovery arm --minutes 15 --apply
synctl --json recovery status
sudo synctl --json install --user luis
```

Keep an independent root console open. If proceeding with the unreviewed path, `--apply --acknowledge-console-recovery` records provider modes, disables alternate setuid sudo providers, selects `sudo.ws`, loads the plug-in, validates sudo configuration, starts the agent, and writes the one-user `NOPASSWD` rule last.

At the first anomaly, restore local sudo from the independent root console:

```sh
synctl recover --restore-local-sudo --apply
```

Do not close the recovery console until allow, deny, timeout, `sudo -n`, cancellation, direct `sudo-rs`, and missing-plug-in checks all produce the expected result.

Cancel the deadline only through a healthy Syn-controlled sudo invocation:

```sh
sudo synctl recovery cancel --apply
```
