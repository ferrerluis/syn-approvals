#!/bin/bash
set -euo pipefail
mobile_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$mobile_root/.." && pwd)"
: "${SYN_RELEASE_METADATA:?Device compilation requires exact non-development release metadata}"
cd "$mobile_root"
export SYN_MOBILE_VARIANT=production
# Validate BEFORE preparing native artifacts. Zero metadata is rejected here.
python3 "$repo_root/scripts/stage-ios-release.py" --configuration Release --platform iphoneos --metadata "$SYN_RELEASE_METADATA" --destination "$mobile_root/artifacts/device-release.json" --repository "$repo_root"
setup_args=()
if [ -n "${SYN_SETUP_ARTIFACTS:-}" ]; then setup_args+=(--artifacts "$SYN_SETUP_ARTIFACTS"); fi
python3 "$repo_root/scripts/stage-mobile-setup.py" --metadata "$SYN_RELEASE_METADATA" --destination "$mobile_root/artifacts/setup-resources" "${setup_args[@]}"
SYN_CORE_CONFIGURATION=Release SYN_CORE_PLATFORM=iphoneos SYN_CORE_OUTPUT="$mobile_root/native-build/device/SynMobileCore.xcframework" bash scripts/build-native-core.sh
frameworks="$mobile_root/modules/syn-native/ios/Frameworks/SynMobileCore.xcframework"
# CocoaPods uses this generated module framework only. Rebuild Debug afterward
# with native:build before returning to simulator work.
rm -rf "$frameworks"
cp -R "$mobile_root/native-build/device/SynMobileCore.xcframework" "$frameworks"
npx --no-install expo prebuild --clean --platform ios --no-install
pod install --project-directory=ios
cp artifacts/device-release.json ios/Syn/release.json
xcodebuild -workspace ios/Syn.xcworkspace -scheme Syn -configuration Release -destination 'generic/platform=iOS' -derivedDataPath artifacts/device-build ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO build > artifacts/device-build.log 2>&1 || { tail -60 artifacts/device-build.log; exit 1; }
app="$mobile_root/artifacts/device-build/Build/Products/Release-iphoneos/Syn.app"
test -f "$app/main.jsbundle"
cmp "$SYN_RELEASE_METADATA" "$app/release.json"
if strings "$app/Frameworks/SynMobileCore.framework/SynMobileCore" | rg 'SimulatorDecisionSigner' > /dev/null; then
  printf '%s\n' 'Production framework unexpectedly contains simulator signing code' >&2
  exit 1
fi
printf '%s\n' "$app"
