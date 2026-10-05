#!/bin/bash
set -euo pipefail
mobile_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$mobile_root/.." && pwd)"
metadata="${SYN_RELEASE_METADATA:-$repo_root/ios/Support/release.json}"
cd "$mobile_root"
export SYN_MOBILE_VARIANT=development
mkdir -p artifacts
python3 "$repo_root/scripts/stage-ios-release.py" --configuration Debug --platform iphonesimulator --metadata "$metadata" --destination "$mobile_root/artifacts/acceptance-release.json" --repository "$repo_root"
setup_args=()
if [ -n "${SYN_SETUP_ARTIFACTS:-}" ]; then setup_args+=(--artifacts "$SYN_SETUP_ARTIFACTS"); fi
python3 "$repo_root/scripts/stage-mobile-setup.py" --metadata "$metadata" --destination "$mobile_root/artifacts/setup-resources" "${setup_args[@]}"
# Rebuild native code from this checkout before every acceptance build.
SYN_CORE_CONFIGURATION=Debug SYN_CORE_PLATFORM=iphonesimulator SYN_CORE_OUTPUT="$mobile_root/modules/syn-native/ios/Frameworks/SynMobileCore.xcframework" bash scripts/build-native-core.sh
npx --no-install expo prebuild --clean --platform ios --no-install
pod install --project-directory=ios
cp artifacts/acceptance-release.json ios/Syn/release.json
unset SKIP_BUNDLING
export FORCE_BUNDLING=1
# Release JavaScript avoids SDK devtools network connections; Swift stays Debug.
export EXTRA_PACKAGER_ARGS="--dev false"
xcodebuild -workspace ios/Syn.xcworkspace -scheme Syn -configuration Debug -destination 'generic/platform=iOS Simulator' -derivedDataPath artifacts/build ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- SWIFT_ACTIVE_COMPILATION_CONDITIONS='DEBUG SYN_EMBEDDED_BUNDLE' build > artifacts/acceptance-build.log 2>&1 || { tail -75 artifacts/acceptance-build.log; exit 1; }
app="$mobile_root/artifacts/build/Build/Products/Debug-iphonesimulator/Syn.app"
test -f "$app/main.jsbundle"
test -f "$app/release.json"
codesign --verify --deep --strict "$app"
printf '%s\n' "$app"
