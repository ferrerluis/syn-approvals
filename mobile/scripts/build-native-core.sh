#!/bin/bash
set -euo pipefail
mobile_root="$(cd "$(dirname "$0")/.." && pwd)"
configuration="${SYN_CORE_CONFIGURATION:-Debug}"
platform="${SYN_CORE_PLATFORM:-iphonesimulator}"
case "$configuration:$platform" in Debug:iphonesimulator|Release:iphoneos|Release:iphonesimulator) ;; *) exit 2;; esac
ruby_bin="${SYN_RUBY:-$(command -v ruby)}"
if ! "$ruby_bin" -e "require 'xcodeproj'" >/dev/null 2>&1; then
  pod_path="$(command -v pod)"
  pod_interpreter="$(head -1 "$pod_path")"
  case "$pod_interpreter" in '#!'/*) ruby_bin="${pod_interpreter#\#!}" ;; esac
fi
"$ruby_bin" "$mobile_root/scripts/generate-core-project.rb"
if [ "$platform" = iphonesimulator ]; then destination='generic/platform=iOS Simulator'; else destination='generic/platform=iOS'; fi
xcodebuild -project "$mobile_root/native-build/SynMobileCore.xcodeproj" -scheme SynMobileCore -configuration "$configuration" -onlyUsePackageVersionsFromResolvedFile -destination "$destination" -derivedDataPath "$mobile_root/native-build/derived-$platform-$configuration" ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO build > "$mobile_root/native-build/core-$platform-$configuration.log" 2>&1 || { tail -60 "$mobile_root/native-build/core-$platform-$configuration.log"; exit 1; }
framework="$mobile_root/native-build/derived-$platform-$configuration/Build/Products/$configuration-$platform/SynMobileCore.framework"
out="${SYN_CORE_OUTPUT:-$mobile_root/modules/syn-native/ios/Frameworks/SynMobileCore.xcframework}"
mkdir -p "$(dirname "$out")"
rm -rf "$out"
xcodebuild -create-xcframework -allow-internal-distribution -framework "$framework" -output "$out"
