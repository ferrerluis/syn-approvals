#!/usr/bin/env python3
"""Bind an iOS app to its exact matching target release before signing."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


# Enumerate compilation inputs, not generated projects, dependency caches or
# framework output. verify-checkout still rejects ALL dirty/untracked files.
MOBILE_INPUTS = (
    'mobile/App.tsx', 'mobile/index.ts', 'mobile/src', 'mobile/native-core',
    'mobile/modules/syn-native/ios/src', 'mobile/modules/syn-native/ios/SynNative.podspec',
    'mobile/modules/syn-native/expo-module.config.json', 'mobile/modules/syn-native/package.json',
    'mobile/modules/syn-native/index.ts', 'mobile/package.json', 'mobile/package-lock.json',
    'mobile/app.json', 'mobile/app.config.js', 'mobile/app.config.ts',
    'mobile/babel.config.js', 'mobile/metro.config.js', 'mobile/plugins', 'mobile/scripts',
    'mobile/assets', 'mobile/tsconfig.json',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', required=True)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--repository', type=Path, required=True)
    args = parser.parse_args()
    value = json.loads(args.metadata.read_text())
    development = value == {'schema_version': 1, 'release_id': '00000000000000', 'commit': '0' * 40}
    if development:
        if args.configuration != 'Debug' or args.platform != 'iphonesimulator':
            raise ValueError('development release metadata is restricted to Debug simulator builds')
    else:
        tool = args.repository / 'scripts/release-tool.py'
        command = [sys.executable, str(tool), 'verify-checkout', '--metadata', str(args.metadata),
            '--repository', str(args.repository)]
        for path in ('ios', 'macos/Sources/Syn', 'scripts/stage-ios-release.py', 'scripts/stage-mobile-setup.py', *MOBILE_INPUTS):
            command.extend(('--source-input', path))
        subprocess.run(command, check=True)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.metadata, args.destination)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'iOS release identity check failed: {error}', file=sys.stderr)
        sys.exit(1)
