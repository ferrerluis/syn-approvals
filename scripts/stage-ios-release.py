#!/usr/bin/env python3
"""Bind an iOS app to its exact matching target release before signing."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


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
        subprocess.run([sys.executable, str(tool), 'verify-checkout', '--metadata', str(args.metadata),
            '--repository', str(args.repository), '--source-input', 'ios', '--source-input', 'macos/Sources/Syn',
            '--source-input', 'scripts/stage-ios-release.py'], check=True)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.metadata, args.destination)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'iOS release identity check failed: {error}', file=sys.stderr)
        sys.exit(1)
