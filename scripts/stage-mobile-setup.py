#!/usr/bin/env python3
"""Embed only hash-verified setup artifacts from the app's exact release."""
import argparse
import json
from pathlib import Path
import shutil
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    release = json.loads(args.metadata.read_text())
    if release['release_id'] == '00000000000000' and args.artifacts is None:
        if args.destination.exists():
            shutil.rmtree(args.destination)
        return
    if args.artifacts is None:
        raise ValueError('matching-release phone setup requires SYN_SETUP_ARTIFACTS')
    tool = Path(__file__).with_name('release-tool.py')
    source = f"syn-remote-source-{release['release_id']}.tar.gz"
    helper = f"synctl-arm64-{release['release_id']}"
    for kind, name in [('source', source), ('helper', helper)]:
        subprocess.run([sys.executable, str(tool), f'validate-remote-{kind}',
            '--metadata', str(args.metadata), f'--remote-{kind}', str(args.artifacts / f'remote-{kind}.json'),
            '--artifact', str(args.artifacts / name)], check=True)
    with (args.artifacts / helper).open('rb') as binary:
        header = binary.read(64)
    if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 183:
        raise ValueError('setup helper must be a 64-bit Linux ARM64 executable')
    args.destination.mkdir(parents=True, exist_ok=True)
    allowed = {'remote-source.json', 'remote-helper.json', source, helper}
    for existing in args.destination.iterdir():
        if existing.is_symlink() or not existing.is_file():
            raise ValueError('unexpected file in setup staging')
        if existing.name not in allowed:
            if not re.fullmatch(r'(?:syn-remote-source-\d{14}\.tar\.gz|synctl-arm64-\d{14})', existing.name):
                raise ValueError('unexpected file in setup staging')
            existing.unlink()
    for name in sorted(allowed):
        src = args.artifacts / name
        if src.is_symlink() or not src.is_file():
            raise ValueError('setup artifacts must be regular files')
        shutil.copyfile(src, args.destination / name)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'Mobile setup staging failed: {error}', file=sys.stderr)
        sys.exit(1)
