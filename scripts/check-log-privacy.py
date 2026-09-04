#!/usr/bin/env python3
"""Check captured Syn output without echoing contents or test passwords.

Read-only validation helper, not part of the privileged runtime. Supply only
Syn-owned output, not standard sudo/auth logs (which have a different policy).
Test passwords are optional and read from the terminal, never command arguments.
"""

import argparse
import getpass
import json
from pathlib import Path
import re
import sys
import warnings

MAX_CAPTURE_BYTES = 16 * 1024 * 1024
PEM_MATERIAL = re.compile(
    rb"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|CERTIFICATE)-----"
)


def scan(data, markers, passwords):
    """Return counts only; keys are fixed labels, never user-provided values."""
    return {
        "pem_material": len(PEM_MATERIAL.findall(data)),
        "environment_marker": data.count(markers[0]),
        "argument_marker": data.count(markers[1]),
        "test_password": sum(data.count(password) for password in passwords),
    }


def read_capture(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_CAPTURE_BYTES + 1)
    if not data or len(data) > MAX_CAPTURE_BYTES:
        raise ValueError("capture is empty or exceeds size limit")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", type=Path, nargs="+")
    parser.add_argument("--environment-marker", required=True)
    parser.add_argument("--argument-marker", required=True)
    parser.add_argument("--prompt-test-password", action="count", default=0)
    args = parser.parse_args()
    markers = [args.environment_marker.encode(), args.argument_marker.encode()]
    if any(len(marker) < 16 for marker in markers) or markers[0] == markers[1]:
        parser.error("use two distinct dummy markers of at least 16 bytes")
    if args.prompt_test_password and not sys.stdin.isatty():
        parser.error("test passwords require an interactive terminal")
    passwords = []
    for _ in range(args.prompt_test_password):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("Test password for scan only (not echoed): ")
        except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
            print(json.dumps({"ok": False, "error": "secure_password_input_unavailable_or_canceled"}))
            return 2
        if not password:
            parser.error("empty test password")
        passwords.append(password.encode())
    reports = []
    for index, path in enumerate(args.captures):
        try:
            data = read_capture(path)
        except (OSError, ValueError):
            # Do not echo exception text, file contents, paths, or input values.
            print(json.dumps({"ok": False, "capture": index, "error": "capture_unreadable_empty_or_oversized"}))
            return 2
        reports.append({"capture": index, "bytes": len(data), "matches": scan(data, markers, passwords)})
    clean = all(not any(report["matches"].values()) for report in reports)
    print(json.dumps({"ok": clean, "test_passwords_checked": len(passwords), "captures": reports}))
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
