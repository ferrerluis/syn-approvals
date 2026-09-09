#!/usr/bin/env python3
"""Check a trusted, locally built ARM64 synctl before publishing or packaging it.

This is a build gate, not a verifier for executing downloaded, untrusted files.
It never installs software or reads the machine's active Syn configuration.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


class HelperError(ValueError):
    pass


ALLOWED_LIBRARIES = {"libc.so.6", "libgcc_s.so.1", "libm.so.6", "ld-linux-aarch64.so.1"}
INTERPRETER = "/lib/ld-linux-aarch64.so.1"


def verify_elf(header: str, program: str, dynamic: str) -> set[str]:
    if not re.search(r"^\s*Class:\s+ELF64\s*$", header, re.MULTILINE):
        raise HelperError("helper is not ELF64")
    if not re.search(r"^\s*Machine:\s+AArch64\s*$", header, re.MULTILINE):
        raise HelperError("helper is not ARM64")
    interpreters = re.findall(r"\[Requesting program interpreter: ([^\]]+)\]", program)
    if interpreters != [INTERPRETER]:
        raise HelperError("helper uses an unexpected program interpreter")
    if re.search(r"\((?:RPATH|RUNPATH)\)", dynamic):
        raise HelperError("helper contains a custom library search path")
    libraries = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
    if not libraries or len(libraries) != len(set(libraries)):
        raise HelperError("helper library inventory is empty or duplicated")
    if not set(libraries) <= ALLOWED_LIBRARIES:
        raise HelperError("helper requires a library outside the Ubuntu bootstrap baseline")
    return set(libraries)


def verify_status(data: bytes, expected: dict) -> None:
    if len(data) > 16_384:
        raise HelperError("helper returned too much status data")
    try:
        envelope = json.loads(data)
        report = envelope["data"]
        if envelope["ok"] is not True or report["schema_version"] != 1:
            raise HelperError("helper status schema is unsupported")
        if report["release_id"] != expected["release_id"] or report["release_commit"] != expected["commit"]:
            raise HelperError("compiled helper identity differs from release metadata")
        if report["configuration_state"] != "absent" or report["configured"] is not False:
            raise HelperError("helper did not use the isolated configuration paths")
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HelperError("helper returned invalid status data") from error


def command(arguments: list[str], environment: dict[str, str]) -> bytes:
    try:
        result = subprocess.run(arguments, env=environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HelperError("helper build check could not complete") from error
    if result.returncode != 0 or len(result.stdout) > 65_536 or len(result.stderr) > 16_384:
        raise HelperError("helper build check failed or exceeded output limits")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise HelperError("run this build check without administrator privileges")
    if args.binary.is_symlink() or not args.binary.is_file():
        raise HelperError("helper must be a regular, locally built file")
    binary = str(args.binary.resolve())
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    command(["/usr/bin/python3", str(Path(__file__).with_name("release-tool.py")),
             "validate", "--metadata", str(args.metadata.resolve())], environment)
    expected = json.loads(args.metadata.read_bytes())
    header = command(["/usr/bin/readelf", "-h", binary], environment).decode("ascii")
    program = command(["/usr/bin/readelf", "-l", binary], environment).decode("ascii")
    dynamic = command(["/usr/bin/readelf", "-d", binary], environment).decode("ascii")
    libraries = verify_elf(header, program, dynamic)
    # ldd is appropriate only here: this binary came from the trusted build,
    # and has already passed the interpreter/library inventory checks.
    resolved = command(["/usr/bin/ldd", binary], environment)
    if b"not found" in resolved or not resolved.strip():
        raise HelperError("helper has an unresolved runtime library")
    with tempfile.TemporaryDirectory(prefix="syn-helper-check-") as temporary:
        report = command([binary, "--json", "status", "--agent-config",
                          str(Path(temporary) / "absent-agent.toml"), "--plugin-config",
                          str(Path(temporary) / "absent-plugin.toml")], environment)
        verify_status(report, expected)
    print("ARM64 helper loader and compiled release identity verified: " + ", ".join(sorted(libraries)))


if __name__ == "__main__":
    try:
        main()
    except (HelperError, OSError, UnicodeError) as error:
        raise SystemExit(str(error)) from None
