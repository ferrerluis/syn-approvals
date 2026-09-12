#!/usr/bin/env python3
"""Validate and summarize Syn's temporary hybrid-E2E resources.

This is a dry-run bookkeeping tool. It cannot provision or remove anything and
does not accept commands. Cleanup behavior is fixed by each supported resource
type so a manifest cannot become a privileged execution interface.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


HEX_64 = re.compile(r"[0-9a-f]{64}")
KEY_ID = re.compile(r"(?:SHA256:)?[A-Za-z0-9+/=_-]{16,128}")
PROFILE_ID = re.compile(r"syn-e2e-[a-z0-9][a-z0-9-]{2,63}")
RUN_ID = re.compile(r"syn-e2e-[0-9]{8}t[0-9]{6}z-[a-z0-9]{4,16}")
CREATION_NONCE = re.compile(r"[a-z0-9]{16,64}")
TEMP_ROOT = Path("/tmp")
OWNER_MARKER = ".syn-e2e-owner.json"
SUPPORTED_TYPES = {
    "source_directory",
    "test_approval_profile",
    "linux_test_account",
    "linux_test_unit",
}


class ManifestError(ValueError):
    pass


def exact_keys(value, expected, context):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ManifestError(f"{context} must contain exactly: {', '.join(expected)}")


def require_string(value, pattern, context):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ManifestError(f"invalid {context}")
    return value


def run_token(run_id):
    return hashlib.sha256(run_id.encode()).hexdigest()[:12]


def validate_source(resource, run_id):
    exact_keys(resource, ("type", "path", "content_digest", "creation_nonce"), "source_directory")
    path = resource["path"]
    if not isinstance(path, str):
        raise ManifestError("invalid source directory path")
    parsed = PurePosixPath(path)
    expected_prefix = f"{run_id}."
    if (
        not parsed.is_absolute()
        or parsed.parent != PurePosixPath(TEMP_ROOT)
        or not parsed.name.startswith(expected_prefix)
        or parsed.name == expected_prefix
        or "." in parsed.parts
        or ".." in parsed.parts
        or any(character in path for character in "*?[]${}~")
    ):
        raise ManifestError("source directory must be one exact run-owned temporary path")
    require_string(resource["content_digest"], HEX_64, "source content digest")
    nonce = require_string(resource["creation_nonce"], CREATION_NONCE, "creation nonce")
    source = Path(path)
    try:
        root_metadata = TEMP_ROOT.lstat()
        source_metadata = source.lstat()
        marker = source / OWNER_MARKER
        marker_metadata = marker.lstat()
    except OSError as error:
        raise ManifestError("source directory or ownership marker is unavailable") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise ManifestError("temporary root must be a real directory")
    if not stat.S_ISDIR(source_metadata.st_mode) or stat.S_ISLNK(source_metadata.st_mode):
        raise ManifestError("source path must be a real directory, not a symlink")
    if source_metadata.st_uid != os.geteuid():
        raise ManifestError("source directory is not owned by the current user")
    if not stat.S_ISREG(marker_metadata.st_mode) or stat.S_ISLNK(marker_metadata.st_mode):
        raise ManifestError("ownership marker must be a regular file, not a symlink")
    if marker_metadata.st_uid != source_metadata.st_uid or marker_metadata.st_mode & 0o022:
        raise ManifestError("ownership marker has unsafe ownership or permissions")
    try:
        marker_value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError("ownership marker is unreadable") from error
    exact_keys(marker_value, ("schema_version", "run_id", "resource_type", "path", "creation_nonce"),
               "ownership marker")
    if marker_value != {
        "schema_version": 1,
        "run_id": run_id,
        "resource_type": "source_directory",
        "path": path,
        "creation_nonce": nonce,
    }:
        raise ManifestError("ownership marker does not match this run and resource")
    return {
        "resource": "source_directory",
        "target": path,
        "cleanup": "remove this exact unprivileged directory after verifying its recorded digest",
        "verify": "the exact path is absent",
    }


def validate_profile(resource, run_id):
    fields = (
        "type", "profile_id", "approval_public_key_id", "denial_public_key_id",
        "scenario_payload_hash", "request_id", "nonce", "request_context_digest",
    )
    exact_keys(resource, fields, "test_approval_profile")
    profile_id = require_string(resource["profile_id"], PROFILE_ID, "profile ID")
    if profile_id != run_id:
        raise ManifestError("profile ID must equal the manifest run ID")
    approval = require_string(resource["approval_public_key_id"], KEY_ID, "approval key ID")
    denial = require_string(resource["denial_public_key_id"], KEY_ID, "denial key ID")
    if approval == denial:
        raise ManifestError("approval and denial key IDs must differ")
    for field in ("scenario_payload_hash", "request_context_digest"):
        require_string(resource[field], HEX_64, field)
    for field in ("request_id", "nonce"):
        require_string(resource[field], re.compile(r"[A-Za-z0-9_-]{16,128}"), field)
    return {
        "resource": "test_approval_profile",
        "target": profile_id,
        "cleanup": "revoke exactly both recorded public key IDs and remove this disposable profile",
        "verify": "profile and both exact public key IDs are absent from target trust",
    }


def validate_account(resource, run_id):
    exact_keys(resource, ("type", "name"), "linux_test_account")
    name = resource["name"]
    if name != f"syn-e2e-{run_token(run_id)}-pam":
        raise ManifestError("Linux test account must be derived from the manifest run ID")
    return {
        "resource": "linux_test_account",
        "target": name,
        "cleanup": "delete exactly this test account and its owned home after its test units are absent",
        "verify": "account and its exact home are absent; unrelated accounts are unchanged",
    }


def validate_unit(resource, run_id):
    exact_keys(resource, ("type", "name"), "linux_test_unit")
    name = resource["name"]
    if name != f"syn-e2e-{run_token(run_id)}-recovery.timer":
        raise ManifestError("Linux test unit must be derived from the manifest run ID")
    return {
        "resource": "linux_test_unit",
        "target": name,
        "cleanup": "stop, disable, and remove exactly this test unit, then reload systemd",
        "verify": "the exact unit is absent and inactive; no production Syn unit changed",
    }


VALIDATORS = {
    "source_directory": validate_source,
    "test_approval_profile": validate_profile,
    "linux_test_account": validate_account,
    "linux_test_unit": validate_unit,
}


def validate_manifest(value):
    exact_keys(value, ("schema_version", "run_id", "host", "resources"), "manifest")
    if value["schema_version"] != 1 or isinstance(value["schema_version"], bool):
        raise ManifestError("schema_version must be 1")
    require_string(value["run_id"], RUN_ID, "run ID")
    if value["host"] != "pi":
        raise ManifestError("host must be the configured SSH alias pi")
    resources = value["resources"]
    if not isinstance(resources, list) or not resources:
        raise ManifestError("resources must be a non-empty list")
    plan = []
    seen = set()
    for resource in resources:
        if not isinstance(resource, dict) or resource.get("type") not in SUPPORTED_TYPES:
            raise ManifestError("unsupported resource type")
        item = VALIDATORS[resource["type"]](resource, value["run_id"])
        identity = (item["resource"], item["target"])
        if identity in seen:
            raise ManifestError("duplicate resource")
        seen.add(identity)
        plan.append(item)
    order = {"linux_test_unit": 0, "test_approval_profile": 1,
             "linux_test_account": 2, "source_directory": 3}
    plan.sort(key=lambda item: (order[item["resource"]], item["target"]))
    return {"ok": True, "dry_run": True, "run_id": value["run_id"], "cleanup_plan": plan}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=argparse.FileType("r", encoding="utf-8"))
    args = parser.parse_args()
    try:
        value = json.load(args.manifest)
        result = validate_manifest(value)
    except (OSError, json.JSONDecodeError, ManifestError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
