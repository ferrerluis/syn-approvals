#!/usr/bin/env python3
"""Create and verify Syn release metadata without accessing the network."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


RELEASE_ID = re.compile(r"^[0-9]{14}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
MAC_BUILD_VERSION = re.compile(
    r"^([1-9][0-9]{0,3})\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$"
)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_RELEASE_METADATA_BYTES = 16 * 1024
MAX_CARGO_CONFIG_BYTES = 64 * 1024


class MetadataError(ValueError):
    pass


def fail(message: str) -> None:
    raise MetadataError(message)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read valid JSON from {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        fail(f"refusing to replace existing metadata: {path}")
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def validate_release_id(value: Any) -> str:
    if not isinstance(value, str) or not RELEASE_ID.fullmatch(value):
        fail("release_id must be 14 UTC digits in YYYYMMDDHHMMSS form")
    try:
        parsed = dt.datetime.strptime(value, "%Y%m%d%H%M%S")
    except ValueError as error:
        fail(f"release_id is not a real UTC date: {error}")
    if parsed.year < 2026:
        fail("release_id predates Syn's timestamp release scheme")
    return value


def validate_commit(value: Any) -> str:
    if not isinstance(value, str) or not COMMIT.fullmatch(value):
        fail("commit must be a full lowercase 40-character Git SHA-1")
    return value


def validate_mac_build_version(value: str) -> str:
    match = MAC_BUILD_VERSION.fullmatch(value)
    if match is None:
        fail("Mac build version must be three numeric components with 4.2.2 digit limits")
    if any(int(component) > 99 for component in match.groups()[1:]):
        fail("Mac build version components exceed Apple's documented limits")
    return value


def validate_release(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {"schema_version", "release_id", "commit"}:
        fail("release metadata has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        fail("unsupported release metadata schema")
    validate_release_id(value["release_id"])
    validate_commit(value["commit"])
    return value


def file_record(path: Path, kind: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"artifact must be a regular file: {path}")
    if not ARTIFACT_NAME.fullmatch(path.name):
        fail(f"unsafe artifact name: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "kind": kind,
        "name": path.name,
        "sha256": digest.hexdigest(),
        "size_bytes": path.stat().st_size,
    }


def sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as value:
        for block in iter(lambda: value.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_sha256(value: str, label: str = "sha256") -> str:
    if not SHA256.fullmatch(value):
        fail(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def checked_process(arguments: list[str], *, output_limit: int = 16 * 1024) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"release verification command failed: {error}")
    if result.returncode != 0:
        fail("release verification command failed")
    if len(result.stdout) > output_limit or len(result.stderr) > output_limit:
        fail("release verification command returned too much output")
    return result


def verify_macos_signature(app: Path, expected_signer_sha256: str) -> None:
    expected = validate_sha256(expected_signer_sha256, "expected signer sha256")
    if app.is_symlink() or not app.is_dir():
        fail("Mac release app must be a real directory")
    checked_process(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(app)])
    details = checked_process(["/usr/bin/codesign", "-d", "--verbose=4", str(app)])
    diagnostic = details.stderr + details.stdout
    if b"Signature=adhoc" in diagnostic or b"(runtime)" not in diagnostic:
        fail("Mac release app requires non-ad-hoc hardened-runtime signing")
    with tempfile.TemporaryDirectory(prefix="syn-codesign-cert-") as temporary:
        prefix = Path(temporary) / "signer"
        checked_process([
            "/usr/bin/codesign", "-d", "--extract-certificates", str(prefix), str(app)
        ])
        leaf = Path(f"{prefix}0")
        if leaf.is_symlink() or not leaf.is_file() or leaf.stat().st_size > 1024 * 1024:
            fail("codesign did not produce a bounded leaf certificate")
        if sha256_hex(leaf) != expected:
            fail("Mac release signer does not match the expected certificate")


def validate_artifact(value: Any, expected_kind: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "kind",
        "name",
        "sha256",
        "size_bytes",
    }:
        fail("artifact descriptor has missing or unknown fields")
    if expected_kind is not None and value["kind"] != expected_kind:
        fail(f"expected {expected_kind} artifact")
    if value["kind"] not in {"mac_app", "remote_source", "remote_helper"}:
        fail("unknown artifact kind")
    if not isinstance(value["name"], str) or not ARTIFACT_NAME.fullmatch(value["name"]):
        fail("artifact name is unsafe")
    if not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"]):
        fail("artifact sha256 must be 64 lowercase hexadecimal characters")
    if type(value["size_bytes"]) is not int or not 0 < value["size_bytes"] <= MAX_ARCHIVE_EXPANDED_BYTES:
        fail("artifact size_bytes must be between 1 byte and 2 GiB")
    return value


def validate_remote_source(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {"schema_version", "release_id", "commit", "artifact"}:
        fail("remote-source metadata has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        fail("unsupported remote-source metadata schema")
    validate_release_id(value["release_id"])
    validate_commit(value["commit"])
    validate_artifact(value["artifact"], "remote_source")
    return value


def validate_remote_helper(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {"schema_version", "release_id", "commit", "artifact"}:
        fail("remote-helper metadata has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        fail("unsupported remote-helper metadata schema")
    validate_release_id(value["release_id"])
    validate_commit(value["commit"])
    validate_artifact(value["artifact"], "remote_helper")
    return value


def matching_identity(release: dict[str, Any], other: dict[str, Any]) -> None:
    if other["release_id"] != release["release_id"] or other["commit"] != release["commit"]:
        fail("release ID or commit differs between metadata files")


def require_newer_release(candidate: dict[str, Any], previous: dict[str, Any]) -> None:
    """Refuse both a rollback and reuse of the current published identity."""
    if candidate["release_id"] <= previous["release_id"]:
        fail("candidate release ID must be newer than the published latest release")


def verify_record(record: dict[str, Any], path: Path) -> None:
    actual = file_record(path, record["kind"])
    if actual != record:
        fail(f"artifact does not match its descriptor: {path}")


def validate_index(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {"schema_version", "release_id", "commit", "artifacts"}:
        fail("release index has missing or unknown fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        fail("unsupported release index schema")
    validate_release_id(value["release_id"])
    validate_commit(value["commit"])
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        fail("release index must contain exactly the Mac and remote-source artifacts")
    validated = [validate_artifact(item) for item in artifacts]
    if {item["kind"] for item in validated} != {"mac_app", "remote_source"}:
        fail("release index must contain one artifact of each kind")
    if len({item["name"] for item in validated}) != 2:
        fail("release artifact names must be unique")
    return value


def command_create(args: argparse.Namespace) -> None:
    release = {
        "schema_version": 1,
        "release_id": validate_release_id(args.release_id),
        "commit": validate_commit(args.commit),
    }
    write_new_json(args.output, release)


def command_validate(args: argparse.Namespace) -> None:
    validate_release(read_json(args.metadata))


def command_verify_macos_signature(args: argparse.Namespace) -> None:
    verify_macos_signature(args.app, args.expected_signer_sha256)


def git_output(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot inspect release checkout: {error}")
    if result.returncode != 0:
        fail("cannot inspect release checkout")
    return result.stdout


def command_verify_checkout(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    head = git_output(args.repository, "rev-parse", "HEAD").strip()
    if head != release["commit"]:
        fail("release metadata commit does not match the checked-out commit")
    status = git_output(
        args.repository, "status", "--porcelain=v1", "--untracked-files=all"
    )
    if status:
        fail("release checkout has tracked or untracked changes")
    source_inputs: list[str] = []
    for path in args.source_input:
        if path.is_absolute() or not path.parts or ".." in path.parts:
            fail("source input paths must stay within the release checkout")
        source_inputs.append(path.as_posix())
    if source_inputs:
        ignored = git_output(
            args.repository,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            *source_inputs,
        )
        if ignored:
            fail("release checkout has ignored files in a build input")


def command_validate_mac_build(args: argparse.Namespace) -> None:
    print(validate_mac_build_version(args.value))


def command_get(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    print(release[args.field])


def command_create_remote_source(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    value = {
        **release,
        "artifact": file_record(args.artifact, "remote_source"),
    }
    write_new_json(args.output, value)


def command_validate_remote_source(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    remote = validate_remote_source(read_json(args.remote_source))
    matching_identity(release, remote)
    if args.artifact is not None:
        verify_record(remote["artifact"], args.artifact)


def command_create_remote_helper(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    value = {
        **release,
        "artifact": file_record(args.artifact, "remote_helper"),
    }
    write_new_json(args.output, value)


def command_validate_remote_helper(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    helper = validate_remote_helper(read_json(args.remote_helper))
    matching_identity(release, helper)
    if args.artifact is not None:
        verify_record(helper["artifact"], args.artifact)


def command_require_newer(args: argparse.Namespace) -> None:
    candidate = validate_release(read_json(args.candidate))
    previous = validate_release(read_json(args.previous))
    require_newer_release(candidate, previous)


def add_archive_member_to_limits(count: int, expanded_bytes: int, member: Any) -> tuple[int, int]:
    count += 1
    if count > MAX_ARCHIVE_MEMBERS:
        fail("source archive contains too many entries")
    if member.isfile():
        if type(member.size) is not int or member.size < 0:
            fail("source archive contains an invalid file size")
        expanded_bytes += member.size
        if expanded_bytes > MAX_ARCHIVE_EXPANDED_BYTES:
            fail("source archive expands beyond its supported size")
    return count, expanded_bytes


def read_archive_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size > limit:
        fail(f"source archive metadata exceeds {limit} bytes")
    extracted = archive.extractfile(member)
    if extracted is None:
        fail("source archive metadata cannot be read")
    value = extracted.read(limit + 1)
    if len(value) > limit:
        fail(f"source archive metadata exceeds {limit} bytes")
    return value


def command_verify_source_archive(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    remote = validate_remote_source(read_json(args.remote_source))
    matching_identity(release, remote)
    verify_record(remote["artifact"], args.artifact)
    expected_root = f"syn-remote-source-{release['release_id']}"
    required = {
        f"{expected_root}/Cargo.lock",
        f"{expected_root}/Cargo.toml",
        f"{expected_root}/.cargo/config.toml",
        f"{expected_root}/release/release.json",
        f"{expected_root}/scripts/build-deb.sh",
    }
    names: set[str] = set()
    vendor_checksum = False
    release_member: tarfile.TarInfo | None = None
    config_member: tarfile.TarInfo | None = None
    member_count = 0
    expanded_bytes = 0
    try:
        with tarfile.open(args.artifact, mode="r:gz") as archive:
            for member in archive:
                member_count, expanded_bytes = add_archive_member_to_limits(
                    member_count, expanded_bytes, member
                )
                path = Path(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or path.parts[0] != expected_root
                ):
                    fail("source archive contains a path outside its release root")
                if not (member.isfile() or member.isdir()):
                    fail("source archive contains a link or special file")
                normalized_name = member.name.rstrip("/")
                if normalized_name in names:
                    fail("source archive contains duplicate paths")
                names.add(normalized_name)
                if member.name.startswith(f"{expected_root}/vendor/") and member.name.endswith(
                    "/.cargo-checksum.json"
                ):
                    vendor_checksum = True
                if normalized_name == f"{expected_root}/release/release.json":
                    release_member = member
                if normalized_name == f"{expected_root}/.cargo/config.toml":
                    config_member = member
            missing = required - names
            if missing:
                fail(f"source archive is missing required files: {sorted(missing)}")
            if not vendor_checksum:
                fail("source archive has no checksummed vendored crate")
            if release_member is None or config_member is None:
                fail("source archive metadata cannot be read")
            archived_release = json.loads(
                read_archive_member(
                    archive, release_member, MAX_RELEASE_METADATA_BYTES
                ).decode("utf-8")
            )
            if not isinstance(archived_release, dict):
                fail("source archive release metadata must be an object")
            if validate_release(archived_release) != release:
                fail("source archive release identity does not match")
            cargo_config = read_archive_member(
                archive, config_member, MAX_CARGO_CONFIG_BYTES
            ).decode("utf-8")
            if (
                '[source.crates-io]' not in cargo_config
                or 'replace-with = "vendored-sources"' not in cargo_config
                or '[source.vendored-sources]' not in cargo_config
                or 'directory = "vendor"' not in cargo_config
            ):
                fail("source archive is not configured for the vendored Cargo source")
    except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot inspect remote source archive: {error}")


def command_create_index(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    remote = validate_remote_source(read_json(args.remote_source))
    matching_identity(release, remote)
    verify_record(remote["artifact"], args.source)
    mac = file_record(args.mac, "mac_app")
    value = {
        **release,
        "artifacts": [mac, remote["artifact"]],
    }
    write_new_json(args.output, value)


def command_verify_index(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    index = validate_index(read_json(args.index))
    matching_identity(release, index)
    by_kind = {item["kind"]: item for item in index["artifacts"]}
    verify_record(by_kind["mac_app"], args.mac)
    verify_record(by_kind["remote_source"], args.source)


def command_create_channel(args: argparse.Namespace) -> None:
    release = validate_release(read_json(args.metadata))
    index = validate_index(read_json(args.index))
    matching_identity(release, index)
    if not REPOSITORY.fullmatch(args.repository):
        fail("repository must be an owner/name pair")
    expected_tag = f"experimental-{release['commit']}"
    if args.release_tag != expected_tag:
        fail("experimental release tag must contain the exact commit")
    artifacts = {item["kind"]: item for item in index["artifacts"]}
    base = f"https://github.com/{args.repository}/releases/download/{args.release_tag}"
    value = {
        "schema_version": 1,
        "channel": "latest-experimental",
        "release_id": release["release_id"],
        "commit": release["commit"],
        "release_tag": args.release_tag,
        "release_page": f"https://github.com/{args.repository}/releases/tag/{args.release_tag}",
        "downloads": {
            "mac_app": f"{base}/{artifacts['mac_app']['name']}",
            "remote_source": f"{base}/{artifacts['remote_source']['name']}",
        },
        "release_index": {
            "name": args.index.name,
            "sha256": sha256_hex(args.index),
        },
    }
    write_new_json(args.output, value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create")
    create.add_argument("--release-id", required=True)
    create.add_argument("--commit", required=True)
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(function=command_create)

    validate = commands.add_parser("validate")
    validate.add_argument("--metadata", type=Path, required=True)
    validate.set_defaults(function=command_validate)

    mac_signature = commands.add_parser("verify-macos-signature")
    mac_signature.add_argument("--app", type=Path, required=True)
    mac_signature.add_argument("--expected-signer-sha256", required=True)
    mac_signature.set_defaults(function=command_verify_macos_signature)

    checkout = commands.add_parser("verify-checkout")
    checkout.add_argument("--metadata", type=Path, required=True)
    checkout.add_argument("--repository", type=Path, required=True)
    checkout.add_argument("--source-input", type=Path, action="append", default=[])
    checkout.set_defaults(function=command_verify_checkout)

    mac_build = commands.add_parser("validate-mac-build")
    mac_build.add_argument("--value", required=True)
    mac_build.set_defaults(function=command_validate_mac_build)

    get = commands.add_parser("get")
    get.add_argument("--metadata", type=Path, required=True)
    get.add_argument("--field", choices=("release_id", "commit"), required=True)
    get.set_defaults(function=command_get)

    remote = commands.add_parser("create-remote-source")
    remote.add_argument("--metadata", type=Path, required=True)
    remote.add_argument("--artifact", type=Path, required=True)
    remote.add_argument("--output", type=Path, required=True)
    remote.set_defaults(function=command_create_remote_source)

    validate_remote = commands.add_parser("validate-remote-source")
    validate_remote.add_argument("--metadata", type=Path, required=True)
    validate_remote.add_argument("--remote-source", type=Path, required=True)
    validate_remote.add_argument("--artifact", type=Path)
    validate_remote.set_defaults(function=command_validate_remote_source)

    helper = commands.add_parser("create-remote-helper")
    helper.add_argument("--metadata", type=Path, required=True)
    helper.add_argument("--artifact", type=Path, required=True)
    helper.add_argument("--output", type=Path, required=True)
    helper.set_defaults(function=command_create_remote_helper)

    validate_helper = commands.add_parser("validate-remote-helper")
    validate_helper.add_argument("--metadata", type=Path, required=True)
    validate_helper.add_argument("--remote-helper", type=Path, required=True)
    validate_helper.add_argument("--artifact", type=Path)
    validate_helper.set_defaults(function=command_validate_remote_helper)

    newer = commands.add_parser("require-newer")
    newer.add_argument("--candidate", type=Path, required=True)
    newer.add_argument("--previous", type=Path, required=True)
    newer.set_defaults(function=command_require_newer)

    verify_source = commands.add_parser("verify-source-archive")
    verify_source.add_argument("--metadata", type=Path, required=True)
    verify_source.add_argument("--remote-source", type=Path, required=True)
    verify_source.add_argument("--artifact", type=Path, required=True)
    verify_source.set_defaults(function=command_verify_source_archive)

    index = commands.add_parser("create-index")
    index.add_argument("--metadata", type=Path, required=True)
    index.add_argument("--remote-source", type=Path, required=True)
    index.add_argument("--source", type=Path, required=True)
    index.add_argument("--mac", type=Path, required=True)
    index.add_argument("--output", type=Path, required=True)
    index.set_defaults(function=command_create_index)

    verify = commands.add_parser("verify-index")
    verify.add_argument("--metadata", type=Path, required=True)
    verify.add_argument("--index", type=Path, required=True)
    verify.add_argument("--source", type=Path, required=True)
    verify.add_argument("--mac", type=Path, required=True)
    verify.set_defaults(function=command_verify_index)

    channel = commands.add_parser("create-channel")
    channel.add_argument("--metadata", type=Path, required=True)
    channel.add_argument("--index", type=Path, required=True)
    channel.add_argument("--repository", required=True)
    channel.add_argument("--release-tag", required=True)
    channel.add_argument("--output", type=Path, required=True)
    channel.set_defaults(function=command_create_channel)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        args.function(args)
    except MetadataError as error:
        print(f"release-tool: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
