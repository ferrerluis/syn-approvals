#!/usr/bin/env python3

import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1]
TOOL = SCRIPTS / "release-tool.py"
MAC_BUILD_SCRIPT = SCRIPTS / "build-macos-app.sh"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RELEASE_ID = "20260905143022"

SPEC = importlib.util.spec_from_file_location("release_tool", TOOL)
assert SPEC is not None and SPEC.loader is not None
RELEASE_TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_TOOL)


class ReleaseToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_tool(self, *arguments: str, succeeds: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["python3", str(TOOL), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def create_metadata(self) -> Path:
        path = self.root / "release.json"
        self.run_tool(
            "create",
            "--release-id", RELEASE_ID,
            "--commit", COMMIT,
            "--output", str(path),
        )
        return path

    def test_metadata_is_strict_and_cannot_be_replaced(self) -> None:
        path = self.create_metadata()
        self.assertEqual(
            json.loads(path.read_text()),
            {"schema_version": 1, "release_id": RELEASE_ID, "commit": COMMIT},
        )
        self.run_tool("validate", "--metadata", str(path))
        self.run_tool(
            "create",
            "--release-id", RELEASE_ID,
            "--commit", COMMIT,
            "--output", str(path),
            succeeds=False,
        )

        path.unlink()
        path.write_text(json.dumps({"schema_version": True, "release_id": RELEASE_ID, "commit": COMMIT}))
        self.run_tool("validate", "--metadata", str(path), succeeds=False)

    def test_invalid_dates_and_commits_fail(self) -> None:
        for release_id in ("2026090514302", "20261305143022", "20260230000000"):
            self.run_tool(
                "create", "--release-id", release_id, "--commit", COMMIT,
                "--output", str(self.root / release_id), succeeds=False,
            )
        self.run_tool(
            "create", "--release-id", RELEASE_ID, "--commit", COMMIT.upper(),
            "--output", str(self.root / "uppercase"), succeeds=False,
        )

    def test_mac_build_number_obeys_apple_component_limits(self) -> None:
        self.run_tool("validate-mac-build", "--value", "123.4.0")
        for value in (
            "0.1.0", "10000.1.0", "1.100.0", "1.01.0", "1.1", "20260905143022",
        ):
            self.run_tool("validate-mac-build", "--value", value, succeeds=False)

    def test_signed_app_source_descriptor_binds_identity_and_bytes(self) -> None:
        metadata = self.create_metadata()
        source = self.root / f"syn-remote-source-{RELEASE_ID}.tar.gz"
        source.write_bytes(b"verified vendored source")
        descriptor = self.root / "remote-source.json"
        self.run_tool(
            "create-remote-source", "--metadata", str(metadata),
            "--artifact", str(source), "--output", str(descriptor),
        )
        self.run_tool(
            "validate-remote-source", "--metadata", str(metadata),
            "--remote-source", str(descriptor), "--artifact", str(source),
        )
        source.write_bytes(b"tampered")
        self.run_tool(
            "validate-remote-source", "--metadata", str(metadata),
            "--remote-source", str(descriptor), "--artifact", str(source),
            succeeds=False,
        )
        value = json.loads(descriptor.read_text())
        value["artifact"]["size_bytes"] = True
        descriptor.write_text(json.dumps(value))
        self.run_tool(
            "validate-remote-source", "--metadata", str(metadata),
            "--remote-source", str(descriptor), succeeds=False,
        )

    def test_candidate_release_must_be_strictly_newer_than_published_latest(self) -> None:
        candidate = self.create_metadata()
        older = self.root / "older.json"
        self.run_tool(
            "create", "--release-id", "20260905143021", "--commit", "1" * 40,
            "--output", str(older),
        )
        self.run_tool(
            "require-newer", "--candidate", str(candidate), "--previous", str(older),
        )

        equal = self.root / "equal.json"
        self.run_tool(
            "create", "--release-id", RELEASE_ID, "--commit", "2" * 40,
            "--output", str(equal),
        )
        self.run_tool(
            "require-newer", "--candidate", str(candidate), "--previous", str(equal),
            succeeds=False,
        )

        newer = self.root / "newer.json"
        self.run_tool(
            "create", "--release-id", "20260905143023", "--commit", "3" * 40,
            "--output", str(newer),
        )
        self.run_tool(
            "require-newer", "--candidate", str(candidate), "--previous", str(newer),
            succeeds=False,
        )

    def test_remote_helper_descriptor_binds_identity_kind_and_exact_bytes(self) -> None:
        metadata = self.create_metadata()
        helper = self.root / f"synctl-arm64-{RELEASE_ID}"
        helper.write_bytes(b"verified ARM64 bootstrap helper")
        descriptor = self.root / "remote-helper.json"
        self.run_tool(
            "create-remote-helper", "--metadata", str(metadata),
            "--artifact", str(helper), "--output", str(descriptor),
        )
        self.run_tool(
            "validate-remote-helper", "--metadata", str(metadata),
            "--remote-helper", str(descriptor), "--artifact", str(helper),
        )
        value = json.loads(descriptor.read_text())
        self.assertEqual(value["artifact"]["kind"], "remote_helper")
        helper.write_bytes(b"tampered helper")
        self.run_tool(
            "validate-remote-helper", "--metadata", str(metadata),
            "--remote-helper", str(descriptor), "--artifact", str(helper), succeeds=False,
        )

    def test_source_archive_expansion_limits_are_enforced(self) -> None:
        class FakeMember:
            size = 1

            @staticmethod
            def isfile() -> bool:
                return True

        with self.assertRaises(RELEASE_TOOL.MetadataError):
            RELEASE_TOOL.add_archive_member_to_limits(
                RELEASE_TOOL.MAX_ARCHIVE_MEMBERS, 0, FakeMember()
            )
        FakeMember.size = RELEASE_TOOL.MAX_ARCHIVE_EXPANDED_BYTES + 1
        with self.assertRaises(RELEASE_TOOL.MetadataError):
            RELEASE_TOOL.add_archive_member_to_limits(0, 0, FakeMember())

    def test_release_index_requires_exactly_matching_artifacts(self) -> None:
        metadata = self.create_metadata()
        source = self.root / f"syn-remote-source-{RELEASE_ID}.tar.gz"
        source.write_bytes(b"source")
        mac = self.root / f"Syn-macOS-{RELEASE_ID}.zip"
        mac.write_bytes(b"signed app archive")
        descriptor = self.root / "remote-source.json"
        index = self.root / "release-index.json"
        self.run_tool(
            "create-remote-source", "--metadata", str(metadata),
            "--artifact", str(source), "--output", str(descriptor),
        )
        self.run_tool(
            "create-index", "--metadata", str(metadata),
            "--remote-source", str(descriptor), "--source", str(source),
            "--mac", str(mac), "--output", str(index),
        )
        self.run_tool(
            "verify-index", "--metadata", str(metadata), "--index", str(index),
            "--source", str(source), "--mac", str(mac),
        )
        value = json.loads(index.read_text())
        value["commit"] = "f" * 40
        index.write_text(json.dumps(value))
        self.run_tool(
            "verify-index", "--metadata", str(metadata), "--index", str(index),
            "--source", str(source), "--mac", str(mac), succeeds=False,
        )

    def test_artifact_size_limit_matches_the_mac_verifier(self) -> None:
        record = {"kind": "remote_source", "name": "source.tar.gz", "sha256": "a" * 64,
                  "size_bytes": 2 * 1024 * 1024 * 1024}
        RELEASE_TOOL.validate_artifact(record, "remote_source")
        with self.assertRaises(RELEASE_TOOL.MetadataError):
            RELEASE_TOOL.validate_artifact({**record, "size_bytes": record["size_bytes"] + 1}, "remote_source")

    def test_source_archive_requires_safe_vendored_exact_release(self) -> None:
        metadata = self.create_metadata()
        source_root = self.root / f"syn-remote-source-{RELEASE_ID}"
        for relative in (
            "release", ".cargo", "scripts", "vendor/example-1.0.0",
        ):
            (source_root / relative).mkdir(parents=True, exist_ok=True)
        (source_root / "Cargo.toml").write_text("[workspace]\n")
        (source_root / "Cargo.lock").write_text("version = 3\n")
        (source_root / "scripts/build-deb.sh").write_text("#!/bin/sh\n")
        (source_root / "release/release.json").write_bytes(metadata.read_bytes())
        (source_root / "vendor/example-1.0.0/.cargo-checksum.json").write_text("{}\n")
        (source_root / ".cargo/config.toml").write_text(
            '[source.crates-io]\nreplace-with = "vendored-sources"\n'
            '[source.vendored-sources]\ndirectory = "vendor"\n'
        )
        archive = self.root / f"syn-remote-source-{RELEASE_ID}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(source_root, arcname=source_root.name)
        descriptor = self.root / "remote-source.json"
        self.run_tool(
            "create-remote-source", "--metadata", str(metadata),
            "--artifact", str(archive), "--output", str(descriptor),
        )
        self.run_tool(
            "verify-source-archive", "--metadata", str(metadata),
            "--remote-source", str(descriptor), "--artifact", str(archive),
        )

        unsafe = self.root / "unsafe.tar.gz"
        payload = self.root / "payload"
        payload.write_text("unsafe")
        with tarfile.open(unsafe, "w:gz") as output:
            output.add(payload, arcname=f"{source_root.name}/../outside")
        unsafe_descriptor = self.root / "unsafe-source.json"
        self.run_tool(
            "create-remote-source", "--metadata", str(metadata),
            "--artifact", str(unsafe), "--output", str(unsafe_descriptor),
        )
        self.run_tool(
            "verify-source-archive", "--metadata", str(metadata),
            "--remote-source", str(unsafe_descriptor), "--artifact", str(unsafe),
            succeeds=False,
        )

    def test_latest_channel_points_to_immutable_commit_release(self) -> None:
        metadata = self.create_metadata()
        source = self.root / f"syn-remote-source-{RELEASE_ID}.tar.gz"
        source.write_bytes(b"source")
        mac = self.root / f"Syn-macOS-{RELEASE_ID}.zip"
        mac.write_bytes(b"signed app archive")
        descriptor = self.root / "remote-source.json"
        index = self.root / "release-index.json"
        channel = self.root / "latest-experimental.json"
        self.run_tool(
            "create-remote-source", "--metadata", str(metadata),
            "--artifact", str(source), "--output", str(descriptor),
        )
        self.run_tool(
            "create-index", "--metadata", str(metadata),
            "--remote-source", str(descriptor), "--source", str(source),
            "--mac", str(mac), "--output", str(index),
        )
        tag = f"experimental-{COMMIT}"
        self.run_tool(
            "create-channel", "--metadata", str(metadata), "--index", str(index),
            "--repository", "ferrerluis/syn-approvals", "--release-tag", tag,
            "--output", str(channel),
        )
        value = json.loads(channel.read_text())
        self.assertEqual(value["release_tag"], tag)
        self.assertIn(tag, value["downloads"]["mac_app"])
        self.run_tool(
            "create-channel", "--metadata", str(metadata), "--index", str(index),
            "--repository", "ferrerluis/syn-approvals", "--release-tag", "latest",
            "--output", str(self.root / "bad-channel.json"), succeeds=False,
        )

    def test_release_build_refuses_ad_hoc_mac_signing(self) -> None:
        metadata = self.create_metadata()
        source = self.root / f"syn-remote-source-{RELEASE_ID}.tar.gz"
        source.write_bytes(b"source")
        descriptor = self.root / "remote-source.json"
        self.run_tool(
            "create-remote-source", "--metadata", str(metadata),
            "--artifact", str(source), "--output", str(descriptor),
        )
        helper = self.root / f"synctl-arm64-{RELEASE_ID}"
        helper.write_bytes(b"helper")
        helper_descriptor = self.root / "remote-helper.json"
        self.run_tool(
            "create-remote-helper", "--metadata", str(metadata),
            "--artifact", str(helper), "--output", str(helper_descriptor),
        )
        environment = os.environ.copy()
        environment.update(
            {
                "SYN_RELEASE_MODE": "1",
                "SYN_RELEASE_METADATA": str(metadata),
                "SYN_REMOTE_SOURCE_METADATA": str(descriptor),
                "SYN_REMOTE_SOURCE_ARCHIVE": str(source),
                "SYN_REMOTE_HELPER_METADATA": str(helper_descriptor),
                "SYN_REMOTE_HELPER_BINARY": str(helper),
                "SYN_MAC_BUILD_NUMBER": "1.0.0",
                "SYN_CODESIGN_IDENTITY": "-",
                "SYN_EXPECTED_SIGNER_SHA256": "0" * 64,
            }
        )
        result = subprocess.run(
            [str(MAC_BUILD_SCRIPT), str(self.root / "mac")],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refuses ad-hoc signing", result.stderr)

    def test_release_checkout_must_match_commit_and_be_clean(self) -> None:
        repository = self.root / "checkout"
        sources = repository / "macos" / "Sources" / "Syn"
        sources.mkdir(parents=True)
        self.git(repository, "init", "--quiet")
        tracked = repository / "tracked.txt"
        tracked.write_text("committed\n")
        (sources / "tracked.swift").write_text("// tracked\n")
        (repository / ".gitignore").write_text("macos/Sources/Syn/ignored.swift\n")
        self.git(repository, "add", "tracked.txt", ".gitignore", "macos/Sources/Syn/tracked.swift")
        self.git(
            repository, "-c", "user.name=Syn Test", "-c", "user.email=syn@example.invalid",
            "-c", "commit.gpgsign=false",
            "commit", "--quiet", "-m", "fixture",
        )
        head = self.git(repository, "rev-parse", "HEAD").stdout.strip()
        metadata = self.root / "checkout-release.json"
        self.run_tool(
            "create", "--release-id", RELEASE_ID, "--commit", head,
            "--output", str(metadata),
        )
        checkout_arguments = (
            "verify-checkout", "--metadata", str(metadata), "--repository", str(repository),
            "--source-input", "macos/Sources/Syn",
        )
        self.run_tool(*checkout_arguments)

        tracked.write_text("dirty\n")
        self.run_tool(
            *checkout_arguments,
            succeeds=False,
        )
        tracked.write_text("committed\n")
        untracked = repository / "untracked.swift"
        untracked.write_text("unexpected build input\n")
        self.run_tool(
            *checkout_arguments,
            succeeds=False,
        )
        untracked.unlink()

        ignored = sources / "ignored.swift"
        ignored.write_text("// ignored build input\n")
        self.assertEqual(self.git(repository, "status", "--porcelain=v1").stdout, "")
        self.run_tool(*checkout_arguments, succeeds=False)
        ignored.unlink()

        wrong = self.root / "wrong-checkout-release.json"
        self.run_tool(
            "create", "--release-id", RELEASE_ID, "--commit", COMMIT,
            "--output", str(wrong),
        )
        self.run_tool(
            "verify-checkout", "--metadata", str(wrong), "--repository", str(repository),
            "--source-input", "macos/Sources/Syn",
            succeeds=False,
        )

    def test_mac_release_build_checks_actual_source_bytes_before_building(self) -> None:
        repository = self.root / "mac-release-repository"
        scripts = repository / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(MAC_BUILD_SCRIPT, scripts / MAC_BUILD_SCRIPT.name)
        shutil.copy2(TOOL, scripts / TOOL.name)
        self.git(repository, "init", "--quiet")
        self.git(repository, "add", "scripts")
        self.git(
            repository, "-c", "user.name=Syn Test", "-c", "user.email=syn@example.invalid",
            "-c", "commit.gpgsign=false",
            "commit", "--quiet", "-m", "fixture",
        )
        head = self.git(repository, "rev-parse", "HEAD").stdout.strip()
        metadata = self.root / "mac-release.json"
        self.run_tool(
            "create", "--release-id", RELEASE_ID, "--commit", head,
            "--output", str(metadata),
        )
        source = self.root / f"syn-remote-source-{RELEASE_ID}.tar.gz"
        source.write_bytes(b"expected source bytes")
        descriptor = self.root / "mac-remote-source.json"
        self.run_tool(
            "create-remote-source", "--metadata", str(metadata),
            "--artifact", str(source), "--output", str(descriptor),
        )
        helper = self.root / f"synctl-arm64-{RELEASE_ID}"
        helper.write_bytes(b"helper")
        helper_descriptor = self.root / "mac-remote-helper.json"
        self.run_tool(
            "create-remote-helper", "--metadata", str(metadata),
            "--artifact", str(helper), "--output", str(helper_descriptor),
        )
        source.write_bytes(b"tampered source bytes")
        environment = os.environ.copy()
        environment.update(
            {
                "SYN_RELEASE_MODE": "1",
                "SYN_RELEASE_METADATA": str(metadata),
                "SYN_REMOTE_SOURCE_METADATA": str(descriptor),
                "SYN_REMOTE_SOURCE_ARCHIVE": str(source),
                "SYN_REMOTE_HELPER_METADATA": str(helper_descriptor),
                "SYN_REMOTE_HELPER_BINARY": str(helper),
                "SYN_MAC_BUILD_NUMBER": "1.0.0",
                "SYN_CODESIGN_IDENTITY": "test-non-adhoc-identity",
                "SYN_EXPECTED_SIGNER_SHA256": "0" * 64,
            }
        )
        result = subprocess.run(
            [str(scripts / MAC_BUILD_SCRIPT.name), str(self.root / "mac-output")],
            env=environment, text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact does not match its descriptor", result.stderr)
        self.assertFalse((repository / "macos" / ".build").exists())

        app_resources = self.root / "Syn.app" / "Contents" / "Resources"
        app_resources.mkdir(parents=True)
        shutil.copy2(metadata, app_resources / "release.json")
        shutil.copy2(descriptor, app_resources / "remote-source.json")
        shutil.copy2(source, app_resources / source.name)
        shutil.copy2(helper_descriptor, app_resources / "remote-helper.json")
        shutil.copy2(helper, app_resources / helper.name)
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_codesign = fake_bin / "codesign"
        fake_codesign.write_text(
            "#!/bin/sh\n"
            "case \" $* \" in\n"
            "  *\" -d \"*) printf '%s\\n' 'Signature=adhoc' >&2 ;;\n"
            "esac\n"
        )
        fake_codesign.chmod(0o755)
        package_environment = os.environ.copy()
        package_environment.update(
            {
                "PATH": f"{fake_bin}:{package_environment['PATH']}",
                "SYN_ALLOW_ADHOC_PACKAGE_TEST": "1",
            }
        )
        package_result = subprocess.run(
            [
                str(SCRIPTS / "package-macos-release.sh"),
                str(self.root / "Syn.app"),
                str(metadata),
                str(source),
                str(helper),
                str(self.root / "packaged"),
            ],
            env=package_environment, text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(package_result.returncode, 0)
        self.assertIn("artifact does not match its descriptor", package_result.stderr)
        self.assertFalse((self.root / "packaged").exists())

    def test_expected_macos_signer_is_exact_and_temporary_certificate_is_removed(self) -> None:
        app = self.root / "Syn.app"
        app.mkdir()
        certificate = b"fixed leaf certificate"
        expected = __import__("hashlib").sha256(certificate).hexdigest()
        extracted: list[Path] = []

        def fake_run(arguments, **_kwargs):
            if "--extract-certificates" in arguments:
                prefix = Path(arguments[arguments.index("--extract-certificates") + 1])
                leaf = Path(f"{prefix}0")
                leaf.write_bytes(certificate)
                extracted.append(leaf)
                return subprocess.CompletedProcess(arguments, 0, b"", b"")
            if "--verbose=4" in arguments:
                return subprocess.CompletedProcess(arguments, 0, b"", b"flags=0x10000(runtime)\n")
            return subprocess.CompletedProcess(arguments, 0, b"", b"")

        with patch.object(RELEASE_TOOL.subprocess, "run", side_effect=fake_run):
            RELEASE_TOOL.verify_macos_signature(app, expected)
            with self.assertRaises(RELEASE_TOOL.MetadataError):
                RELEASE_TOOL.verify_macos_signature(app, "0" * 64)
        self.assertTrue(extracted)
        self.assertTrue(all(not path.exists() for path in extracted))

        def ad_hoc(arguments, **_kwargs):
            details = b"Signature=adhoc\n" if "--verbose=4" in arguments else b""
            return subprocess.CompletedProcess(arguments, 0, b"", details)

        with patch.object(RELEASE_TOOL.subprocess, "run", side_effect=ad_hoc):
            with self.assertRaises(RELEASE_TOOL.MetadataError):
                RELEASE_TOOL.verify_macos_signature(app, expected)
        for invalid in ["", "A" * 64, "f" * 63, "g" * 64]:
            with self.assertRaises(RELEASE_TOOL.MetadataError):
                RELEASE_TOOL.verify_macos_signature(app, invalid)

    def git(self, repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result


if __name__ == "__main__":
    unittest.main()
