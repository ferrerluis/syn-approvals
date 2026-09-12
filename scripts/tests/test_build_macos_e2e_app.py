import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build-macos-e2e-app.sh"
RELEASE_TOOL = ROOT / "scripts" / "release-tool.py"
RELEASE_ID = "20260912120000"


class ExactCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="syn-e2e-build-test-")
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        branding = self.candidate / "macos" / "Sources" / "Syn" / "Resources" / "Branding"
        branding.mkdir(parents=True)
        (branding / "test.txt").write_text("branding")
        (self.candidate / "macos" / "Package.swift").write_text("// synthetic fixture\n")
        subprocess.run(["git", "init", "-q", str(self.candidate)], check=True)
        subprocess.run(["git", "-C", str(self.candidate), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.candidate), "-c", "user.name=Syn Test",
             "-c", "user.email=syn-test@example.invalid", "-c", "commit.gpgsign=false",
             "commit", "-qm", "fixture"],
            check=True,
        )
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.candidate), "rev-parse", "HEAD"], text=True
        ).strip()
        self.release = self.root / "release.json"
        self.source = self.root / f"syn-remote-source-{RELEASE_ID}.tar.gz"
        self.helper = self.root / f"synctl-arm64-{RELEASE_ID}"
        self.source.write_bytes(b"synthetic source")
        self.helper.write_bytes(b"synthetic helper")
        self.source_json = self.root / "remote-source.json"
        self.helper_json = self.root / "remote-helper.json"
        self.tool("create", "--release-id", RELEASE_ID, "--commit", self.commit,
                  "--output", self.release)
        self.tool("create-remote-source", "--metadata", self.release,
                  "--artifact", self.source, "--output", self.source_json)
        self.tool("create-remote-helper", "--metadata", self.release,
                  "--artifact", self.helper, "--output", self.helper_json)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def tool(self, *arguments: object) -> None:
        subprocess.run(
            ["python3", str(RELEASE_TOOL), *(str(value) for value in arguments)], check=True
        )

    def run_script(
        self, *, validate_only: bool = True, extra_environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "SYN_E2E_PRODUCTION_ROOT": str(self.candidate),
            "SYN_RELEASE_METADATA": str(self.release),
            "SYN_REMOTE_SOURCE_METADATA": str(self.source_json),
            "SYN_REMOTE_SOURCE_ARCHIVE": str(self.source),
            "SYN_REMOTE_HELPER_METADATA": str(self.helper_json),
            "SYN_REMOTE_HELPER_BINARY": str(self.helper),
        }
        if validate_only:
            environment["SYN_E2E_VALIDATE_ONLY"] = "1"
        environment.update(extra_environment or {})
        return subprocess.run(
            [str(SCRIPT), str(self.root / "output")], env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_accepts_exact_clean_candidate_without_creating_output(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("candidate inputs verified", result.stdout)
        self.assertFalse((self.root / "output").exists())

    def test_rejects_dirty_candidate_before_creating_output(self) -> None:
        (self.candidate / "dirty.txt").write_text("not committed")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked or untracked changes", result.stderr)
        self.assertFalse((self.root / "output").exists())

    def test_rejects_wrong_candidate_commit(self) -> None:
        value = json.loads(self.release.read_text())
        value["commit"] = "f" * 40
        self.release.write_text(json.dumps(value))
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("commit does not match", result.stderr)

    def test_rejects_mismatched_remote_artifact(self) -> None:
        self.source.write_bytes(b"substituted source")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact does not match", result.stderr)

    def test_refuses_existing_app_and_preserves_its_sentinel(self) -> None:
        app = self.root / "output" / "SynE2E.app"
        app.mkdir(parents=True)
        sentinel = app / "sentinel.txt"
        sentinel.write_text("belongs to an earlier run")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to replace existing E2E app", result.stderr)
        self.assertEqual(sentinel.read_text(), "belongs to an earlier run")

    def test_refuses_symlinked_app_and_preserves_its_target(self) -> None:
        target = self.root / "unrelated-app"
        target.mkdir()
        sentinel = target / "sentinel.txt"
        sentinel.write_text("unrelated")
        output = self.root / "output"
        output.mkdir()
        (output / "SynE2E.app").symlink_to(target, target_is_directory=True)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to replace existing E2E app", result.stderr)
        self.assertEqual(sentinel.read_text(), "unrelated")

    @unittest.skipUnless(sys.platform == "darwin", "the E2E app builder is macOS-only")
    def test_late_failure_publishes_no_app_and_preserves_output_sibling(self) -> None:
        tools = self.root / "tools"
        tools.mkdir()
        fake_swift = tools / "swift"
        fake_swift.write_text("""#!/bin/sh
set -eu
scratch=
product=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --scratch-path) scratch=$2; shift 2 ;;
        --product) product=$2; shift 2 ;;
        *) shift ;;
    esac
done
mkdir -p "$scratch/release"
if [ "$product" = SynE2E ]; then
    printf 'E2EScenarioSigner\\n' > "$scratch/release/SynE2E"
    chmod 755 "$scratch/release/SynE2E"
    mkdir -p "$scratch/release/SynE2E_SynE2E.bundle"
else
    printf 'shipping Syn\\n' > "$scratch/release/Syn"
    chmod 755 "$scratch/release/Syn"
fi
""")
        fake_swift.chmod(0o755)
        output = self.root / "output"
        output.mkdir()
        sibling = output / "keep.txt"
        sibling.write_text("preserve me")
        result = self.run_script(
            validate_only=False,
            extra_environment={
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "SYN_E2E_FORCE_LATE_FAILURE": "1",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forced late SynE2E build failure", result.stderr)
        self.assertFalse((output / "SynE2E.app").exists())
        self.assertEqual(sibling.read_text(), "preserve me")


if __name__ == "__main__":
    unittest.main()
