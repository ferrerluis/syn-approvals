"""Exercise the real scanner using disposable repositories and synthetic tokens."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCANNER = os.environ.get("GITLEAKS_BINARY") or shutil.which("gitleaks")


@unittest.skipUnless(SCANNER, "Gitleaks is required for scanner integration tests")
class SecretScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syn-secret-scan-test-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/check-secrets.sh", self.repo / "scripts/check-secrets.sh")
        shutil.copyfile(ROOT / ".gitleaks.toml", self.repo / ".gitleaks.toml")
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Synthetic audit test")
        self.git("config", "user.email", "audit@example.invalid")
        self.git("add", ".")
        self.commit("Initial clean fixture")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True)

    def commit(self, message):
        self.git("-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "-m", message)

    def scan(self, root=None):
        environment = dict(os.environ, GITLEAKS_BINARY=str(SCANNER))
        return subprocess.run(["sh", "scripts/check-secrets.sh"], cwd=root or self.repo,
                              env=environment, capture_output=True, text=True)

    def add_synthetic_secret(self):
        # Generated only in a disposable fixture; not an issued credential.
        value = "gh" + "p_" + "0123456789abcdef" * 2 + "abcd"
        (self.repo / "fixture.txt").write_text("test_token=" + value + "\n")
        self.git("add", "fixture.txt")
        return value

    def test_clean_history_passes(self):
        result = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_staged_secret_fails_without_printing_it(self):
        value = self.add_synthetic_secret()
        result = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_deleted_historical_secret_still_fails(self):
        value = self.add_synthetic_secret()
        self.commit("Synthetic scanner detection fixture")
        self.git("rm", "fixture.txt")
        self.commit("Delete fixture from tip")
        result = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_shallow_checkout_fails_instead_of_claiming_full_coverage(self):
        shallow = Path(self.temp.name) / "shallow"
        self.git("clone", "--depth=1", self.repo.as_uri(), str(shallow))
        result = self.scan(shallow)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Refusing a partial history scan", result.stderr)


if __name__ == "__main__":
    unittest.main()
