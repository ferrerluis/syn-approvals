import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'stage-ios-release.py'

class IOSReleaseGuards(unittest.TestCase):
    def run_stage(self, configuration, platform, metadata):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'input.json', root / 'app/release.json'
            source.write_text(json.dumps(metadata))
            result = subprocess.run([sys.executable, str(SCRIPT), '--configuration', configuration,
                '--platform', platform, '--metadata', str(source), '--destination', str(destination),
                '--repository', str(root)], capture_output=True, text=True)
            return result.returncode, destination.exists()

    def test_development_metadata_cannot_ship_or_run_on_hardware(self):
        development = {'schema_version': 1, 'release_id': '00000000000000', 'commit': '0' * 40}
        self.assertEqual(self.run_stage('Debug', 'iphonesimulator', development), (0, True))
        for configuration, platform in [('Release', 'iphonesimulator'), ('Release', 'iphoneos'), ('Debug', 'iphoneos')]:
            code, written = self.run_stage(configuration, platform, development)
            self.assertNotEqual(code, 0)
            self.assertFalse(written)

    def test_unverified_candidate_is_not_written(self):
        code, written = self.run_stage('Release', 'iphoneos',
            {'schema_version': 1, 'release_id': '20261004123456', 'commit': '1' * 40})
        self.assertNotEqual(code, 0)
        self.assertFalse(written)
