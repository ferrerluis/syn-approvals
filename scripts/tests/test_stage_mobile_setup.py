import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]


class MobileSetupStaging(unittest.TestCase):
    def test_matching_artifacts_embed_and_changed_helper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / 'release.json'
            metadata.write_text(json.dumps({'schema_version': 1, 'release_id': '20261005010000', 'commit': 'a' * 40}))
            source = root / 'syn-remote-source-20261005010000.tar.gz'
            source.write_bytes(b'public inert test archive')
            helper = root / 'synctl-arm64-20261005010000'
            header = bytearray(64)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = (183).to_bytes(2, 'little')
            helper.write_bytes(header)
            for kind, artifact in [('source', source), ('helper', helper)]:
                subprocess.run([sys.executable, str(SCRIPTS / 'release-tool.py'), f'create-remote-{kind}',
                    '--metadata', str(metadata), '--artifact', str(artifact), '--output', str(root / f'remote-{kind}.json')], check=True, capture_output=True)
            destination = root / 'embedded'
            command = [sys.executable, str(SCRIPTS / 'stage-mobile-setup.py'), '--metadata', str(metadata),
                '--artifacts', str(root), '--destination', str(destination)]
            first = subprocess.run(command, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual((destination / helper.name).read_bytes(), bytes(header))
            helper.write_bytes(header + b'changed')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual((destination / helper.name).read_bytes(), bytes(header))

    def test_real_release_cannot_omit_setup_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / 'release.json'
            metadata.write_text(json.dumps({'schema_version': 1, 'release_id': '20261005010000', 'commit': 'a' * 40}))
            destination = root / 'embedded'
            result = subprocess.run([sys.executable, str(SCRIPTS / 'stage-mobile-setup.py'), '--metadata', str(metadata),
                '--destination', str(destination)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(destination.exists())
