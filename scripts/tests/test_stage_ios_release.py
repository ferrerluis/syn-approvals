import json
import shutil
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

    def test_generated_cache_is_allowed_but_hidden_source_and_dirty_checkout_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / 'repository'
            repository.mkdir()
            (repository / 'scripts').mkdir()
            shutil.copyfile(SCRIPT.parent / 'release-tool.py', repository / 'scripts/release-tool.py')
            (repository / 'mobile/src').mkdir(parents=True)
            app = repository / 'mobile/App.tsx'
            app.write_text('export default function App() {}\n')
            (repository / '.gitignore').write_text('mobile/node_modules/\nmobile/src/ignored.js\n')
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repository), *args], text=True).strip()
            git('init', '-q')
            git('add', '.')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
            metadata = base / 'release.json'
            metadata.write_text(json.dumps({'schema_version':1, 'release_id':'20261005010000', 'commit':git('rev-parse','HEAD')}))
            cache = repository / 'mobile/node_modules'
            cache.mkdir()
            (cache / 'generated.js').write_text('cache')
            destination = base / 'output.json'
            def stage():
                destination.unlink(missing_ok=True)
                result = subprocess.run([sys.executable, str(SCRIPT), '--configuration', 'Release',
                    '--platform', 'iphoneos', '--metadata', str(metadata), '--destination', str(destination),
                    '--repository', str(repository)], capture_output=True, text=True)
                return result.returncode, destination.exists()
            self.assertEqual(stage(), (0, True))
            hidden = repository / 'mobile/src/ignored.js'
            hidden.write_text('unreviewed source')
            self.assertNotEqual(stage()[0], 0)
            self.assertFalse(destination.exists())
            hidden.unlink()
            app.write_text('changed source')
            self.assertNotEqual(stage()[0], 0)
            self.assertFalse(destination.exists())

    def test_unverified_candidate_is_not_written(self):
        code, written = self.run_stage('Release', 'iphoneos',
            {'schema_version': 1, 'release_id': '20261004123456', 'commit': '1' * 40})
        self.assertNotEqual(code, 0)
        self.assertFalse(written)
