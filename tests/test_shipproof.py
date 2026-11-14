import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from shipproof import run

class ShipProofTests(unittest.TestCase):
    def test_pass_and_missing_release_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config = root / 'shipproof.json'
            config.write_text(json.dumps({'schema_version':1,'project':'test','checks':[{'id':'python','argv':[sys.executable,'-c','print(1)'],'stages':['pr','release']}],'required_artifacts':['dist/*.exe']}))
            self.assertEqual(run('pr', config, Path('.shipproof')), 0)
            self.assertEqual(json.loads((root/'.shipproof/report.json').read_text())['status'], 'PASS')
            self.assertEqual(run('release', config, Path('.shipproof')), 1)
    def test_no_configured_checks_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config = root / 'shipproof.json'
            config.write_text(json.dumps({'schema_version':1,'checks':[]}))
            self.assertEqual(run('change',config,Path('.shipproof')), 1)

if __name__ == '__main__':
    unittest.main()
