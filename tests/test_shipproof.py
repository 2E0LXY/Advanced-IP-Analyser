import json
from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from shipproof import run, resolve_argv, validate_config


class ShipProofTests(unittest.TestCase):
    def config(self, root, checks, artifacts=None, **kwargs):
        config=root/'shipproof.json'
        config.write_text(json.dumps({'schema_version':1,'project':'self-test','checks':checks,'required_artifacts':artifacts or [], **kwargs}))
        return config

    def test_release_fails_when_artifact_missing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            config=self.config(root,[{'id':'ok','argv':[sys.executable,'-c','print(1)'],'stages':['pr','release']}],['dist/*.exe'])
            self.assertEqual(run('pr',config,Path('.shipproof')),0)
            self.assertEqual(run('release',config,Path('.shipproof')),1)

    def test_no_required_checks_cannot_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cfg=self.config(root,[{'id':'advisory','argv':[sys.executable,'-c','print(1)'],'stages':['pr'],'required':False}])
            self.assertEqual(run('pr',cfg,Path('.shipproof')),1)

    def test_windows_command_shim_resolution(self):
        locate=lambda name:'C:/Program Files/nodejs/npm.cmd' if name=='npm.cmd' else None
        self.assertEqual(resolve_argv(['npm','test'],windows=True,locate=locate),['C:/Program Files/nodejs/npm.cmd','test'])
        self.assertEqual(resolve_argv(['npm','test'],windows=False,locate=locate),['npm','test'])

    def test_required_test_count(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cfg=self.config(root,[{'id':'empty','argv':[sys.executable,'-c','print("Ran 0 tests")'],'stages':['pr'],'min_tests':1}])
            self.assertEqual(run('pr',cfg,Path('.shipproof')),1)

    def test_acceptance_fails_if_not_verified(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cfg=self.config(root,[{'id':'other','argv':[sys.executable,'-c','print(1)'],'stages':['release']}],['dist/*.exe'],acceptance=[{'id':'feature','checks':['other']}],require_acceptance=True)
            # required artefact absent: fail, but acceptance itself is satisfied
            self.assertEqual(run('release',cfg,Path('.shipproof')),1)
            report=json.loads((root/'.shipproof/report.json').read_text())
            self.assertEqual(report['acceptance'][0]['status'],'PASS')
            self.assertEqual(report['status'],'FAIL')

    def test_invalid_artifact_traversal_rejected(self):
        with self.assertRaises(ValueError):
            validate_config({'schema_version':1,'checks':[],'required_artifacts':['../secrets']},'release')

    def test_logs_never_include_command_output(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cfg=self.config(root,[{'id':'secret','argv':[sys.executable,'-c','print("secret-token-for-test")'],'stages':['pr']}])
            self.assertEqual(run('pr',cfg,Path('.shipproof')),0)
            self.assertNotIn('secret-token-for-test',(root/'.shipproof/report.json').read_text())

    def test_release_rejects_zero_length_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'dist').mkdir();(root/'dist/a.exe').touch()
            cfg=self.config(root,[{'id':'test','argv':[sys.executable,'-c','print(1)'],'stages':['release']}],['dist/*.exe'])
            self.assertEqual(run('release',cfg,Path('.shipproof')),1)

    def test_duplicate_check_id_rejected(self):
        check={'id':'same','argv':[sys.executable,'-c','print(1)'],'stages':['pr']}
        with self.assertRaises(ValueError):
            validate_config({'schema_version':1,'checks':[check,check]},'pr')

    def test_invalid_test_count_pattern_rejected(self):
        for pattern in ['(', r'Ran \d+ tests', '', 5]:
            check={'id':'c','argv':[sys.executable,'-c','print(1)'],'stages':['pr'],'min_tests':1,'test_count_pattern':pattern}
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                validate_config({'schema_version':1,'checks':[check]},'pr')

    def test_unparseable_test_count_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            cfg=self.config(root,[{'id':'words','argv':[sys.executable,'-c','print("Ran many tests")'],'stages':['pr'],
                                   'min_tests':1,'test_count_pattern':r'Ran (\w+) tests'}])
            self.assertEqual(run('pr',cfg,Path('.shipproof')),1)
            report=json.loads((root/'.shipproof/report.json').read_text())
            self.assertEqual(report['checks'][0]['status'],'FAIL')
            self.assertIsNone(report['checks'][0]['tests_observed'])

if __name__ == '__main__': unittest.main()
