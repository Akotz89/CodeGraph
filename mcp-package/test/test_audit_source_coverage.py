import tempfile
import unittest
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'bin/codegraph-audit-source-coverage.py'
spec = importlib.util.spec_from_file_location('codegraph_audit_source_coverage', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
source_like = module.source_like


class SourceCoverageClassificationTest(unittest.TestCase):
    def test_templates_and_toml_are_source_like(self):
        for name in ('conf.sh.dist', 'jemalloc_preamble.h.in', 'pyproject.toml'):
            self.assertTrue(source_like(Path(name)), name)
        for name in ('binary.exe', 'records.jsonl', 'image.png'):
            self.assertFalse(source_like(Path(name)), name)

    def test_extensionless_source_requires_supported_shebang(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'launcher'
            path.write_text('#!/usr/bin/env bash\necho ok\n')
            self.assertTrue(source_like(path))
            path.write_bytes(b'\x7fELFnot-a-script')
            self.assertFalse(source_like(path))

    def test_cli_uses_selected_config_and_preserves_missing_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'source'
            repo.mkdir()
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo / 'main.py').write_text('print(1)\n')
            subprocess.run(['git', '-C', str(repo), 'add', 'main.py'], check=True)
            config = root / 'config.toml'
            config.write_text('[mcp_servers.selected]\nargs = ["--workspace", ' + json.dumps(str(repo)) + ']\n')
            state = root / 'index_state.json'
            state.write_text(json.dumps({str(repo / 'main.py'): 1}))
            command = [sys.executable, str(SCRIPT), '--project-root', str(root), '--config', 'config.toml',
                       '--endpoint', 'selected', '--state', str(state)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['recorded'], 1)
            self.assertNotIn('unavailable_roots', json.loads(result.stdout))
            (repo / 'other.py').write_text('print(2)\n')
            subprocess.run(['git', '-C', str(repo), 'add', 'other.py'], check=True)
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)['missing'], [str(repo / 'other.py')])

    def test_unavailable_roots_are_reported_while_other_roots_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'source'
            repo.mkdir()
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (repo / 'main.py').write_text('print(1)\n')
            subprocess.run(['git', '-C', str(repo), 'add', 'main.py'], check=True)
            absent = root / 'absent'
            nongit = root / 'nongit'
            nongit.mkdir()
            state = root / 'state.json'
            state.write_text(json.dumps({str(repo / 'main.py'): 1}))
            config = root / 'config.toml'
            command = [sys.executable, str(SCRIPT), '--project-root', str(root), '--config', str(config),
                       '--endpoint', 'selected', '--state', str(state)]
            for roots in ([repo, absent, nongit], [absent, repo, nongit]):
                argv = sum((['--workspace', str(path)] for path in roots), [])
                config.write_text('[mcp_servers.selected]\nargs = ' + json.dumps(argv) + '\n')
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual((report['roots'], report['eligible'], report['recorded']), (3, 1, 1))
                self.assertEqual(report['missing'], [])
                self.assertEqual(report['unavailable_roots'], [
                    {'path': str(absent), 'reason': 'missing_or_not_directory'},
                    {'path': str(nongit), 'reason': 'git_failed'},
                ])

    def test_invalid_configuration_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state.json'
            state.write_text('{}')
            config = root / 'config.toml'
            command = [sys.executable, str(SCRIPT), '--project-root', str(root), '--config', str(config),
                       '--endpoint', 'selected', '--state', str(state)]
            for contents in ('[mcp_servers.other]\nargs = []\n',
                             '[mcp_servers.selected]\nargs = "bad"\n',
                             '[mcp_servers.selected]\nargs = ["--workspace", "--include-file"]\n',
                             '[broken'):
                config.write_text(contents)
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('invalid endpoint configuration', result.stderr)
                self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
