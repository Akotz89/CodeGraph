import unittest
from unittest import mock
import os
import subprocess
import sys
import tempfile
from importlib.machinery import SourceFileLoader
from pathlib import Path
check_scope = SourceFileLoader('codegraph_scope_guard', str(Path(__file__).resolve().parents[1] / 'bin/codegraph-scope-guard.py')).load_module().check_scope


class ScopeGuardTest(unittest.TestCase):
    def setUp(self):
        self.args = ['--mcp', '--workspace', '/project', '--exclude', 'archive', '--max-files', '1000', '--include-file', '/project/extra']
        self.config = {'mcp_servers': {name: {'args': self.args, 'env': {'CODEGRAPH_STATE_DIR': '/state/' + name}} for name in ('codegraph-wow', 'codegraph-operations', 'codegraph-tooling')}}

    def test_full_scope_allows_query(self):
        self.assertTrue(check_scope('/state/codegraph-operations', self.args + ['--run-tool', 'codegraph_symbol_search'], self.config))

    def test_missing_exclusion_or_workspace_is_rejected(self):
        self.assertFalse(check_scope('/state/codegraph-operations', ['--workspace', '/project'], self.config))
        self.assertFalse(check_scope('/state/codegraph-operations', ['--exclude', 'archive', '--max-files', '1000', '--include-file', '/project/extra'], self.config))

    def test_separate_state_and_help_are_allowed(self):
        self.assertTrue(check_scope('/other-state', [], self.config))
        self.assertTrue(check_scope('/state/codegraph-operations', ['--help'], self.config))

    def test_new_configured_view_is_guarded(self):
        self.config['mcp_servers']['codegraph-candidate'] = {
            'args': self.args, 'env': {'CODEGRAPH_STATE_DIR': '/state/candidate'}}
        self.assertTrue(check_scope('/state/candidate', self.args, self.config))
        self.assertFalse(check_scope('/state/candidate', ['--workspace', '/project'], self.config))

    def test_shared_store_rejects_conflicting_configured_scopes(self):
        self.config['mcp_servers']['codegraph-candidate'] = {
            'args': ['--workspace', '/different'],
            'env': {'CODEGRAPH_STATE_DIR': '/state/codegraph-operations'}}
        self.assertFalse(check_scope('/state/codegraph-operations', self.args, self.config))
        self.assertFalse(check_scope('/state/codegraph-operations', ['--workspace', '/different'], self.config))

    def test_shared_store_accepts_matching_scopes_and_ignores_other_servers(self):
        self.config['mcp_servers']['codegraph-candidate'] = {
            'args': list(self.args), 'env': {'CODEGRAPH_STATE_DIR': '/state/codegraph-operations'}}
        self.config['mcp_servers']['other-tool'] = {
            'args': ['--workspace', '/different'],
            'env': {'CODEGRAPH_STATE_DIR': '/state/codegraph-operations'}}
        self.assertTrue(check_scope('/state/codegraph-operations', self.args, self.config))

    def test_resolution_maps_are_part_of_persistent_scope(self):
        env = self.config['mcp_servers']['codegraph-operations']['env']
        env['CODEGRAPH_CALL_SCOPE_MAP'] = '{"/project/core":"live","/project/module":"live"}'
        env['CODEGRAPH_SQL_SCOPE_MAP'] = '{"/project/core":"live"}'
        same = {'CODEGRAPH_CALL_SCOPE_MAP': '{"/project/module":"live","/project/core":"live"}',
                'CODEGRAPH_SQL_SCOPE_MAP': '{"/project/core":"live"}'}
        self.assertTrue(check_scope('/state/codegraph-operations', self.args, self.config, same))
        with mock.patch.dict(os.environ, same, clear=True):
            self.assertTrue(check_scope('/state/codegraph-operations', self.args, self.config))
        self.assertFalse(check_scope('/state/codegraph-operations', self.args, self.config, {}))
        bad_sql = dict(same, CODEGRAPH_SQL_SCOPE_MAP='{"/project/core":"other"}')
        self.assertFalse(check_scope('/state/codegraph-operations', self.args, self.config, bad_sql))
        with self.assertRaises(ValueError):
            check_scope('/state/codegraph-operations', self.args, self.config, dict(same, CODEGRAPH_SQL_SCOPE_MAP='bad'))
        same['CODEGRAPH_CALL_SCOPE_MAP'] = '{"/project/core":"other"}'
        self.assertFalse(check_scope('/state/codegraph-operations', self.args, self.config, same))
        with self.assertRaises(ValueError):
            check_scope('/state/codegraph-operations', self.args, self.config, {'CODEGRAPH_CALL_SCOPE_MAP': 'bad'})

    def test_cpp_override_is_part_of_persistent_scope(self):
        with_cpp = self.args + ['--include-cpp-file', '/project/fragment.inc']
        self.config['mcp_servers']['codegraph-operations']['args'] = with_cpp
        self.assertTrue(check_scope('/state/codegraph-operations', with_cpp, self.config))
        self.assertFalse(check_scope('/state/codegraph-operations', self.args, self.config))
        self.assertFalse(check_scope('/state/codegraph-operations', self.args + ['--include-cpp-file', '/project/other.inc'], self.config))

    def test_entrypoint_requires_configuration_and_executes_only_matching_scope(self):
        guard = Path(__file__).resolve().parents[1] / 'bin/codegraph-scope-guard.py'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.codex').mkdir()
            (root / '.codex/config.toml').write_text(
                '[mcp_servers.codegraph-test]\nargs = ["--workspace", "/project"]\n'
                '[mcp_servers.codegraph-test.env]\nCODEGRAPH_STATE_DIR = "/state/test"\n')
            engine = root / 'engine'
            engine.write_text('#!/bin/sh\nprintf launched\n')
            engine.chmod(0o755)
            env = dict(os.environ, CODEGRAPH_GUARD_PROJECT_ROOT=str(root),
                       CODEGRAPH_GUARD_BINARY=str(engine), CODEGRAPH_STATE_DIR='/state/test',
                       CODEGRAPH_CALL_SCOPE_MAP='', CODEGRAPH_SQL_SCOPE_MAP='')
            def run(args, environment):
                return subprocess.run([sys.executable, str(guard), *args], env=environment, capture_output=True)
            self.assertEqual(run(['--workspace', '/project'], env).stdout, b'launched')
            self.assertEqual(run(['--workspace', '/other'], env).returncode, 2)
            del env['CODEGRAPH_GUARD_BINARY']
            self.assertEqual(run(['--workspace', '/project'], env).returncode, 2)


if __name__ == '__main__':
    unittest.main()
