#!/usr/bin/env python3
"""Keep project graph stores from being updated with incomplete index options."""
import argparse
import json
import os
from pathlib import Path
import sys
import tomllib



def scope(args):
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--workspace', '-w', action='append', default=[])
    parser.add_argument('--exclude', '-e', action='append', default=[])
    parser.add_argument('--include-file', action='append', default=[])
    parser.add_argument('--include-cpp-file', action='append', default=[])
    parser.add_argument('--max-files', type=int)
    options, _ = parser.parse_known_args(args)
    return (
        sorted(str(Path(p).resolve()) for p in options.workspace),
        sorted(options.exclude),
        sorted(str(Path(p).resolve()) for p in options.include_file),
        sorted(str(Path(p).resolve()) for p in options.include_cpp_file),
        options.max_files,
    )


def resolution_maps(environment):
    result = []
    for key in ('CODEGRAPH_CALL_SCOPE_MAP', 'CODEGRAPH_SQL_SCOPE_MAP'):
        value = json.loads(environment.get(key) or '{}')
        if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
            raise ValueError(f'{key} must be a JSON object of strings')
        result.append(value)
    schemas = json.loads(environment.get('CODEGRAPH_SQL_SCHEMA_MAP') or '{}')
    if not isinstance(schemas, dict):
        raise ValueError('CODEGRAPH_SQL_SCHEMA_MAP must be a JSON object')
    for root, config in schemas.items():
        if not isinstance(root, str) or not isinstance(config, dict) or 'aliases' not in config or set(config) - {'aliases', 'default_files', 'definition_files'}:
            raise ValueError('Invalid SQL schema root configuration')
        for key in ('aliases', 'default_files'):
            value = config.get(key, {})
            if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
                raise ValueError(f'SQL schema {key} must be an object of strings')
        definitions = config.get('definition_files', [])
        if not isinstance(definitions, list) or any(not isinstance(path, str) for path in definitions):
            raise ValueError('SQL schema definition_files must be a list of strings')
    result.append(schemas)
    return result


def check_scope(state, args, config, environment=None):
    if not state or any(x in args for x in ('--help', '-h', '--version', '-V', '--info')):
        return True
    target = Path(state).resolve()
    for name, server in config['mcp_servers'].items():
        if not name.startswith('codegraph-'):
            continue
        configured = server.get('env', {}).get('CODEGRAPH_STATE_DIR')
        if configured and Path(configured).resolve() == target:
            if scope(args) != scope(server['args']):
                return False
            if resolution_maps(os.environ if environment is None else environment) != resolution_maps(server.get('env', {})):
                return False
    return True


def main():
    try:
        root = os.environ.get('CODEGRAPH_GUARD_PROJECT_ROOT')
        binary = os.environ.get('CODEGRAPH_GUARD_BINARY')
        if not root or not binary or not Path(root).is_absolute() or not Path(binary).is_absolute():
            raise ValueError('set absolute CODEGRAPH_GUARD_PROJECT_ROOT and CODEGRAPH_GUARD_BINARY')
        with (Path(root) / '.codex/config.toml').open('rb') as f:
            config = tomllib.load(f)
        if not check_scope(os.environ.get('CODEGRAPH_STATE_DIR'), sys.argv[1:], config):
            print('CodeGraph scope does not match this project store; use all configured workspace and exclusion options or a separate state directory.', file=sys.stderr)
            return 2
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f'Cannot validate CodeGraph project scope: {exc}', file=sys.stderr)
        return 2
    try:
        os.execv(binary, [binary, *sys.argv[1:]])
    except OSError as exc:
        print(f'Cannot launch CodeGraph: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
