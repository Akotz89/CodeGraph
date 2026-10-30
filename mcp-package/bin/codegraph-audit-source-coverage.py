#!/usr/bin/env python3
"""Compare tracked source files with an explicitly selected CodeGraph index state."""

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

EXTENSIONS = {'.bash', '.bat', '.bats', '.c', '.cc', '.cmake', '.cpp', '.css',
              '.conf', '.cxx', '.go', '.h', '.hpp', '.html', '.js', '.json', '.jsx', '.lua',
              '.php', '.py', '.rc', '.rs', '.sh', '.sql', '.ts', '.tsx', '.am',
              '.yaml', '.yml', '.toml'}
SPECIAL = {'CMakeLists.txt', 'configure.ac', 'Dockerfile', 'Makefile'}
INTERPRETERS = {'bash', 'sh', 'python', 'python3', 'make'}


def source_like(path):
    if path.suffix.lower() in EXTENSIONS or path.name in SPECIAL or path.name.endswith(('.conf.dist', '.sh.dist', '.h.in')):
        return True
    if path.suffix:
        return False
    try:
        with path.open('rb') as file:
            first = file.readline(256).decode('ascii', errors='ignore')
    except OSError:
        return False
    if not first.startswith('#!'):
        return False
    words = first[2:].split()
    if not words:
        return False
    command = Path(words[0]).name
    interpreter = words[1] if command == 'env' and len(words) > 1 else command
    return interpreter in INTERPRETERS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, type=Path, help='Exact saved source index_state.json')
    parser.add_argument('--project-root', required=True, type=Path, help='Root for resolving a relative configuration path')
    parser.add_argument('--config', required=True, type=Path, help='Project configuration to audit')
    parser.add_argument('--endpoint', required=True, help='Configured MCP endpoint name')
    args = parser.parse_args()
    invalidation = args.state.with_suffix('.invalid')
    if invalidation.exists():
        parser.error(f'index state is invalidated: {invalidation}')
    state = json.loads(args.state.read_text())
    if not isinstance(state, dict):
        parser.error('index state is not a path-to-hash object')
    config_path = args.config if args.config.is_absolute() else args.project_root / args.config
    try:
        config = tomllib.loads(config_path.read_text())
        argv = config['mcp_servers'][args.endpoint]['args']
        if not isinstance(argv, list) or any(not isinstance(value, str) for value in argv):
            raise ValueError('endpoint args must be a list of strings')
        if any(i + 1 == len(argv) or argv[i + 1].startswith('--')
               for i, value in enumerate(argv) if value in ('--workspace', '--include-file')):
            raise ValueError('workspace or include option is missing its value')
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError, ValueError) as exc:
        parser.error(f'invalid endpoint configuration: {exc}')
    def configured_path(value):
        path = Path(value)
        return path if path.is_absolute() else args.project_root / path

    roots = [configured_path(argv[i + 1]) for i, v in enumerate(argv[:-1]) if v == '--workspace']
    included = {str(configured_path(argv[i + 1])) for i, v in enumerate(argv[:-1]) if v == '--include-file'}
    if not roots:
        parser.error('endpoint has no configured source roots')
    checked, generated, unlisted_config, missing = 0, [], [], []
    unavailable_roots = []
    for index, root in enumerate(roots):
        if not root.is_dir():
            unavailable_roots.append({'path': str(root), 'reason': 'missing_or_not_directory'})
            continue
        try:
            result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], capture_output=True)
        except OSError:
            unavailable_roots.append({'path': str(root), 'reason': 'git_unavailable'})
            continue
        if result.returncode:
            unavailable_roots.append({'path': str(root), 'reason': 'git_failed'})
            continue
        if index == 0 and not any(str(root) + '/' in key for key in state):
            parser.error('state does not contain files under the configured primary source root')
        for raw in result.stdout.split(b'\0'):
            if not raw:
                continue
            path = root / raw.decode(errors='surrogateescape')
            parts = path.relative_to(root).parts
            lower = path.name.lower()
            if (any(p.startswith('.') or p == 'private' for p in parts)
                    or 'secret' in lower or 'credential' in lower or lower.endswith('.env')
                    or path.is_symlink() or not path.is_file()):
                continue
            if not source_like(path):
                continue
            if (path.suffix.lower() == '.conf' or path.name.endswith(('.conf.dist', '.sh.dist', '.h.in'))) and str(path) not in included:
                unlisted_config.append(str(path))
                continue
            if ((any(p in ('dist', 'examples') for p in parts) and str(path) not in included)
                    or path.name in ('package-lock.json', 'npm-shrinkwrap.json')):
                generated.append(str(path))
                continue
            checked += 1
            if str(path) not in state:
                missing.append(str(path))
    report = {'roots': len(roots), 'eligible': checked, 'recorded': checked - len(missing),
              'missing': sorted(missing), 'excluded_generated_or_examples': sorted(generated),
              'excluded_unlisted_config': sorted(unlisted_config)}
    if unavailable_roots:
        report['unavailable_roots'] = sorted(unavailable_roots, key=lambda item: item['path'])
    print(json.dumps(report, indent=2))
    return bool(missing or unavailable_roots)


if __name__ == '__main__':
    sys.exit(main())
