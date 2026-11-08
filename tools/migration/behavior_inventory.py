#!/usr/bin/env python3
"""Inventory Python behavior entry points without importing production modules.

Mappings identify candidate Go evidence, never automatically claim parity.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path

MAPPING = {
    'server.py': ['internal/web', 'internal/config', 'internal/subscriptions', 'internal/subsource', 'internal/geo'],
    'remote_manager.py': ['internal/remote', 'internal/subscriptions'],
    'core_adapter.py': ['internal/remote'],
    'shared_users.py': ['internal/remote', 'internal/subscriptions', 'internal/billing'],
    'panel_user_runtime.py': ['internal/remote'],
    'managed_nodes.py': ['internal/managednodes', 'internal/config'],
    'bandwidth.py': ['internal/remote', 'internal/billing', 'internal/config'],
    'certificate_manager.py': ['internal/remote'],
    'reality_probe.py': ['internal/remote'],
    'server_monitor.py': ['internal/remote'],
    'client_adapter.py': ['internal/subscriptions'],
    'mieru_adapter.py': ['internal/links', 'internal/config'],
    'snell_adapter.py': ['internal/links', 'internal/config'],
}


def inventory(source, repo):
    modules = []
    for path in sorted(source.glob('*.py')):
        raw = path.read_bytes()
        tree = ast.parse(raw, filename=path.name)
        entries = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                entries.append({'symbol': node.name, 'line': node.lineno})
            elif isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        entries.append({'symbol': f'{node.name}.{method.name}', 'line': method.lineno})
        candidates = MAPPING.get(path.name, [])
        for candidate in candidates:
            if not (repo / candidate).is_dir():
                raise ValueError(f'missing Go evidence directory: {candidate}')
        modules.append({'source': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'candidateGoDirectories': candidates,
                        'reviewStatus': 'requires-behavior-review', 'entries': entries})
    return {'scope': 'Top-level functions and class methods in every root Python module. Nested helpers are covered by their enclosing behavior. Candidate directories and route coverage do not prove parity.',
            'moduleCount': len(modules), 'entryCount': sum(len(m['entries']) for m in modules),
            'modules': modules}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--repo', type=Path, default=Path('.'))
    args = parser.parse_args()
    result = inventory(args.source, args.repo)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(f'{result["moduleCount"]} Python modules, {result["entryCount"]} behavior entries; review pending')
