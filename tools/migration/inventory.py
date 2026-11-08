#!/usr/bin/env python3
"""Extract Python's explicit route/method pairs without importing the server."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('source', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
raw = args.source.read_bytes()
routes = set()
for node in ast.walk(ast.parse(raw)):
    if not isinstance(node, ast.FunctionDef) or node.name not in ('do_GET', 'do_POST', 'do_PUT', 'do_DELETE'):
        continue
    method = node.name[3:]
    for expr in ast.walk(node):
        if not isinstance(expr, ast.Compare) or not isinstance(expr.left, ast.Name) or expr.left.id != 'path':
            continue
        for op, right in zip(expr.ops, expr.comparators):
            values = right.elts if isinstance(op, ast.In) and isinstance(right, (ast.Tuple, ast.List)) else [right] if isinstance(op, ast.Eq) else []
            for value in values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    routes.add((method, value.value))
rows = [{'method': method, 'path': path} for method, path in sorted(routes)]
args.output.write_text(json.dumps({'sourceRepository': 'Angasky/mxioc-vpn-manager', 'sourceSHA256': hashlib.sha256(raw).hexdigest(), 'scope': 'Explicit path comparisons; dynamic public routes and response semantics require separate tests', 'routes': rows}, ensure_ascii=False, indent=2)+'\n')
