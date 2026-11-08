#!/usr/bin/env python3
"""Run only extracted pure link parsers; never import or start the Python server."""
import argparse
import ast
import base64
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

parser = argparse.ArgumentParser()
parser.add_argument('source', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
raw = args.source.read_bytes()
names = {'first', 'bool_value', 'normalize_reality_options', 'normalize_ipv6_authority', 'parse_node_link'}
functions = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name in names]
assert {n.name for n in functions} == names
scope = dict(re=re, json=json, parse_qs=parse_qs, unquote=unquote, urlsplit=urlsplit)
exec(compile(ast.Module(body=functions, type_ignores=[]), str(args.source), 'exec'), scope)
uris = [
    'hy2://secret@example.net:443',
    'hysteria2://account:secret@example.net:443?alpn=custom,h3',
    'tuic://11111111-1111-4111-8111-111111111111:secret@example.net:443',
    'tuic://11111111-1111-4111-8111-111111111111@example.net:443?password=secret&congestion-controller=cubic&udp-relay-mode=quic&alpn=custom',
]
keys = ['type', 'server', 'port', 'uuid', 'password', 'alpn', 'congestion-controller', 'udp-relay-mode']
rows = []
for uri in uris:
    node = scope['parse_node_link'](uri)
    rows.append(dict(uri=uri, expected={k: node[k] for k in keys if k in node}))
args.output.write_text(json.dumps(dict(sourceSHA256=hashlib.sha256(raw).hexdigest(), cases=rows), indent=2) + '\n')
