"""Production Python handler, isolated data and no periodic/network workers."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import server

root = Path(sys.argv[1]).resolve()
server.ROOT = root
server.FRONT = root/'index.html'
server.AUTH = root/'auth.json'
server.LEGACY_AUTH = root/'unused-legacy-auth'
server.PROFILES_FILE = root/'profiles.json'
server.PROFILES_DIR = root/'profiles'
server.BACKUP_DIR = root/'backups'
server.SESSIONS_FILE = root/'sessions.json'
server.FILES = [root/'primary.yaml', root/'mirror.yaml']
server.PROFILES_CACHE = None
server.PROFILES_MTIME = 0
server.CONFIG_CACHE = {}
server.SESSIONS = None
httpd = server.LimitedThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
print(json.dumps({'port': httpd.server_port}), flush=True)
httpd.serve_forever()
