#!/usr/bin/env python3
"""Build isolated, pinned compatibility cores; never installs or deploys."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile

base = pathlib.Path(__file__).resolve().parent
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--go', default='go')
p.add_argument('--output', type=pathlib.Path, required=True)
p.add_argument('--arch', choices=['amd64', 'arm64'], default='amd64')
a = p.parse_args()
go = str(pathlib.Path(shutil.which(a.go) or a.go).resolve())
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
manifest = json.loads((base / 'manifest.json').read_text())
results = {}
for name, spec in manifest.items():
    with tempfile.TemporaryDirectory(prefix='mxioc-core-build-') as temporary:
        # An explicit module version is verified through Go's module checksum database.
        metadata = json.loads(subprocess.check_output([go, 'mod', 'download', '-json', spec['module']+'@'+spec['version']], cwd=temporary))
        source = pathlib.Path(metadata['Dir'])
        target = pathlib.Path(temporary) / 'source'
        shutil.copytree(source, target)
        file = target / spec['file']
        if hashlib.sha256(file.read_bytes()).hexdigest() != spec['originalSHA256']:
            raise SystemExit('Source digest mismatch: '+name)
        file.chmod(0o644)
        subprocess.run(['patch', '--batch', '--forward', '-p1', '-i', str(base / (name+'.patch'))], cwd=target, check=True)
        if hashlib.sha256(file.read_bytes()).hexdigest() != spec['patchedSHA256']:
            raise SystemExit('Patched digest mismatch: '+name)
        binary = out / (name+'-'+spec['version'][1:]+'-compat-linux-'+a.arch)
        args = [go, 'build', '-trimpath', '-ldflags=-s -w', '-o', str(binary)]
        args += ['-tags', 'with_quic,with_utls,with_v2ray_api', './cmd/sing-box'] if name == 'sing-box' else ['.']
        subprocess.run(args, cwd=target, env=dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=a.arch), check=True)
        results[name] = dict(spec, moduleSum=metadata['Sum'], binary=binary.name, binarySHA256=hashlib.sha256(binary.read_bytes()).hexdigest())
        license = source / 'LICENSE'
        if license.exists(): shutil.copy2(license, out / (name+'-LICENSE'))
(out / ('manifest-'+a.arch+'.json')).write_text(json.dumps(results, indent=2)+'\n')
print(out)
