#!/bin/sh
# Build the image from a checksum-verified release, without a Go toolchain.
set -eu
umask 077
version=${1:-v0.1.29}
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo '版本号无效' >&2; exit 2 ;; esac
case "$version" in *[!v0-9.]*) exit 2 ;; esac
case "${MX_PANEL_ARCH:-$(uname -m)}" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo '仅支持 amd64/arm64' >&2; exit 2 ;; esac
script=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
name=mxioc-go-$version-linux-$arch.tar.gz
base=https://github.com/Angasky/Mx-Panel/releases/download/go-$version
if [ -n "${MX_PANEL_RELEASE_DIR:-}" ]; then
    cp "$MX_PANEL_RELEASE_DIR/$name" "$MX_PANEL_RELEASE_DIR/SHA256SUMS" "$stage/"
else
    curl -fL --retry 3 "$base/$name" -o "$stage/$name"
    curl -fL --retry 3 "$base/SHA256SUMS" -o "$stage/SHA256SUMS"
fi
(cd "$stage" && awk -v n="$name" '$2==n {print;found++} END {if(found!=1)exit 1}' SHA256SUMS > selected.sha256 && sha256sum -c selected.sha256)
# The image only needs two regular files; never extract arbitrary archive paths.
for file in mxioc index.html; do tar -xOf "$stage/$name" "$file" > "$stage/$file"; done
chmod 755 "$stage/mxioc"
chmod 644 "$stage/index.html"
cp "$script/Dockerfile" "$stage/Dockerfile"
cp "$script/entrypoint.sh" "$stage/container-entrypoint.sh"
docker build --platform "linux/$arch" -t "mx-panel:$version" "$stage"
