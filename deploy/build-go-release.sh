#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 1 || ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]]; then
    echo "Usage: bash deploy/build-go-release.sh VERSION" >&2
    exit 2
fi
version=$1
out="dist/go-$version"
mkdir -p "$out"
for arch in amd64 arm64; do
    name="mxioc-go-$version-linux-$arch"
    stage=$(mktemp -d)
    trap 'rm -rf -- "$stage"' EXIT
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "${MXIOC_GO_BIN:-go}" build -buildvcs=false -trimpath -ldflags "-s -w -X main.releaseVersion=$version" -o "$stage/mxioc" ./cmd/mxioc
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "${MXIOC_GO_BIN:-go}" build -buildvcs=false -trimpath -ldflags "-s -w" -o "$stage/mxioc-agent" ./cmd/mxioc-agent
    cp index.html deploy/mxioc-go-release.service deploy/install-go.sh "$stage/"
    printf '%s\n' "$version" > "$stage/VERSION"
    printf '%s\n' "$arch" > "$stage/ARCH"
    (
        cd "$stage"
        sha256sum mxioc index.html mxioc-go-release.service VERSION ARCH > SHA256SUMS
    )
    tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner -czf "$out/$name.tar.gz" -C "$stage" mxioc index.html mxioc-go-release.service install-go.sh VERSION ARCH SHA256SUMS
    cp deploy/install-agent.sh "$stage/"
    (cd "$stage" && sha256sum mxioc-agent install-agent.sh > SHA256SUMS)
    tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner -czf "$out/mxioc-agent-$version-linux-$arch.tar.gz" -C "$stage" mxioc-agent install-agent.sh SHA256SUMS
    rm -rf -- "$stage"
    trap - EXIT
done
(
    cd "$out"
    sha256sum "mxioc-go-$version-linux-amd64.tar.gz" "mxioc-go-$version-linux-arm64.tar.gz" "mxioc-agent-$version-linux-amd64.tar.gz" "mxioc-agent-$version-linux-arm64.tar.gz" > SHA256SUMS
)
printf '%s\n' "$out"
