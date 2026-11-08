#!/usr/bin/env bash
# Source-tree entry point: build native Go release archives; no Python installer.
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ $# != 1 ]]; then
    printf '%s\n' 'Usage: bash install.sh VERSION' 'Builds local Go release archives. Extract the archive for your architecture, then run install-go.sh fresh or install.' >&2
    exit 2
fi
exec bash deploy/build-go-release.sh "$1"
