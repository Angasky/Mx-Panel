#!/usr/bin/env bash
# Runs on a clean GitHub-hosted Ubuntu VM with a real systemd manager.
set -Eeuo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID == 0 ]]
[[ $# == 2 ]]
old_binary=$(realpath -- "$1")
new_binary=$(realpath -- "$2")
cd -- "$(dirname -- "$0")"
base=/opt/mxioc-go
data=/opt/mxioc-rule-manager
auth=/etc/mxioc-rule-manager.auth.json
unit=/etc/systemd/system/mxioc-go.service
for target in "$base" "$data" "$auth" "$unit"; do
    [[ ! -e "$target" && ! -L "$target" ]] || { echo "Fixture requires unused path: $target" >&2; exit 1; }
done
[[ $(ps -p 1 -o comm=) == systemd ]]
stage=$(mktemp -d)
cleanup() {
    rc=$?
    if ((rc != 0)); then
        journalctl -u mxioc-go.service -u 'mxioc-go-test-*' --no-pager -n 100 >&2 || true
    fi
    if [[ -L "$base/current" && -f "$unit" ]]; then
        bash "$stage/old/install-go.sh" uninstall || true
    fi
    rm -rf -- "$stage"
    exit "$rc"
}
trap cleanup EXIT

make_bundle() {
    local dir="$1" binary="$2" version="$3"
    mkdir -- "$dir"
    install -m 0755 "$binary" "$dir/mxioc"
    install -m 0644 ../index.html mxioc-go-release.service install-go.sh "$dir/"
    printf '%s\n' "$version" > "$dir/VERSION"
    printf 'amd64\n' > "$dir/ARCH"
    (cd -- "$dir"; sha256sum mxioc index.html mxioc-go-release.service VERSION ARCH > SHA256SUMS)
}
expect_health() {
    curl -fsS --max-time 5 http://127.0.0.1:62578/healthz | grep -F "\"version\":\"$1\""
    curl -fsS --max-time 5 --head http://127.0.0.1:62578/admin/ >/dev/null
}
apply_bundle() {
    local name="$1" bundle="$2" expected="$3"
    systemd-run --quiet --wait --collect --unit="mxioc-go-test-$name.service" \
        --property=Type=exec --property=RuntimeMaxSec=3min --property=TimeoutStopSec=45s \
        --setenv="MXIOC_GO_EXPECT_CURRENT=$expected" /bin/bash "$bundle/install-go.sh" update
}

make_bundle "$stage/old" "$old_binary" v0.0.1
make_bundle "$stage/new" "$new_binary" v0.0.2
# The checksum and archive metadata pass, but the running binary reports v0.0.1.
make_bundle "$stage/mismatch" "$old_binary" v0.0.3
printf '%s\n' 'ci-lifecycle-fixture-password' | "$old_binary" --root "$data" --auth "$auth" --bootstrap-user ci-admin
bash "$stage/old/install-go.sh" install
expect_health v0.0.1
old=$(readlink -- "$base/current")
apply_bundle success "$stage/new" "$old"
current=$(readlink -- "$base/current")
[[ "$old" != "$current" ]]
expect_health v0.0.2
if apply_bundle rollback "$stage/mismatch" "$current"; then
    echo "Mismatched binary unexpectedly passed the health gate." >&2
    exit 1
fi
[[ $(readlink -- "$base/current") == "$current" ]]
expect_health v0.0.2
bash "$stage/old/install-go.sh" uninstall
[[ ! -e "$unit" && ! -L "$base/current" && -f "$auth" && -d "$data" ]]
"$new_binary" --root "$data" --auth "$auth" --check-data
echo 'systemd lifecycle passed: install, upgrade, rollback, and uninstall with data retained'
