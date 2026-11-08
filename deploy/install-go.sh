#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

base=/opt/mxioc-go
data=/opt/mxioc-rule-manager
auth=/etc/mxioc-rule-manager.auth.json
unit=/etc/systemd/system/mxioc-go.service
service=mxioc-go.service
legacy=mxioc-rule-manager.service
bundle=$(cd -- "$(dirname -- "$0")" && pwd -P)
action=${1:-}
die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 1 && "$action" =~ ^(fresh|install|update|uninstall)$ ]] || die "Usage: sudo bash install-go.sh {fresh|install|update|uninstall}"
[[ $EUID == 0 && $(uname -s) == Linux ]] || die "Linux root access is required."
for command in flock systemctl install readlink; do
    command -v "$command" >/dev/null || die "Missing command: $command"
done
exec 9>/run/lock/mxioc-go-release.lock
flock -n 9 || die "A Go release operation is already running."

if [[ "$action" == uninstall ]]; then
    [[ -L "$base/current" && -f "$unit" ]] || die "No managed Go installation found."
    current=$(readlink -f -- "$base/current")
    [[ $(dirname -- "$current") == "$base/releases" ]] || die "Unexpected release path."
    if [[ -n ${MXIOC_GO_EXPECT_CURRENT:-} ]]; then
        [[ "$current" == "$MXIOC_GO_EXPECT_CURRENT" ]] || die "Installed version changed before removal."
        cmp -s "$current/mxioc-go-release.service" "$unit" || die "Installed systemd unit differs from this release."
    fi
    purge=${MXIOC_GO_PURGE_DATA:-0}
    [[ "$purge" == 0 || "$purge" == 1 ]] || die "Invalid data removal option."
    if [[ "$purge" == 1 ]]; then
        [[ -n ${MXIOC_GO_EXPECT_CURRENT:-} ]] || die "Data removal requires a version-bound uninstall job."
        if systemctl is-active --quiet "$legacy" || systemctl is-enabled --quiet "$legacy"; then
            die "Python service still uses the shared data; data removal refused."
        fi
        [[ -d "$data" && ! -L "$data" && $(readlink -f -- "$data") == "$data" ]] || die "Unexpected data directory."
        [[ -f "$auth" && ! -L "$auth" && $(readlink -f -- "$auth") == "$auth" ]] || die "Unexpected credential path."
        command -v findmnt >/dev/null || die "findmnt is required for data removal."
        # Do not traverse mounted filesystems inside the data directory.
        mount_table=$(findmnt -rn -o TARGET) || die "Mount inventory unavailable."
        while IFS= read -r mount_path; do
            [[ "$mount_path" != "$data" && "$mount_path" != "$data/"* ]] || die "Mounted data cannot be purged."
        done <<< "$mount_table"
    fi
    # Keep enough local state to undo a partial removal. The release lock
    # remains held throughout rollback, including service restoration.
    was_active=0
    was_enabled=0
    systemctl is-active --quiet "$service" && was_active=1
    systemctl is-enabled --quiet "$service" && was_enabled=1
    original_link=$(readlink -- "$base/current")
    removal_stage=$(mktemp -d "$base/.remove.XXXXXXXX")
    if ! cp -p -- "$unit" "$removal_stage/unit"; then
        rmdir -- "$removal_stage"
        die "Could not preserve the installed unit before removal."
    fi
    rollback_removal() {
        local status=$? restored=1
        trap - EXIT HUP INT TERM
        if (( status != 0 )); then
            cp -p -- "$removal_stage/unit" "$unit" || restored=0
            if [[ ! -e "$base/current" && ! -L "$base/current" ]]; then
                ln -s -- "$original_link" "$base/current" || restored=0
            elif [[ ! -L "$base/current" || $(readlink -- "$base/current") != "$original_link" ]]; then
                restored=0
            fi
            systemctl daemon-reload || restored=0
            if (( restored )); then
                if (( was_enabled )); then
                    systemctl enable "$service" || restored=0
                fi
                if (( was_active )); then
                    systemctl start "$service" || restored=0
                fi
            fi
            if (( restored )); then
                printf 'Removal failed; previous installation and service state restored.\n' >&2
            else
                printf 'Removal failed; restoration is incomplete. Recovery unit retained at %s/unit.\n' "$removal_stage" >&2
            fi
        fi
        if (( restored )); then
            rm -rf -- "$removal_stage"
        fi
        exit "$status"
    }
    trap rollback_removal EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    systemctl disable --now "$service"
    rm -- "$unit" "$base/current"
    systemctl daemon-reload
    if [[ "$purge" == 1 ]]; then
        # Deletion is irreversible: never restart the service against partially
        # removed data. Leave a recovery unit for diagnosis on deletion failure.
        trap - EXIT HUP INT TERM
        if ! rm -rf --one-file-system -- "$data" || ! rm -f -- "$auth"; then
            die "Service removed; data removal incomplete. Check data paths before reinstalling."
        fi
        rm -rf -- "$removal_stage"
        printf 'Go service and local subscription data, backups and credentials removed. Remote nodes and cached releases are preserved.\n'
    else
        printf 'Go service removed. Subscription data, credentials and cached releases are preserved.\n'
    fi
    exit 0
fi

for command in sha256sum curl; do
    command -v "$command" >/dev/null || die "Missing command: $command"
done
case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) die "Unsupported architecture." ;;
esac
cd -- "$bundle"
# Check the manifest names before asking sha256sum to open any paths.
expected_files=$'mxioc\nindex.html\nmxioc-go-release.service\nVERSION\nARCH'
[[ $(awk '/^[0-9a-f]{64}  [a-zA-Z0-9._-]+$/ {print substr($0,67)}' SHA256SUMS) == "$expected_files" ]] ||
    die "Invalid release manifest."
[[ $(wc -l < SHA256SUMS) == 5 ]] || die "Invalid release manifest."
sha256sum --strict --check SHA256SUMS
version=$(cat VERSION)
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ && $(cat ARCH) == "$arch" ]] ||
    die "Release version or architecture does not match."
if systemctl is-active --quiet "$legacy" || systemctl is-enabled --quiet "$legacy"; then
    die "Stop and disable the Python service before installing Go against the same data."
fi
if [[ "$action" == fresh ]]; then
    [[ ! -e "$data" && ! -L "$data" && ! -e "$auth" && ! -L "$auth" ]] ||
        die "Fresh installation requires unused data and credential paths."
    [[ -t 0 ]] || die "Fresh installation requires a terminal for credential setup."
elif [[ ! -d "$data" || ! -f "$auth" ]]; then
    die "Existing subscription data and administrator credentials are required."
fi
if [[ "$action" != update ]]; then
    [[ ! -e "$unit" && ! -L "$base/current" ]] || die "Use update for an existing Go installation."
else
    [[ -f "$unit" && -L "$base/current" ]] || die "Use install for a new Go installation."
    cmp -s mxioc-go-release.service "$unit" || die "Installed systemd unit differs from this release."
fi

install -d -m 0755 "$base" "$base/releases"
stage=$(mktemp -d "$base/releases/.stage.XXXXXXXX")
old=$(readlink -- "$base/current" || true)
if [[ "$action" == update && -n "${MXIOC_GO_EXPECT_CURRENT:-}" && "$old" != "$MXIOC_GO_EXPECT_CURRENT" ]]; then
    rmdir -- "$stage"
    die "Current release changed while the update was downloading."
fi
switched=0
unit_created=0
wait_healthy() {
    local expected="${1:-}" health attempt
    for ((attempt=0; attempt<20; attempt++)); do
        if systemctl is-active --quiet "$service" &&
            health=$(curl -fsS --max-time 2 http://127.0.0.1:62578/healthz) &&
            grep -Fq '"runtime":"go"' <<< "$health" &&
            { [[ -z "$expected" ]] || grep -Fq "\"version\":\"$expected\"" <<< "$health"; } &&
            curl -fsS --max-time 2 --head http://127.0.0.1:62578/admin/ >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}
rollback() {
    rc=$?
    trap - EXIT
    rm -rf -- "$stage"
    rm -f -- "$base/.current-new"
    if ((rc != 0 && switched)); then
        if [[ -n "$old" ]]; then
            if ln -s -- "$old" "$base/.current-new" && mv -Tf -- "$base/.current-new" "$base/current" &&
                systemctl restart "$service" && wait_healthy; then
                printf 'Previous Go release restored.\n' >&2
            else
                printf 'Previous Go release could not be restarted. Check systemctl status.\n' >&2
            fi
        else
            systemctl disable --now "$service" || true
            rm -f -- "$base/current"
        fi
    fi
    if ((rc != 0 && unit_created)); then
        rm -f -- "$unit"
        systemctl daemon-reload || true
    fi
    exit "$rc"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
install -m 0755 mxioc "$stage/mxioc"
install -m 0644 index.html "$stage/index.html"
if [[ "$action" == fresh ]]; then
    read -r -p 'Administrator username: ' username
    read -rs -p 'Administrator password: ' password
    printf '\n'
    read -rs -p 'Repeat password: ' repeat
    printf '\n'
    [[ -n "$username" && "$password" == "$repeat" ]] || die "Username is empty or passwords do not match."
    printf '%s\n' "$password" | "$stage/mxioc" --root "$data" --auth "$auth" --bootstrap-user "$username"
    unset password repeat
fi
"$stage/mxioc" --root "$data" --auth "$auth" --check-data

release=$(mktemp -d "$base/releases/$version.XXXXXXXX")
install -m 0755 "$stage/mxioc" "$release/mxioc"
install -m 0644 "$stage/index.html" "$release/index.html"
if [[ "$action" != update ]]; then
    unit_created=1
    install -m 0644 mxioc-go-release.service "$unit"
    systemctl daemon-reload
fi
ln -s -- "$release" "$base/.current-new"
switched=1
mv -Tf -- "$base/.current-new" "$base/current"
systemctl restart "$service"
wait_healthy "${MXIOC_GO_EXPECT_CURRENT:+$version}" || die "Go service did not pass HTTP checks."
if [[ "$action" != update ]]; then
    systemctl enable "$service"
fi
printf 'Go release %s is running on 127.0.0.1:62578.\n' "$version"
