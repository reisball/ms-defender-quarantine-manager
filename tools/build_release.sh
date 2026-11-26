#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
case ${1:-"${repo_dir}/dist"} in
    /*) output_dir=${1:-"${repo_dir}/dist"} ;;
    *) output_dir="$PWD/$1" ;;
esac
cd "$repo_dir"
release_name=ms-defender-quarantine-manager
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
source_commit=$(git --no-replace-objects rev-parse --verify --end-of-options "${SOURCE_COMMIT:-HEAD}^{commit}")

build_tmp=$(mktemp -d)
trap 'rm -rf -- "$build_tmp"' EXIT
mkdir -p "$build_tmp/release"
cp runbook/runbook.ps1 "$build_tmp/runbook.ps1"
git --no-replace-objects cat-file blob "$source_commit:runbook/runbook.ps1" > "$build_tmp/source-runbook.ps1"
if ! cmp -s "$build_tmp/runbook.ps1" "$build_tmp/source-runbook.ps1"; then
    echo "Source provenance mismatch: runbook/runbook.ps1 does not match $source_commit" >&2
    exit 1
fi

bash tools/build_sdk.sh "$build_tmp/app.tgz" "$source_commit"
tar -xOzf "$build_tmp/app.tgz" "MS Defender Quarantine Manager/manifest.json" > "$build_tmp/manifest.json"
app_version=$(jq -er .app_version "$build_tmp/manifest.json")
appid=$(jq -er .appid "$build_tmp/manifest.json")
runbook_version=$(python3 tools/stamp_runbook.py --check --manifest "$build_tmp/manifest.json" --path "$build_tmp/runbook.ps1" | sed -n 's/^runbook_version=//p')

app_artifact="$release_name-$app_version.tgz"
runbook_artifact="$release_name-runbook-$runbook_version.ps1"
mv "$build_tmp/app.tgz" "$build_tmp/release/$app_artifact"
mv "$build_tmp/runbook.ps1" "$build_tmp/release/$runbook_artifact"
jq -n \
    --arg app_version "$app_version" \
    --arg runbook_version "$runbook_version" \
    --arg appid "$appid" \
    --arg source_commit "$source_commit" \
    --argjson source_date_epoch "$SOURCE_DATE_EPOCH" \
    '{app_version:$app_version,runbook_version:$runbook_version,appid:$appid,source_commit:$source_commit,source_date_epoch:$source_date_epoch}' \
    > "$build_tmp/release/BUILD_METADATA.json"
(
    cd "$build_tmp/release"
    sha256sum "$app_artifact" "$runbook_artifact" BUILD_METADATA.json > SHA256SUMS
    chmod 0644 "$app_artifact" "$runbook_artifact" BUILD_METADATA.json SHA256SUMS
)
mkdir -p -- "$output_dir"
for artifact in "$app_artifact" "$runbook_artifact" BUILD_METADATA.json SHA256SUMS; do
    mv -- "$build_tmp/release/$artifact" "$output_dir/$artifact"
done
printf '%s\n' "$output_dir/$app_artifact" "$output_dir/$runbook_artifact" "$output_dir/SHA256SUMS"
