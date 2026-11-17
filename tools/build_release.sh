#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=${1:-"${repo_dir}/dist"}
app_dir_name="ms-quarantine-for-splunk-soar"
python3 "${repo_dir}/tools/render_readme.py" --check
cd "${repo_dir}"

source_epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
# Resolve the override once, but keep packaging the caller's working-tree bytes.
# A different commit is allowed only when all delivered source bytes match it.
source_commit=$(git --no-replace-objects rev-parse --verify --end-of-options "${SOURCE_COMMIT:-HEAD}^{commit}")

build_tmp=$(mktemp -d)
cleanup() {
    rm -rf -- "${build_tmp}"
}
trap cleanup EXIT

mkdir -p "${build_tmp}/${app_dir_name}" "${build_tmp}/release"
for source_file in \
    __init__.py \
    LICENSE \
    NOTICE \
    readme.html \
    ms_quarantine_for_splunk_soar.json \
    ms_quarantine_for_splunk_soar_connector.py \
    ms_quarantine_for_splunk_soar_utils.py \
    ms_quarantine_for_splunk_soar_ingestion.py \
    ms_quarantine_for_splunk_soar_es_ingestion.py \
    ms_quarantine_for_splunk_soar.svg \
    ms_quarantine_for_splunk_soar_dark.svg; do
    cp "${source_file}" "${build_tmp}/${app_dir_name}/${source_file}"
done
cp runbook.ps1 "${build_tmp}/runbook.ps1"

# Verify the exact staged bytes, including the separately shipped runbook,
# before touching any previous successful output. Index/status cleanliness is
# not the contract: unrelated docs/tests/output may remain dirty or untracked.
python3 - "${source_commit}" "${build_tmp}" "${app_dir_name}" <<'VERIFY'
from pathlib import Path
import subprocess
import sys

commit, staging, app_name = sys.argv[1:]
staging = Path(staging)
inputs = sorted((staging / app_name).iterdir()) + [staging / "runbook.ps1"]
for path in inputs:
    result = subprocess.run(
        ["git", "--no-replace-objects", "cat-file", "blob", f"{commit}:{path.name}"],
        capture_output=True,
    )
    if result.returncode or result.stdout != path.read_bytes():
        sys.exit(f"Source provenance mismatch: {path.name} does not match {commit}")
VERIFY

manifest="${build_tmp}/${app_dir_name}/ms_quarantine_for_splunk_soar.json"
app_version=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["app_version"])' "${manifest}")
appid=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["appid"])' "${manifest}")
runbook_version=$(python3 tools/stamp_runbook.py --check --path "${build_tmp}/runbook.ps1" | sed -n 's/^runbook_version=//p')
# Normalize only staging, never the checkout or caller-owned output directory.
find "${build_tmp}/${app_dir_name}" -type d -exec chmod 0755 {} +
find "${build_tmp}/${app_dir_name}" -type f -exec chmod 0644 {} +

app_artifact="${build_tmp}/release/${app_dir_name}-${app_version}.tgz"
tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@${source_epoch}" \
    -cf - -C "${build_tmp}" "${app_dir_name}" \
    | gzip -n > "${app_artifact}.tmp"
mv "${app_artifact}.tmp" "${app_artifact}"

expected_members=$(printf '%s\n' \
    "${app_dir_name}/" \
    "${app_dir_name}/LICENSE" \
    "${app_dir_name}/NOTICE" \
    "${app_dir_name}/__init__.py" \
    "${app_dir_name}/ms_quarantine_for_splunk_soar.json" \
    "${app_dir_name}/ms_quarantine_for_splunk_soar.svg" \
    "${app_dir_name}/ms_quarantine_for_splunk_soar_connector.py" \
    "${app_dir_name}/ms_quarantine_for_splunk_soar_dark.svg" \
    "${app_dir_name}/ms_quarantine_for_splunk_soar_utils.py" \
    "${app_dir_name}/ms_quarantine_for_splunk_soar_es_ingestion.py" \
    "${app_dir_name}/ms_quarantine_for_splunk_soar_ingestion.py" \
    "${app_dir_name}/readme.html" | LC_ALL=C sort)
actual_members=$(tar -tzf "${app_artifact}" | LC_ALL=C sort)
if [[ "${actual_members}" != "${expected_members}" ]]; then
    echo "Legacy SOAR package member contract failed." >&2
    diff -u <(printf '%s\n' "${expected_members}") <(printf '%s\n' "${actual_members}") >&2 || true
    exit 1
fi

runbook_artifact="${build_tmp}/release/ms-quarantine-for-splunk-soar-runbook-${runbook_version}.ps1"
mv "${build_tmp}/runbook.ps1" "${runbook_artifact}"

jq -n \
    --arg app_version "${app_version}" \
    --arg runbook_version "${runbook_version}" \
    --arg appid "${appid}" \
    --arg source_commit "${source_commit}" \
    --argjson source_date_epoch "${source_epoch}" \
    '{app_version:$app_version,runbook_version:$runbook_version,appid:$appid,source_commit:$source_commit,source_date_epoch:$source_date_epoch}' \
    > "${build_tmp}/release/BUILD_METADATA.json"

(
    cd "${build_tmp}/release"
    sha256sum \
        "$(basename "${app_artifact}")" \
        "$(basename "${runbook_artifact}")" \
        BUILD_METADATA.json \
        > SHA256SUMS
)

find "${build_tmp}/release" -type f -exec chmod 0644 {} +
mkdir -p "${output_dir}"
for artifact in "${app_artifact}" "${runbook_artifact}" "${build_tmp}/release/BUILD_METADATA.json" "${build_tmp}/release/SHA256SUMS"; do
    mv "${artifact}" "${output_dir}/$(basename "${artifact}")"
done
printf '%s\n' "${output_dir}/$(basename "${app_artifact}")" "${output_dir}/$(basename "${runbook_artifact}")" "${output_dir}/SHA256SUMS"
