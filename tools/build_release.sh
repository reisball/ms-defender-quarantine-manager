#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=${1:-"${repo_dir}/dist"}
app_dir_name="ms-quarantine-for-splunk-soar"
release_name="ms-defender-quarantine-manager"
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
    source_path="app/${source_file}"
    if [[ "${source_file}" == "LICENSE" ]]; then
        source_path="LICENSE"
    fi
    cp "${source_path}" "${build_tmp}/${app_dir_name}/${source_file}"
done
cp runbook/runbook.ps1 "${build_tmp}/runbook.ps1"

# Verify staged inputs against the selected commit before touching previous
# output. Dependencies are copied offline from the exact manifest/lock set.
wheel_members=$(python3 - "${source_commit}" "${build_tmp}" "${app_dir_name}" <<'VERIFY'
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

commit, staging, app_name = sys.argv[1:]
staging = Path(staging)
app = staging / app_name


def verify(data, source_path):
    result = subprocess.run(
        ["git", "--no-replace-objects", "cat-file", "blob", f"{commit}:{source_path}"],
        capture_output=True,
    )
    if result.returncode or result.stdout != data:
        sys.exit(f"Source provenance mismatch: {source_path} does not match {commit}")


for path in sorted(app.iterdir()):
    verify(path.read_bytes(), "LICENSE" if path.name == "LICENSE" else f"app/{path.name}")
verify((staging / "runbook.ps1").read_bytes(), "runbook/runbook.ps1")

lock_path = "tools/wheel-lock.json"
lock_data = Path(lock_path).read_bytes()
verify(lock_data, lock_path)
lock = json.loads(lock_data)
manifest = json.loads((app / "ms_quarantine_for_splunk_soar.json").read_bytes())
wheel_paths = set()
for key in ("pip39_dependencies", "pip313_dependencies"):
    entries = manifest[key]["wheel"]
    seen_modules = set()
    for entry in entries:
        module, wheel = entry["module"], entry["input_file"]
        if not re.fullmatch(r"wheels/py(?:3|39|313)/[A-Za-z0-9_.-]+\.whl", wheel):
            sys.exit(f"Invalid wheel path in {key}: {wheel}")
        if module in seen_modules or not Path(wheel).name.startswith(f"{module}-"):
            sys.exit(f"Invalid or duplicate wheel module in {key}: {module}")
        seen_modules.add(module)
        wheel_paths.add(wheel)
    if "cryptography" not in seen_modules:
        sys.exit(f"Missing cryptography wheel in {key}")
if wheel_paths != set(lock["wheels"]):
    sys.exit("Manifest dependency wheels do not match tools/wheel-lock.json")

members = set()
for wheel in sorted(wheel_paths):
    dest = app / wheel
    dest.parent.mkdir(parents=True, exist_ok=True)
    source_path = f"app/{wheel}"
    shutil.copyfile(source_path, dest)
    data = dest.read_bytes()
    verify(data, source_path)
    if hashlib.sha256(data).hexdigest() != lock["wheels"][wheel]["sha256"]:
        sys.exit(f"Wheel SHA-256 mismatch: {source_path}")
    members.add(f"{app_name}/{wheel}")
    members.update(f"{app_name}/{parent}/" for parent in Path(wheel).parents if parent != Path("."))
print("\n".join(sorted(members)))
VERIFY
)

manifest="${build_tmp}/${app_dir_name}/ms_quarantine_for_splunk_soar.json"
app_version=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["app_version"])' "${manifest}")
appid=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["appid"])' "${manifest}")
runbook_version=$(python3 tools/stamp_runbook.py --check --manifest "${manifest}" --path "${build_tmp}/runbook.ps1" | sed -n 's/^runbook_version=//p')
# Normalize only staging, never the checkout or caller-owned output directory.
find "${build_tmp}/${app_dir_name}" -type d -exec chmod 0755 {} +
find "${build_tmp}/${app_dir_name}" -type f -exec chmod 0644 {} +

app_artifact="${build_tmp}/release/${release_name}-${app_version}.tgz"
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
    "${app_dir_name}/readme.html" \
    "${wheel_members}" | LC_ALL=C sort)
actual_members=$(tar -tzf "${app_artifact}" | LC_ALL=C sort)
if [[ "${actual_members}" != "${expected_members}" ]]; then
    echo "Legacy SOAR package member contract failed." >&2
    diff -u <(printf '%s\n' "${expected_members}") <(printf '%s\n' "${actual_members}") >&2 || true
    exit 1
fi

runbook_artifact="${build_tmp}/release/${release_name}-runbook-${runbook_version}.ps1"
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
