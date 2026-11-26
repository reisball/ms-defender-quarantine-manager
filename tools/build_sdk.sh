#!/usr/bin/env bash
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:?Usage: tools/build_sdk.sh OUTPUT.tgz [SOURCE_COMMIT]}
stage_options=()
if [[ -n "${2:-}" ]]; then
    stage_options=(--source-commit "$2")
fi
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
export LC_ALL=C TZ=UTC PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1
python3 "$root/tools/stage_sdk.py" "$scratch/project" "${stage_options[@]}"
(
    cd -- "$scratch/project"
    uv run --locked --no-dev --python 3.13 soarapps package build -o "$scratch/inventory.tgz"
)
python3 "$root/tools/render_sdk_notice.py" "$scratch/inventory.tgz" "$scratch/verified.tgz" \
    --package-output --project "$scratch/project" --epoch "$SOURCE_DATE_EPOCH" "${stage_options[@]}"
cp -- "$scratch/verified.tgz" "$output"
sha256sum -- "$output"
