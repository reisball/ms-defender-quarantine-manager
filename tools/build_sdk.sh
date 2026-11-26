#!/usr/bin/env bash
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:?Usage: tools/build_sdk.sh OUTPUT.tgz}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
python3 "$root/tools/stage_sdk.py" "$scratch/project"
builder=(uvx --python 3.13 --from splunk-soar-sdk==8.0.2 soarapps package build "$scratch/project")
"${builder[@]}" -o "$scratch/inventory.tgz"
python3 "$root/tools/render_sdk_notice.py" "$scratch/inventory.tgz" "$scratch/verified.tgz" --package-output
cp -- "$scratch/verified.tgz" "$output"
sha256sum -- "$output"
