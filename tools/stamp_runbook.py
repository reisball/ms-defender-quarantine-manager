#!/usr/bin/env python3
"""Verify or update the normalized self-fingerprint in runbook.ps1."""

import argparse
import hashlib
from pathlib import Path
import re
import sys


SOURCE_LINE = re.compile(
    r'(?m)^\$RunbookSourceRevision\s*=\s*"[^"]+"$'
)
BUILD_LINE = re.compile(
    r'(?m)^\$RunbookBuildId\s*=\s*"[^"]+"$'
)
VERSION_LINE = re.compile(
    r'(?m)^\$RunbookVersion\s*=\s*"(\d+\.\d+\.\d+)"$'
)


def canonicalize(text: str) -> str:
    text, source_count = SOURCE_LINE.subn(
        '$RunbookSourceRevision = "<canonical>"',
        text,
    )
    text, build_count = BUILD_LINE.subn(
        '$RunbookBuildId = "<canonical>"',
        text,
    )
    if source_count != 1 or build_count != 1:
        raise ValueError(
            "runbook must contain exactly one source and one build fingerprint"
        )
    return text


def expected_values(text: str):
    version_match = VERSION_LINE.search(text)
    if not version_match:
        raise ValueError("runbook must contain one semantic RunbookVersion")
    version = version_match.group(1)
    digest = hashlib.sha256(canonicalize(text).encode("utf-8")).hexdigest()
    return version, f"sha256:{digest}", f"ms-quarantine-for-splunk-soar-runbook-{version}+sha256.{digest}"


def replace_value(pattern: re.Pattern, text: str, value: str) -> str:
    match = pattern.search(text)
    if not match:
        raise ValueError("fingerprint line is missing")
    prefix = match.group(0).split('"', 1)[0]
    return pattern.sub(f'{prefix}"{value}"', text, count=1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=str(Path(__file__).resolve().parents[1] / "runbook" / "runbook.ps1"))
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    path = Path(args.path)
    raw = path.read_bytes()
    if b"\r\n" in raw:
        raise ValueError("runbook fingerprint contract requires LF line endings")
    text = raw.decode("utf-8")
    version, source_revision, build_id = expected_values(text)

    if args.write:
        text = replace_value(SOURCE_LINE, text, source_revision)
        text = replace_value(BUILD_LINE, text, build_id)
        path.write_bytes(text.encode("utf-8"))

    current_source = SOURCE_LINE.search(text).group(0).split('"', 2)[1]
    current_build = BUILD_LINE.search(text).group(0).split('"', 2)[1]
    valid = current_source == source_revision and current_build == build_id
    print(f"runbook_version={version}")
    print(f"runbook_source_revision={source_revision}")
    print(f"runbook_build_id={build_id}")
    if args.check and not valid:
        print("runbook fingerprint is stale", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
