#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Stage the SDK project and shared transport/intake modules."""

import argparse
import json
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "sdk_app"


def source_bytes(path: Path, commit: str | None) -> bytes:
    if (
        not path.is_file()
        or path.is_symlink()
        or any(
            parent.is_symlink()
            for parent in path.parents
            if parent.is_relative_to(ROOT)
        )
    ):
        raise ValueError(f"Not a regular source file: {path.relative_to(ROOT)}")
    content = path.read_bytes()
    if commit:
        relative = path.relative_to(ROOT).as_posix()
        result = subprocess.run(
            ["git", "--no-replace-objects", "cat-file", "blob", f"{commit}:{relative}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if result.returncode or result.stdout != content:
            raise ValueError(
                f"Source provenance mismatch: {relative} does not match {commit}"
            )
    return content


def source_files():
    for path in PROJECT.rglob("*"):
        parts = path.relative_to(PROJECT).parts
        if any(part.startswith(".") or part == "__pycache__" for part in parts):
            continue
        if path.is_symlink():
            raise ValueError(f"Unexpected symlink in SDK project: {path}")
        if not path.is_file() or path.suffix in {".pyc", ".tgz"}:
            continue
        yield path


def stage(destination: Path, commit: str | None) -> None:
    destination.mkdir()
    for path in sorted(source_files()):
        # The release does not build from tests. A development stage includes them.
        relative = path.relative_to(PROJECT)
        if commit and relative.parts[0] == "tests":
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source_bytes(path, commit))

    if commit:
        paths = (
            subprocess.check_output(
                [
                    "git",
                    "--no-replace-objects",
                    "ls-tree",
                    "-r",
                    "--name-only",
                    "-z",
                    commit,
                    "--",
                    "sdk_app",
                ],
                cwd=ROOT,
            )
            .decode()
            .split("\0")
        )
        for tracked in paths:
            if (
                tracked
                and not tracked.startswith("sdk_app/tests/")
                and not (destination / Path(tracked).relative_to("sdk_app")).is_file()
            ):
                raise ValueError(f"Source provenance mismatch: missing {tracked}")

    for module in ("utils", "ingestion", "es_ingestion", "mail"):
        name = f"ms_quarantine_for_splunk_soar_{module}.py"
        source = source_bytes(ROOT / "app" / name, commit).decode("utf-8")
        target = destination / "src" / name
        with target.open("x", encoding="utf-8") as stream:
            stream.write(
                source.replace(
                    "from ms_quarantine_for_splunk_soar_",
                    "from .ms_quarantine_for_splunk_soar_",
                )
            )
    project = tomllib.loads(
        (destination / "pyproject.toml").read_text(encoding="utf-8")
    )
    with (destination / "src/version.py").open("x", encoding="utf-8") as stream:
        stream.write(f"APP_VERSION = {json.dumps(project['project']['version'])}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New staging directory")
    parser.add_argument(
        "--source-commit", help="Verify staged input bytes against this commit"
    )
    args = parser.parse_args()
    stage(args.destination, args.source_commit)


if __name__ == "__main__":
    main()
