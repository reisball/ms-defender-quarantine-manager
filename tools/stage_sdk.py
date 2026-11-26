#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Stage an isolated SDK project using the shared transport/intake modules."""

import argparse
import shutil
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New staging directory")
    destination = parser.parse_args().destination
    shutil.copytree(
        ROOT / "sdk_app",
        destination,
        ignore=shutil.ignore_patterns(".*", "__pycache__", "*.tgz"),
    )
    for module in ("utils", "ingestion", "es_ingestion", "mail"):
        name = f"ms_quarantine_for_splunk_soar_{module}.py"
        source = (ROOT / "app" / name).read_text(encoding="utf-8")
        # Match the same modules under the SDK loader's src package.
        (destination / "src" / name).write_text(
            source.replace(
                "from ms_quarantine_for_splunk_soar_",
                "from .ms_quarantine_for_splunk_soar_",
            ),
            encoding="utf-8",
        )
    project = tomllib.loads(
        (destination / "pyproject.toml").read_text(encoding="utf-8")
    )
    (destination / "src/version.py").write_text(
        f"APP_VERSION = {project['project']['version']!r}\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
