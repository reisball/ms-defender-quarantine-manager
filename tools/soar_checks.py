#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Run upstream SOAR tooling with explicit source and ownership boundaries."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def source_snapshot(destination):
    """Copy tracked source, never Git metadata or tool-created environments."""
    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    names = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"], env=git_env).decode().split("\0")
    for name in filter(None, names):
        relative = Path(name)
        source = ROOT / relative
        if relative.is_absolute() or ".." in relative.parts or source.is_symlink():
            raise ValueError(f"Unsafe source path: {name}")
        if not source.is_file():
            raise ValueError(f"Missing tracked source: {name}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def lint():
    # The upstream linter installs a .venv and may add package marker files.
    # Keep that installation outside the checkout without using --no-deps.
    with tempfile.TemporaryDirectory(prefix="msqsoar-lint-") as temporary:
        snapshot = Path(temporary) / "ms_quarantine_for_splunk_soar"
        snapshot.mkdir()
        source_snapshot(snapshot)
        return subprocess.call(["soar-app-linter", "--single-repo", "--message-level", "error", str(snapshot)])


def restore_documentation_owner(text, year):
    """Adapt only the known upstream template footer, never arbitrary attribution."""
    footer = f"\nCopyright {year} Splunk Inc.\n"
    if text.count(footer) != 1:
        raise ValueError("Upstream README ownership template changed; review it before continuing")
    return text.replace(footer, f"\nCopyright {year} Kai Seidenschnur.\n", 1)


def docs():
    # Do not replace the current README if generation, attribution or formatting fails.
    with tempfile.TemporaryDirectory(prefix="msqsoar-docs-") as temporary:
        snapshot = Path(temporary) / "ms_quarantine_for_splunk_soar"
        snapshot.mkdir()
        source_snapshot(snapshot)
        subprocess.run(["build-docs", str(snapshot), "--json-name", "ms_quarantine_for_splunk_soar.json"], check=True)
        readme = snapshot / "README.md"
        text = restore_documentation_owner(readme.read_text(), datetime.now().year)
        readme.write_text(text)
        subprocess.run(["mdformat", str(readme)], cwd=snapshot, check=True)
        (ROOT / "README.md").write_bytes(readme.read_bytes())
    return 0


def classify_static_results(results, registration_messages):
    """Allow only exact missing-registration diagnostics, never collisions/errors."""
    pending = {}
    failures = {}
    for name, result in results.items():
        if name == "metadata":
            continue
        if result.get("success") is True:
            continue
        if (
            name in registration_messages
            and result.get("message") == registration_messages[name]
            and not result.get("traceback")
            and not result.get("fixed")
            and result.get("verbose") == [registration_messages[name]]
        ):
            pending[name] = result
        else:
            failures[name] = result
    for name in registration_messages:
        if name not in results:
            failures[name] = {"message": "Required upstream registry check did not run"}
    if not any(name != "metadata" for name in results):
        failures["runner"] = {"message": "No upstream checks ran"}
    return pending, failures


def static(strict=False):
    # These imports belong to the pinned dev-cicd-tools hook environment, not
    # the app runtime or the separate SOAR linter environment.
    from local_hooks.app_tests.json_tests import (  # pylint: disable=import-error
        APPID_TO_NAME_FILEPATH,
        APPID_TO_PACKAGE_NAME_FILEPATH,
    )
    from local_hooks.static_tests import TestRunner  # pylint: disable=import-error

    messages = {
        "valid_app_name_and_guid": f"GUID and app not listed in {APPID_TO_NAME_FILEPATH}",
        "app_package_name": f"GUID and app package name not listed in {APPID_TO_PACKAGE_NAME_FILEPATH}",
    }
    # The upstream parser ignores any absolute path containing a hidden
    # directory. A clean /tmp snapshot also isolates its possible auto-fixes.
    with tempfile.TemporaryDirectory(prefix="msqsoar-static-") as temporary:
        snapshot = Path(temporary) / "ms_quarantine_for_splunk_soar"
        snapshot.mkdir()
        source_snapshot(snapshot)
        before = {p.relative_to(snapshot): p.read_bytes() for p in snapshot.rglob("*") if p.is_file()}
        exit_code, results = TestRunner(app_directory=snapshot).run()
        pending, failures = classify_static_results(results, messages)
        after = {p.relative_to(snapshot): p.read_bytes() for p in snapshot.rglob("*") if p.is_file()}
        changed = sorted(str(p) for p in before.keys() | after.keys() if before.get(p) != after.get(p))
        if changed:
            failures["source_mutation"] = {"message": "Upstream checks modified source; apply and recheck explicitly", "files": changed}
        if exit_code and not pending and not failures:
            failures["runner"] = {"message": f"Unexplained upstream exit code: {exit_code}"}
        report = {
            "upstream_exit_code": exit_code,
            "registration_pending": pending,
            "technical_failures": failures,
            "results": results,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        if report_path := os.environ.get("SOAR_CHECK_REPORT"):
            Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if pending:
            print("REGISTRATION PENDING: technical preparation is not full upstream acceptance.")
        return int(bool(failures) or (strict and bool(pending)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=["lint", "docs", "static", "static-strict"])
    args = parser.parse_args()
    return {"lint": lint, "docs": docs, "static": static, "static-strict": lambda: static(strict=True)}[args.check]()


if __name__ == "__main__":
    raise SystemExit(main())
