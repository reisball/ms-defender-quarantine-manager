#!/usr/bin/env python3
# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Run upstream SOAR tooling with explicit source and ownership boundaries."""

import argparse
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def source_snapshot(destination, *, extras=()):
    """Project the verified legacy reference TGZ into the root layout upstream expects."""
    with tempfile.TemporaryDirectory(prefix="msqsoar-package-") as temporary:
        out = Path(temporary)
        subprocess.run(["bash", str(ROOT / "tools/build_legacy_reference.sh"), str(out)], cwd=ROOT, check=True)
        commit = json.loads((out / "BUILD_METADATA.json").read_bytes())["source_commit"]
        package, = out.glob("*.tgz")
        with tarfile.open(package) as archive:
            for member in archive:
                parts = Path(member.name).parts
                if not parts or parts[0] != "ms-quarantine-for-splunk-soar" or ".." in parts:
                    raise ValueError(f"Unexpected archive path: {member.name}")
                if member.isdir():
                    continue
                if not member.isfile() or len(parts) < 2:
                    raise ValueError(f"Unexpected archive member: {member.name}")
                target = destination.joinpath(*parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source:
                    with target.open("xb") as output:
                        output.write(source.read())
        docs = ("README.md", "manual_readme_content.md", "release_notes/unreleased.md")
        for relative, projected in (tuple((path, path) for path in docs) + extras):
            target = destination / projected
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(subprocess.check_output(
                ["git", "--no-replace-objects", "cat-file", "blob", f"{commit}:{relative}"], cwd=ROOT
            ))


def quality():
    """Run the applicable repository hooks against the tracked release projection."""
    with tempfile.TemporaryDirectory(prefix="msqsoar-quality-", dir="/tmp") as temporary:
        snapshot = Path(temporary)
        source_snapshot(snapshot, extras=(
            ("tools/soar-tooling/quality.toml", "pyproject.toml"),
            ("tools/soar-tooling/quality-pre-commit.yaml", ".pre-commit-config.yaml"),
        ))
        subprocess.run(["git", "init", "-q"], cwd=snapshot, check=True)
        subprocess.run(["git", "add", "--all"], cwd=snapshot, check=True)
        return subprocess.call(["pre-commit", "run", "--all-files", "--show-diff-on-failure"], cwd=snapshot)


def sdk_quality(package):
    """Run the pinned quality hooks on the shipped SDK source and metadata."""
    with tempfile.TemporaryDirectory(prefix="msdq-sdk-quality-") as temporary:
        snapshot = Path(temporary)
        with tarfile.open(package) as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != "MS Defender Quarantine Manager" or ".." in parts:
                    raise ValueError(f"Unexpected SDK archive path: {member.name}")
                relative = parts[1:]
                if not relative or relative[0] == "wheels" or member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f"Unexpected SDK archive member: {member.name}")
                target = snapshot.joinpath(*relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("xb") as output:
                    output.write(source.read())
        (snapshot / "pyproject.toml").write_bytes(
            (ROOT / "tools/soar-tooling/sdk-quality.toml").read_bytes()
        )
        (snapshot / ".pre-commit-config.yaml").write_bytes(
            (ROOT / "tools/soar-tooling/quality-pre-commit.yaml").read_bytes()
        )
        subprocess.run(["git", "init", "-q"], cwd=snapshot, check=True)
        subprocess.run(["git", "add", "--all"], cwd=snapshot, check=True)
        return subprocess.call(
            ["pre-commit", "run", "--all-files", "--show-diff-on-failure"], cwd=snapshot
        )


def copyright_audit():
    """Report changes suggested by the time-dependent vendor copyright hook."""
    with tempfile.TemporaryDirectory(prefix="msqsoar-copyright-", dir="/tmp") as temporary:
        snapshot = Path(temporary)
        source_snapshot(snapshot)
        before = {p: p.read_bytes() for p in snapshot.rglob("*") if p.is_file()}
        subprocess.run(["copyright-updates", str(snapshot), "--copyright", "Kai Seidenschnur"], check=True)
        after = {p: p.read_bytes() for p in snapshot.rglob("*") if p.is_file()}
        changes = sorted(str(p.relative_to(snapshot)) for p in before.keys() | after.keys()
                         if before.get(p) != after.get(p))
        for filename in changes:
            print(f"Review copyright change: {filename}")
        return int(bool(changes))


def lint():
    # The upstream linter installs a .venv and may add package marker files.
    # Keep that installation outside the checkout without using --no-deps.
    with tempfile.TemporaryDirectory(prefix="msqsoar-lint-", dir="/tmp") as temporary:
        snapshot = Path(temporary) / "ms_quarantine_for_splunk_soar"
        snapshot.mkdir()
        source_snapshot(snapshot)
        manifest = json.loads((snapshot / "ms_quarantine_for_splunk_soar.json").read_bytes())
        wheels = [str(snapshot / entry["input_file"]) for entry in manifest["pip313_dependencies"]["wheel"]]
        python = snapshot / ".venv/bin/python"
        uv = [sys.executable, "-m", "uv"]
        # This linter creates an inner venv and otherwise installs the latest
        # pylint from PyPI there. Seed it with the same pinned tooling and the
        # actual 3.13 runtime wheels; keep dependency checks enabled.
        subprocess.run([sys.executable, "-m", "venv", str(python.parent.parent)], check=True)
        subprocess.run([
            *uv, "pip", "sync", "--python", str(python),
            "--build-constraints", str(ROOT / "tools/soar-tooling/build-constraints.txt"),
            str(ROOT / "tools/soar-tooling/lint.txt"),
        ], check=True)
        subprocess.run([*uv, "pip", "install", "--python", str(python), "--no-deps", *wheels], check=True)
        subprocess.run([*uv, "pip", "check", "--python", str(python)], check=True)
        return run_app_linter(snapshot)


def run_app_linter(snapshot):
    # The vendor text parser treats empty stdout as success even if Pylint
    # aborted. JSON mode rejects invalid output and keeps the vendor filters.
    return subprocess.call(
        ["soar-app-linter", "--single-repo", "--message-level", "error",
         "--output-format", "json", str(snapshot)],
        env={**os.environ, "PIP_NO_INDEX": "1"},
    )


def release_notes():
    with tempfile.TemporaryDirectory(prefix="msqsoar-notes-", dir="/tmp") as temporary:
        snapshot = Path(temporary)
        source_snapshot(snapshot)
        notes = snapshot / "release_notes/unreleased.md"
        before = notes.read_bytes()
        result = subprocess.call(["release-notes", str(snapshot)])
        if before != notes.read_bytes():
            print("Upstream release-notes hook rewrote the committed notes.")
            return 1
        return result


def docs():
    # Validate the upstream projection without replacing the maintained README.
    with tempfile.TemporaryDirectory(prefix="msqsoar-docs-", dir="/tmp") as temporary:
        snapshot = Path(temporary) / "ms_quarantine_for_splunk_soar"
        snapshot.mkdir()
        source_snapshot(snapshot)
        return subprocess.call(["build-docs", str(snapshot), "--json-name", "ms_quarantine_for_splunk_soar.json"])


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


def static(strict=False, *, sdk=False):
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
    with tempfile.TemporaryDirectory(prefix="msqsoar-static-", dir="/tmp") as temporary:
        snapshot = Path(temporary) / "ms_quarantine_for_splunk_soar"
        if sdk:
            subprocess.run([sys.executable, str(ROOT / "tools/stage_sdk.py"), str(snapshot)], check=True)
        else:
            snapshot.mkdir()
            source_snapshot(snapshot)
        before = {p.relative_to(snapshot): p.read_bytes() for p in snapshot.rglob("*") if p.is_file()}
        exit_code, results = TestRunner(app_directory=snapshot).run()
        pending, failures = classify_static_results(results, messages)
        after = {p.relative_to(snapshot): p.read_bytes() for p in snapshot.rglob("*") if p.is_file() and not {".venv", "__pycache__"}.intersection(p.relative_to(snapshot).parts)}
        changed = sorted(str(p) for p in before.keys() | after.keys() if before.get(p) != after.get(p))
        if changed:
            failures["source_mutation"] = {"message": "Upstream checks modified source; apply and recheck explicitly", "files": changed}
        if exit_code != len(pending) and not failures:
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
    parser.add_argument("check", choices=["sdk-quality", "sdk-static", "quality", "copyright", "lint", "docs", "notes", "static", "static-strict"])
    parser.add_argument("package", type=Path, nargs="?")
    args = parser.parse_args()
    if args.check == "sdk-quality":
        if args.package is None:
            parser.error("sdk-quality requires an SDK package")
        return sdk_quality(args.package)
    if args.package is not None:
        parser.error("package is only supported for sdk-quality")
    return {"sdk-static": lambda: static(sdk=True), "quality": quality, "copyright": copyright_audit, "lint": lint, "docs": docs, "notes": release_notes, "static": static, "static-strict": lambda: static(strict=True)}[args.check]()


if __name__ == "__main__":
    raise SystemExit(main())
