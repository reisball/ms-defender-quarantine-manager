# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Contracts for upstream preparation boundaries, not upstream acceptance."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from test_build_release import git, source as source


SPEC = importlib.util.spec_from_file_location(
    "soar_checks", Path(__file__).resolve().parents[2] / "tools/soar_checks.py"
)
soar_checks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(soar_checks)


REGISTRY = {
    "valid_app_name_and_guid": "GUID and app not listed in /upstream/appid_to_name.json",
    "app_package_name": "GUID and app package name not listed in /upstream/appid_to_package_name.json",
}


def registry_results():
    return {name: {"success": False, "message": message, "verbose": [message]} for name, message in REGISTRY.items()}


def test_only_exact_missing_registration_is_pending():
    results = registry_results()
    results["schema"] = {"success": True}
    results["metadata"] = {"num_failed": 2}
    pending, failures = soar_checks.classify_static_results(results, REGISTRY)
    assert set(pending) == set(REGISTRY)
    assert not failures


@pytest.mark.parametrize(
    "change",
    [
        {"message": "Invalid GUID: already maps to another app"},
        {"message": "Test execution failed"},
        {"traceback": "Network error"},
        {"fixed": True},
        {"verbose": ["Unexpected additional failure"]},
    ],
)
def test_registry_collisions_and_execution_errors_are_blocking(change):
    results = registry_results()
    results["app_package_name"].update(change)
    pending, failures = soar_checks.classify_static_results(results, REGISTRY)
    assert set(pending) == {"valid_app_name_and_guid"}
    assert "app_package_name" in failures


def test_other_failures_and_missing_required_checks_are_blocking():
    results = registry_results()
    del results["app_package_name"]
    results["schema"] = {"success": False, "noncritical": True, "message": "Invalid output"}
    _, failures = soar_checks.classify_static_results(results, REGISTRY)
    assert set(failures) == {"app_package_name", "schema"}


def test_registered_app_requires_no_exception():
    results = {name: {"success": True} for name in REGISTRY}
    assert soar_checks.classify_static_results(results, REGISTRY) == ({}, {})


def test_empty_result_is_not_success():
    _, failures = soar_checks.classify_static_results({}, REGISTRY)
    assert "runner" in failures


@pytest.mark.parametrize(
    "pending,strict,upstream_exit,mutation,expected_exit,failure",
    [
        (True, False, 2, None, 0, None),
        (True, True, 2, None, 1, None),
        (False, True, 0, None, 0, None),
        (False, False, 2, None, 1, "runner"),
        (True, False, 3, None, 1, "runner"),
        (True, False, 2, "change", 1, "source_mutation"),
        (False, False, 0, "add", 1, "source_mutation"),
        (False, False, 0, "delete", 1, "source_mutation"),
    ],
)
def test_static_orchestration_reports_and_blocks_failures(
    tmp_path, monkeypatch, pending, strict, upstream_exit, mutation, expected_exit, failure
):
    modules = {}
    for name in ("local_hooks", "local_hooks.app_tests", "local_hooks.app_tests.json_tests", "local_hooks.static_tests"):
        modules[name] = ModuleType(name)
        monkeypatch.setitem(sys.modules, name, modules[name])
    registry = modules["local_hooks.app_tests.json_tests"]
    registry.APPID_TO_NAME_FILEPATH = "/upstream/appid_to_name.json"
    registry.APPID_TO_PACKAGE_NAME_FILEPATH = "/upstream/appid_to_package_name.json"
    results = registry_results() if pending else {name: {"success": True} for name in REGISTRY}
    results["schema"] = {"success": True}
    snapshots = []

    def snapshot(destination):
        snapshots.append(destination)
        (destination / "app.py").write_text("original\n")

    class FakeRunner:
        def __init__(self, app_directory):
            self.directory = app_directory

        def run(self):
            source = self.directory / "app.py"
            if mutation == "change":
                source.write_text("changed\n")
            elif mutation == "add":
                (self.directory / "new.py").write_text("added\n")
            elif mutation == "delete":
                source.unlink()
            return upstream_exit, results

    modules["local_hooks.static_tests"].TestRunner = FakeRunner
    monkeypatch.setattr(soar_checks, "source_snapshot", snapshot)
    report_file = tmp_path / "report.json"
    monkeypatch.setenv("SOAR_CHECK_REPORT", str(report_file))
    assert soar_checks.static(strict=strict) == expected_exit
    report = json.loads(report_file.read_text())
    assert report["upstream_exit_code"] == upstream_exit
    assert report["results"] == results
    assert set(report["registration_pending"]) == (set(REGISTRY) if pending else set())
    assert set(report["technical_failures"]) == ({failure} if failure else set())
    if mutation:
        assert report["technical_failures"]["source_mutation"]["files"] == ["new.py" if mutation == "add" else "app.py"]
    assert snapshots and all(not p.exists() for p in snapshots)


def test_snapshot_uses_the_packaged_commit_for_documentation(source, tmp_path, monkeypatch):
    files = ("README.md", "manual_readme_content.md", "release_notes/unreleased.md")
    settings = ("tools/soar-tooling/quality.toml", "tools/soar-tooling/quality-pre-commit.yaml")
    for relative in (*files, *settings):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Frozen documentation\n")
    git(source, "add", *files, *settings)
    git(source, "commit", "-qm", "Frozen documentation")
    commit = git(source, "rev-parse", "HEAD")
    (source / "README.md").write_text("Documentation from a later revision\n")
    for relative in settings:
        (source / relative).write_text("Configuration from a later revision\n")
    git(source, "add", "README.md", *settings)
    git(source, "commit", "-qm", "Later documentation")
    monkeypatch.setattr(soar_checks, "ROOT", source)
    monkeypatch.setenv("SOURCE_COMMIT", commit[:12])
    destination = tmp_path / "projection"
    destination.mkdir()
    soar_checks.source_snapshot(destination)
    assert all((destination / relative).read_text() == "Frozen documentation\n" for relative in files)
    assert (destination / "NOTICE").read_bytes() == (source / "app/NOTICE").read_bytes()
    assert not (destination / "runbook.ps1").exists()

    pre_commit = tmp_path / "pre-commit"
    pre_commit.write_text(
        f"#!{sys.executable}\n"
        "from pathlib import Path\n"
        "for name in ('pyproject.toml', '.pre-commit-config.yaml'):\n"
        "    assert Path(name).read_bytes() == b'Frozen documentation\\n', name\n"
    )
    pre_commit.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path), prepend=":")
    assert soar_checks.quality() == 0


def test_linter_requires_json_and_propagates_startup_failure(tmp_path, monkeypatch):
    # Model the pinned vendor CLI: text mode masks the empty child stdout,
    # while attempting to decode that stdout in JSON mode fails the command.
    linter = tmp_path / "soar-app-linter"
    linter.write_text(
        f"#!{sys.executable}\n"
        "import json, subprocess, sys\n"
        "child = subprocess.run([sys.executable, '-c', "
        "'import sys; sys.exit(32)'], capture_output=True)\n"
        "assert child.returncode == 32 and not child.stdout\n"
        "if '--output-format' in sys.argv and sys.argv[sys.argv.index('--output-format') + 1] == 'json':\n"
        "    json.loads(child.stdout)\n"
    )
    linter.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path), prepend=":")
    assert soar_checks.run_app_linter(tmp_path) != 0
