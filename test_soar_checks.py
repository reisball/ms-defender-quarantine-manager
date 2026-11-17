# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""Contracts for upstream preparation boundaries, not upstream acceptance."""

import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tools import soar_checks


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


def test_known_footer_is_adapted_without_replacing_other_attribution():
    text = "Template by Splunk Inc.\n\nCopyright 2026 Splunk Inc.\nLicense text\n"
    actual = soar_checks.restore_documentation_owner(text, 2026)
    assert actual == "Template by Splunk Inc.\n\nCopyright 2026 Kai Seidenschnur.\nLicense text\n"


@pytest.mark.parametrize(
    "text",
    [
        "Copyright 2026 Another owner\n",
        "\nCopyright 2025 Splunk Inc.\n",
        "\nCopyright 2026 Splunk Inc.\n\nCopyright 2026 Splunk Inc.\n",
    ],
)
def test_changed_or_ambiguous_template_requires_review(text):
    with pytest.raises(ValueError, match="template changed"):
        soar_checks.restore_documentation_owner(text, 2026)


def test_linter_uses_disposable_source_and_propagates_failure(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "untracked_secret").write_text("not a fixture input")
    monkeypatch.setattr(soar_checks, "ROOT", root)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"app.py\0")
    snapshots = []

    def fake_linter(command):
        snapshot = Path(command[-1])
        snapshots.append(snapshot)
        assert snapshot != root
        assert (snapshot / "app.py").read_text() == "x = 1\n"
        assert not (snapshot / "untracked_secret").exists()
        assert "--no-deps" not in command
        (snapshot / ".venv").mkdir()
        (snapshot / "app.py").write_text("mutated")
        return 2

    monkeypatch.setattr(subprocess, "call", fake_linter)
    assert soar_checks.lint() == 2
    assert (root / "app.py").read_text() == "x = 1\n"
    assert not (root / ".venv").exists()
    assert all(not p.exists() for p in snapshots)


@pytest.mark.parametrize("name", ["../outside.py", "/outside.py", "link.py", "missing.py"])
def test_snapshot_rejects_unsafe_or_missing_source(tmp_path, monkeypatch, name):
    root = tmp_path / "source"
    root.mkdir()
    (tmp_path / "outside.py").write_text("outside")
    (root / "link.py").symlink_to(tmp_path / "outside.py")
    destination = tmp_path / "copy"
    destination.mkdir()
    monkeypatch.setattr(soar_checks, "ROOT", root)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: (name + "\0").encode())
    with pytest.raises(ValueError):
        soar_checks.source_snapshot(destination)
    assert not list(destination.iterdir())


def test_documentation_generator_failure_preserves_existing_readme(tmp_path, monkeypatch):
    original = tmp_path / "README.md"
    original.write_text("Reviewed documentation\n")
    monkeypatch.setattr(soar_checks, "ROOT", tmp_path)
    monkeypatch.setattr(soar_checks, "source_snapshot", lambda destination: None)

    def broken_generator(command, **kwargs):
        (Path(command[1]) / "README.md").write_text("Partial output")
        raise subprocess.CalledProcessError(2, command)

    monkeypatch.setattr(subprocess, "run", broken_generator)
    with pytest.raises(subprocess.CalledProcessError):
        soar_checks.docs()
    assert original.read_text() == "Reviewed documentation\n"


def test_snapshot_discovery_ignores_foreign_git_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/foreign/repository/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/foreign/repository")

    def inspect_discovery(command, **kwargs):
        assert command[:3] == ["git", "-C", str(soar_checks.ROOT)]
        assert not any(k.startswith("GIT_") for k in kwargs["env"])
        return b""

    monkeypatch.setattr(subprocess, "check_output", inspect_discovery)
    soar_checks.source_snapshot(tmp_path)


@pytest.mark.parametrize(
    "pending,strict,upstream_exit,mutation,expected_exit,failure",
    [
        (True, False, 1, None, 0, None),
        (True, True, 1, None, 1, None),
        (False, True, 0, None, 0, None),
        (False, False, 2, None, 1, "runner"),
        (True, False, 1, "change", 1, "source_mutation"),
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
