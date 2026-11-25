"""Check declared SOAR output paths against actual local PowerShell results."""
import json
from pathlib import Path
import re

import pytest
import requests_mock

from test_connector import APP_ERROR, APP_SUCCESS, IDENTITY, make_connector, mock_full_flow
from test_runbook_release_diagnostics import run_fixture


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "app/ms_quarantine_for_splunk_soar.json").read_text())
RUNBOOK = (ROOT / "runbook/runbook.ps1").read_text()
VERSION = MANIFEST["app_version"]
BUILD_ID = re.search(r'^\$RunbookBuildId\s*=\s*"([^"]+)"$', RUNBOOK, re.M)[1]


@pytest.mark.parametrize("action,identifier,terminal", [
    ("release", "release_quarantine_message", "Released"),
    ("deny", "deny_quarantine_release", "Denied"),
])
@pytest.mark.parametrize("case", ["confirmed", "already", "not_executed", "pending", "failed"])
def test_manifest_disposition_result_matches_generated_runbook(action, identifier, terminal, case):
    statuses = {
        "confirmed": f"Requested,{terminal}", "already": terminal,
        "not_executed": "Denied" if action == "release" else "Released",
        "pending": "PreparingToRelease", "failed": "Requested",
    }
    payload = run_fixture(
        action, statuses[case], *(("-CmdletFailure",) if case == "failed" else ())
    )["result"]
    assert payload["runbook_version"] == VERSION
    assert payload["runbook_build_id"] == BUILD_ID

    c = make_connector()
    with requests_mock.Mocker() as mock:
        mock_full_flow(mock, payload, include_version=False, include_postcondition=False)
        method = getattr(c, "_handle_" + identifier)
        expected = APP_SUCCESS if case in {"confirmed", "already"} else APP_ERROR
        assert method({"identity": IDENTITY}) == expected

    result = c._action_results[-1]
    row, = result.get_data()
    summary = result.get_summary()
    declaration = next(a for a in MANIFEST["actions"] if a["identifier"] == identifier)
    paths = {d["data_path"]: d for d in declaration["output"]}
    assert len(paths) == len(declaration["output"])
    assert row["runbook_build_id"] == BUILD_ID
    assert row["runbook_version"] == summary["runbook_version"] == VERSION
    assert summary["outcome"] == ("confirmed" if case == "already" else case)
    assert result.get_message() == row["message"]
    for section, values in (("data.*", row), ("summary", summary)):
        example_fields = {
            "outcome", "status", "last_job_status", "observed_release_status",
            "runbook_version", "message",
        }
        for name in example_fields & values.keys():
            declaration = paths[f"action_result.{section}.{name}"]
            if name != "message" or expected == APP_SUCCESS:
                assert values[name] in declaration.get("example_values", [values[name]])
    if expected == APP_SUCCESS:
        assert "last_job_status" not in row and "last_job_status" not in summary
        assert row["observed_release_status"] == summary["observed_release_status"] == terminal
    else:
        assert "error_code" in row and summary["last_job_status"] == "Completed"


@pytest.mark.parametrize("remote_version, warning", [
    (VERSION, None),
    ("9.9.9", "differs from runbook version"),
    (None, "comparison unavailable"),
    ("synthetic invalid version", "comparison unavailable"),
])
def test_connectivity_compares_versions_not_fingerprints(remote_version, warning):
    c = make_connector()
    with requests_mock.Mocker() as mock:
        mock_full_flow(mock, {
            "action": "list", "messages": [], "count": 0,
            "runbook_version": remote_version, "runbook_build_id": BUILD_ID,
        }, include_version=False)
        assert c._handle_test_connectivity({}) == APP_SUCCESS
    result = c._action_results[-1]
    summary = result.get_summary()
    assert summary["app_version"] == VERSION
    assert summary["runbook_build_id"] == BUILD_ID
    if warning:
        assert warning in summary["version_warning"]
        assert warning in result.get_message()
    else:
        assert summary["runbook_version"] == VERSION
        assert "version_warning" not in summary
