"""Check declared SOAR output paths against actual local PowerShell results."""
from collections import defaultdict
import json
from pathlib import Path
import re

import pytest
import requests_mock

from test_connector import (
    APP_ERROR, APP_SUCCESS, IDENTITY, JobTimeoutError, JOB_ID, MOCK_TOKEN, TOKEN_URL,
    WEBHOOK_URL, job_url, make_connector, mock_full_flow, released_output,
)
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
def test_manifest_disposition_result_matches_generated_runbook(action, identifier, terminal):
    cases = {
        "confirmed": f"Requested,{terminal}",
        "already": terminal,
        "not_executed": "Denied" if action == "release" else "Released",
        "pending": "PreparingToRelease",
        "failed": "Requested",
    }
    observed = defaultdict(set)

    def observe(c, expected, expected_outcome):
        result = c._action_results[-1]
        row, = result.get_data()
        summary = result.get_summary()
        assert summary["outcome"] == row["outcome"] == expected_outcome
        assert result.get_message() == row["message"]
        assert result.get_status() == expected
        for section, values in (("data.*", row), ("summary", summary), ("parameter", result.param),
                                ("", {"status": "success" if expected == APP_SUCCESS else "failed",
                                      "message": result.get_message()})):
            for name, value in values.items():
                if isinstance(value, (str, bool, int)):
                    path = ".".join(filter(None, ("action_result", section, name)))
                    observed[path].add(value)
        return row, summary

    for case, statuses in cases.items():
        report = run_fixture(action, statuses, *(("-CmdletFailure",) if case == "failed" else ()))
        payload = report["result"]
        assert payload["runbook_version"] == VERSION
        assert payload["runbook_build_id"] == BUILD_ID
        c = make_connector()
        expected = APP_SUCCESS if case in {"confirmed", "already"} else APP_ERROR
        with requests_mock.Mocker() as mock:
            mock_full_flow(mock, payload, include_version=False, include_postcondition=False)
            assert getattr(c, "_handle_" + identifier)({"identity": IDENTITY}) == expected
        row, summary = observe(c, expected, "confirmed" if case == "already" else case)
        assert row["runbook_build_id"] == BUILD_ID
        assert row["runbook_version"] == summary["runbook_version"] == VERSION
        if expected == APP_SUCCESS:
            assert "last_job_status" not in row and "last_job_status" not in summary
            assert row["observed_release_status"] == summary["observed_release_status"] == terminal
        else:
            assert "error_code" in row and summary["last_job_status"] == "Completed"

    for job_status in ("Running", "Stopped"):
        c = make_connector()
        if job_status == "Running":
            def timed_out(*args, **kwargs):
                raise JobTimeoutError("still running", job_id=JOB_ID, last_status=job_status)
            c._utils.poll_job = timed_out
        with requests_mock.Mocker() as mock:
            mock.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            mock.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            mock.get(job_url(), json={"properties": {"status": job_status}})
            assert getattr(c, "_handle_" + identifier)({"identity": IDENTITY}) == APP_ERROR
        row, _ = observe(c, APP_ERROR, "unknown")
        assert row["last_job_status"] == job_status

    declaration = next(a for a in MANIFEST["actions"] if a["identifier"] == identifier)
    paths = {d["data_path"]: d for d in declaration["output"]}
    assert len(paths) == len(declaration["output"])
    # SOAR adds these action-level counters; the connector only emits
    # action_result.* paths. Verify their declarations separately from fixtures.
    platform_counters = {"summary.total_objects", "summary.total_objects_successful"}
    assert platform_counters <= paths.keys()
    assert all(paths[path]["data_type"] == "numeric" for path in platform_counters)
    assert not paths.keys() - platform_counters - observed.keys()
    assert paths["action_result.data.*.outcome"]["column_order"] == 1
    stable_example_fields = {"outcome", "status", "last_job_status", "observed_release_status", "runbook_version"}
    for path, entry in paths.items():
        if path.rsplit(".", 1)[1] in stable_example_fields:
            assert set(entry.get("example_values", [])) <= observed[path], path


@pytest.mark.parametrize("action,identifier", [
    ("release", "release_quarantine_message"), ("deny", "deny_quarantine_release"),
])
def test_preserve_disposition_summary_defaults(action, identifier):
    c = make_connector()
    handle = getattr(c, "_handle_" + identifier)
    with requests_mock.Mocker() as mock:
        assert handle({"identity": ""}) == APP_ERROR
        assert mock.call_count == 0
        old_output = released_output(action)
        old_output.pop("runbook_version", None)
        mock_full_flow(mock, old_output, include_version=False, include_postcondition=False)
        assert handle({"identity": IDENTITY}) == APP_SUCCESS
    first, second = c._action_results
    assert first.get_summary()["azure_job_id"] == first.get_summary()["last_job_status"] == ""
    assert second.get_summary()["runbook_version"] == ""


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
