"""Local, synthetic contract checks for Release and Deny."""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
from unittest.mock import Mock

import pytest
import requests
import requests_mock

from test_connector import (
    APP_ERROR, APP_SUCCESS, IDENTITY, JOB_ID, MOCK_TOKEN, TOKEN_URL, WEBHOOK_URL,
    job_output_url, job_url, make_connector, mock_full_flow, released_output,
)


@pytest.fixture(autouse=True)
def isolate_lock_directory(tmp_path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("TMPDIR", str(tmp_path))


def outcome(connector):
    result = connector._action_results[-1]
    row = result.get_data()[0]
    assert result.get_summary()["outcome"] == row["outcome"]
    return row


def test_lock_rejects_opposite_action_from_separate_worker_and_asset():
    connector = make_connector()
    worker = """
import sys
from unittest.mock import Mock
from test_connector import APP_SUCCESS, IDENTITY, JOB_ID, make_connector, released_output
c = make_connector()
c._asset_id = 700
c._utils.fire_webhook = Mock(return_value=JOB_ID)
def wait(*args, **kwargs):
    print("locked", flush=True)
    sys.stdin.readline()
    return released_output("release")
c._utils.wait_for_action_result = wait
assert c._handle_release_quarantine_message({"identity": IDENTITY.upper()}) == APP_SUCCESS
assert c._utils.fire_webhook.call_count == 1
"""
    child = subprocess.Popen(
        [sys.executable, "-c", worker], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=Path(__file__).parent,
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
    )
    try:
        assert select.select([child.stdout], [], [], 15)[0], "first worker never submitted its job"
        assert child.stdout.readline().strip() == "locked"
        with requests_mock.Mocker() as mock:
            assert connector._handle_deny_quarantine_release({"identity": IDENTITY}) == APP_ERROR
            assert mock.call_count == 0
        row = outcome(connector)
        assert (row["outcome"], row["error_code"]) == ("not_executed", "operation_in_progress")
        with connector._disposition_lock("22222222-2222-2222-2222-222222222222", IDENTITY):
            pass
    finally:
        _, error = child.communicate(input="exit\n", timeout=15)
        assert child.returncode == 0, error
    with requests_mock.Mocker() as mock:
        mock_full_flow(mock, released_output("deny"))
        assert connector._handle_deny_quarantine_release({"identity": IDENTITY}) == APP_SUCCESS
        assert outcome(connector)["outcome"] == "confirmed"


def test_lock_failure_fails_closed_without_job():
    connector = make_connector()
    connector._disposition_lock = Mock(side_effect=PermissionError)
    with requests_mock.Mocker() as mock:
        assert connector._handle_release_quarantine_message({"identity": IDENTITY}) == APP_ERROR
        assert mock.call_count == 0
    row = outcome(connector)
    assert (row["outcome"], row["error_code"]) == ("not_executed", "disposition_lock_unavailable")


@pytest.mark.parametrize("code,expected", [
    ("precondition_unconfirmed", "not_executed"),
    ("disposition_failed", "failed"),
    ("postcondition_unconfirmed", "unknown"),
    ("release_pending", "pending"),
    ("runbook_error", "unknown"),
])
def test_validated_runbook_outcomes(code, expected):
    connector = make_connector()
    with requests_mock.Mocker() as mock:
        mock_full_flow(mock, {
            "action": "release", "identity": IDENTITY, "error": True,
            "message": "native status", "error_code": code,
        })
        assert connector._handle_release_quarantine_message({"identity": IDENTITY}) == APP_ERROR
    row = outcome(connector)
    assert (row["outcome"], row["error_code"], row["azure_job_id"]) == (expected, code, JOB_ID)


@pytest.mark.parametrize("phase", ["webhook", "Stopped", "Suspended", "malformed", "bad_status", "bad_mode", "verbose_bad_mode"])
def test_ambiguous_azure_result_is_unknown_without_replay(phase):
    connector = make_connector()
    with requests_mock.Mocker() as mock:
        if phase == "webhook":
            mock.post(WEBHOOK_URL, exc=requests.exceptions.ConnectionError("lost response"))
        else:
            mock.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            mock.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            status = "Completed" if phase in {"malformed", "bad_status", "bad_mode", "verbose_bad_mode"} else phase
            mock.get(job_url(), json={"properties": {"status": status}})
            if phase == "malformed":
                mock.get(job_output_url(), text="not a disposition result")
            elif phase in {"bad_status", "bad_mode", "verbose_bad_mode"}:
                payload = released_output("deny")
                payload["status" if phase == "bad_status" else "mode"] = []
                if phase == "verbose_bad_mode":
                    mock.get(job_output_url(), text="VERBOSE: waiting\n" + json.dumps(payload))
                else:
                    mock.get(job_output_url(), json=payload)
        assert connector._handle_deny_quarantine_release({"identity": IDENTITY}) == APP_ERROR
        assert sum(r.url == WEBHOOK_URL for r in mock.request_history) == 1
    row = outcome(connector)
    assert (row["outcome"], row["error_code"]) == ("unknown", "outcome_unknown")
    assert row["azure_job_id"] == ("" if phase == "webhook" else JOB_ID)
    assert "Do not retry" in row["message"]


def test_legacy_code_is_classified_consistently_with_published_code():
    connector = make_connector()
    with requests_mock.Mocker() as mock:
        mock_full_flow(mock, {
            "action": "release", "identity": IDENTITY, "error": True,
            "message": "No write performed.", "code": "precondition_unconfirmed",
        })
        assert connector._handle_release_quarantine_message({"identity": IDENTITY}) == APP_ERROR
    row = outcome(connector)
    assert (row["outcome"], row["error_code"]) == ("not_executed", "precondition_unconfirmed")
