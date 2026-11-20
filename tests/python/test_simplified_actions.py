"""Issue 19: one explicit SOAR request is one write, without durable gates."""
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
import requests_mock

from test_connector import (
    APP_ERROR, APP_SUCCESS, IDENTITY, JOB_ID, WEBHOOK_URL, TOKEN_URL,
    MOCK_TOKEN, JobTimeoutError, job_url, job_output_url, make_connector,
    patch_ar, released_output, mock_full_flow, base_asset_config,
    MSQuarantineForSplunkSOARConnector,
)

ACTIONS = [("release", "release_quarantine_message"),
           ("deny", "deny_quarantine_release")]


@pytest.mark.parametrize("action,handler", ACTIONS)
def test_deliberate_repeat_ignores_old_unknown_operation_without_state_write(tmp_path, action, handler):
    path = tmp_path / "state.json"
    old = {"irreversible_operations": {"legacy": {
        "identity": IDENTITY, "action": action, "state": "outcome_unknown",
        "azure_job_id": "old-job", "operation_id": "legacy",
    }}}
    path.write_text(json.dumps(old))
    before = path.read_bytes()
    with requests_mock.Mocker() as m:
        mock_full_flow(m, released_output(action), include_version=False, include_postcondition=False)
        for _ in range(2):
            c = make_connector(state_path=path)
            c.load_state = Mock(side_effect=AssertionError("dispositions must not read persistent state"))
            c.save_state = Mock(side_effect=AssertionError("dispositions must not write persistent state"))
            c._action_id = handler
            assert c.handle_action({"identity": IDENTITY}) == APP_SUCCESS
            assert c._action_results[-1].get_data()[0]["azure_job_id"] == JOB_ID
        writes = [r.json() for r in m.request_history if r.url == WEBHOOK_URL]
    assert [w["action"] for w in writes] == [action, action]
    assert all("operation_id" not in w for w in writes)
    assert path.read_bytes() == before


@pytest.mark.parametrize("action,handler", ACTIONS)
def test_timeout_is_unknown_and_does_not_retry_post(action, handler):
    c = make_connector()
    ar = patch_ar(c)
    progress = []
    c.save_progress = progress.append
    c._utils.poll_job = Mock(side_effect=JobTimeoutError(
        "still running", job_id=JOB_ID, last_status="Running"))
    with requests_mock.Mocker() as m:
        m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
        c._action_id = handler
        assert c.handle_action({"identity": IDENTITY}) == APP_ERROR
        assert [r.json()["action"] for r in m.request_history] == [action]
    assert JOB_ID in ar.get_message()
    assert "unknown" in ar.get_message().lower()
    assert "may still run" in ar.get_message()
    assert "Azure Automation" in ar.get_message()
    assert ar.get_data()[0]["azure_job_id"] == JOB_ID
    assert ar.get_data()[0]["last_job_status"] == "Running"
    assert any(JOB_ID in message for message in progress)


@pytest.mark.parametrize("action,handler", ACTIONS)
def test_failed_job_keeps_original_error_in_native_result(action, handler):
    c = make_connector()
    ar = patch_ar(c)
    cause = "Exchange unauthorized: native error ID [RequestId=abcd]"
    with requests_mock.Mocker() as m:
        m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
        m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
        m.get(job_url(), json={"properties": {"status": "Failed", "exception": cause}})
        m.get(job_output_url(), json=released_output(action))
        c._action_id = handler
        assert c.handle_action({"identity": IDENTITY}) == APP_ERROR
        assert len([r for r in m.request_history if r.url == WEBHOOK_URL]) == 1
        assert not any(r.url == job_output_url() for r in m.request_history)
    assert cause in ar.get_message()
    assert JOB_ID in ar.get_message()
    assert ar.get_data()[0]["error"] is True


@pytest.mark.parametrize("action,handler", ACTIONS)
def test_runbook_error_preserves_native_details_without_proof_matrix(action, handler):
    c = make_connector()
    ar = patch_ar(c)
    output = {"action": action, "identity": IDENTITY, "error": True,
              "code": "native_exchange_error", "message": "Original Exchange failure\nsecond line",
              "context": {"FullyQualifiedErrorId": "NativeException", "RequestId": "abcd"}}
    with requests_mock.Mocker() as m:
        mock_full_flow(m, output, include_version=False, include_postcondition=False)
        c._action_id = handler
        assert c.handle_action({"identity": IDENTITY}) == APP_ERROR
    assert output["message"] in ar.get_message()
    assert ar.get_data()[0]["context"] == output["context"]
    assert ar.get_data()[0]["code"] == output["code"]


@pytest.mark.parametrize("action,handler", ACTIONS)
def test_ambiguous_webhook_transport_failure_is_not_retried(action, handler):
    c = make_connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        m.post(WEBHOOK_URL, exc=requests.exceptions.ConnectionError("connection lost"))
        c._action_id = handler
        assert c.handle_action({"identity": IDENTITY}) == APP_ERROR
        assert m.call_count == 1
    assert "ConnectionError" in ar.get_message()


def test_default_wait_budget():
    c = MSQuarantineForSplunkSOARConnector()
    c._config = base_asset_config()
    assert c.initialize() == APP_SUCCESS
    assert c._utils._poll_timeout == 600
    assert c._utils._poll_interval == 5


def test_manifest_contains_only_native_actions_without_recovery_parameters():
    manifest = json.loads((Path(__file__).resolve().parents[2] /
                           "app/ms_quarantine_for_splunk_soar.json").read_text())
    assert {a["identifier"] for a in manifest["actions"]} == {
        "test_connectivity", "on_poll", "on_es_poll", "inspect_release_environment",
        "release_quarantine_message", "deny_quarantine_release",
    }
    for action in manifest["actions"]:
        assert "operation_id" not in action.get("parameters", {})
    assert "include_verbose_action_diagnostics" not in manifest["configuration"]


@pytest.mark.parametrize("identifier", [
    "reconcile_quarantine_operation", "reconcile_quarantine_ingestion",
    "get_quarantine_message", "list_quarantine_requests",
])
def test_retired_action_never_dispatches_or_touches_state(identifier):
    c = make_connector()
    c._action_id = identifier
    c.load_state = Mock(side_effect=AssertionError("state read"))
    c.save_state = Mock(side_effect=AssertionError("state write"))
    with requests_mock.Mocker() as m:
        assert c.handle_action({"identity": IDENTITY}) == APP_ERROR
        assert m.call_count == 0
