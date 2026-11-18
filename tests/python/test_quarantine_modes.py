"""Offline paired selection contract tests. No tenant or SOAR requests."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest
import requests_mock

# A git-archive snapshot may have a valid package directory name ("source").
# Import its fixture module in the same namespace as pytest's collection so
# it is not executed twice and does not replace the shared phantom SDK stubs.
if __package__:
    from .test_connector import (
        APP_ERROR, APP_SUCCESS, IDENTITY, ORG, MSQuarantineForSplunkSOARConnector,
        AutomationError, RunbookActionError, base_asset_config, build_metadata,
        config_check_output, dispatch_flow, make_connector, make_utils, patch_ar,
        released_output, JOB_ID, TOKEN_URL, MOCK_TOKEN, WEBHOOK_URL, job_url, job_output_url,
    )
else:
    from test_connector import (
        APP_ERROR, APP_SUCCESS, IDENTITY, ORG, MSQuarantineForSplunkSOARConnector,
        AutomationError, RunbookActionError, base_asset_config, build_metadata,
        config_check_output, dispatch_flow, make_connector, make_utils, patch_ar,
        released_output, JOB_ID, TOKEN_URL, MOCK_TOKEN, WEBHOOK_URL, job_url, job_output_url,
    )

ROOT = Path(__file__).resolve().parents[1] / "powershell"
MODE_EVIDENCE = {
    "quarantine_selection_mode": "needs_review",
    "quarantine_selection_contract": "quarantine_selection_v1",
    "selection_release_status": "NotReleased",
}


def selected(output):
    return {**output, **MODE_EVIDENCE, "runbook_version": "3.4.3"}


def connector(**config):
    return make_connector(config_overrides={
        "quarantine_selection_mode": "needs_review", "exchange_organization": ORG, **config,
    })


@pytest.mark.parametrize("value", [None, "", "release_requested"])
def test_upgrade_keeps_requested_default(value):
    c = make_connector(config_overrides={"quarantine_selection_mode": value})
    assert c._utils.selection_release_status == "Requested"


@pytest.mark.parametrize("value", [False, 1, [], {}, "all", "NotReleased", "NEEDS_REVIEW"])
def test_invalid_asset_mode_rejected_before_http(value):
    c = MSQuarantineForSplunkSOARConnector()
    c._config = {**base_asset_config(), "quarantine_selection_mode": value}
    with requests_mock.Mocker() as m:
        assert c.initialize() == APP_ERROR
        assert not m.called


@pytest.mark.parametrize("action", ["list", "release", "deny"])
def test_old_runbook_cannot_silently_ignore_needs_review(action):
    utils = make_utils(quarantine_selection_mode="needs_review")
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {"config_check": config_check_output()})
        with pytest.raises(AutomationError, match="3.4.3"):
            utils.run_action(action, identity=IDENTITY if action != "list" else None)
    assert [b["action"] for b in bodies] == ["config_check"]


@pytest.mark.parametrize("field,value", [
    ("quarantine_selection_mode", "release_requested"),
    ("selection_release_status", "Requested"),
    ("quarantine_selection_contract", "v0"),
])
def test_mismatched_handshake_sends_no_disposition(field, value):
    c = connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {
            "config_check": {**selected(config_check_output()), field: value},
        })
        assert c._handle_release_quarantine_message({
            "identity": IDENTITY, "operation_id": "mismatch",
        }) == APP_ERROR
    assert [b["action"] for b in bodies] == ["config_check"]
    assert "No operation was claimed" in ar.get_message()


def test_list_payload_and_result_use_same_mode():
    c = connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {
            "config_check": selected(config_check_output()),
            "list": selected({"action": "list", "count": 1,
                              "messages": [{"Identity": IDENTITY,
                                            "ReleaseStatus": "NotReleased"}],
                              **build_metadata()}),
        })
        assert c._handle_list_quarantine_requests({"max_results": 1}) == APP_SUCCESS
    assert [b["action"] for b in bodies] == ["config_check", "list"]
    assert all(b["quarantine_selection_mode"] == "needs_review" for b in bodies)
    assert bodies[-1]["page_size"] == 1
    assert "NotReleased" in ar.get_message()


@pytest.mark.parametrize("status", ["Requested", "Released", "Denied", "", None])
def test_wrong_status_candidate_fails_closed(status):
    c = connector()
    with pytest.raises(AutomationError, match="NotReleased"):
        c._normalise_list_result({"count": 1, "messages": [
            {"Identity": IDENTITY, "ReleaseStatus": status},
        ]})


@pytest.mark.parametrize("action,handler", [
    ("release", "_handle_release_quarantine_message"),
    ("deny", "_handle_deny_quarantine_release"),
])
def test_paired_disposition_and_replay_send_one_write(action, handler):
    c = connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {
            "config_check": selected(config_check_output()),
            action: selected(released_output(action)),
        })
        params = {"identity": IDENTITY, "operation_id": "mode-replay-" + action}
        assert getattr(c, handler)(params) == APP_SUCCESS, ar.get_message()
        count = len(m.request_history)
        assert getattr(c, handler)(params) == APP_SUCCESS, ar.get_message()
        assert len(m.request_history) == count
    assert [b["action"] for b in bodies] == ["config_check", action]
    assert bodies[-1]["quarantine_selection_mode"] == "needs_review"


def test_poll_reservations_dedup_and_refuse_unresolved_mode_switch():
    c = connector()
    c._ingest_settings()
    message = {"Identity": IDENTITY, "ReleaseStatus": "NotReleased"}
    c._ingest_reserve([message], 10, 10)
    c._ingest_reserve([message], 10, 10)
    assert len(c._ingest_records()) == 1
    c._utils = make_utils()
    with pytest.raises(AutomationError, match="scope mismatch"):
        c._ingest_records()


def run_ps(filename, *args):
    executable = shutil.which("pwsh")
    if not executable:
        pytest.skip("PowerShell is not available")
    result = subprocess.run([executable, "-NoLogo", "-NoProfile", "-File",
                             str(ROOT / filename), *args],
                            text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()
            if line.startswith("{")]
    assert rows, result.stdout
    return rows[-1]


@pytest.mark.parametrize("action,terminal", [("release", "Released"), ("deny", "Denied")])
@pytest.mark.parametrize("mode,initial", [("release_requested", "Requested"),
                                          ("needs_review", "NotReleased")])
def test_actual_runbook_success_envelope_validates_in_paired_app(action, terminal, mode, initial):
    output = run_ps("test_runbook_irreversible_action.ps1", "-Action", action,
                    "-SelectionMode", mode, "-StatusSequence", f"{initial},{terminal}")
    utils = make_utils(quarantine_selection_mode=mode)
    utils._validate_runbook_result(output, action, IDENTITY)
    utils._raise_for_runbook_error(output, action, IDENTITY)
    assert output["cmdlet_invocation_attempted"] is True
    assert output["observed_release_status"] == terminal
    assert json.loads(output["precondition_trace"])[0]["observed_release_status"] == initial


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("mode,wrong", [("release_requested", "NotReleased"),
                                        ("needs_review", "Requested")])
def test_actual_runbook_wrong_precondition_never_invokes_cmdlet(action, mode, wrong):
    output = run_ps("test_runbook_irreversible_action.ps1", "-Action", action,
                    "-SelectionMode", mode, "-StatusSequence", wrong, "-ForbidCmdlet")
    assert output["error_code"] == "precondition_unconfirmed"
    utils = make_utils(quarantine_selection_mode=mode)
    utils._validate_runbook_result(output, action, IDENTITY)
    with pytest.raises(RunbookActionError):
        utils._raise_for_runbook_error(output, action, IDENTITY)
    assert output["details"]["cmdlet_invocation_attempted"] is False


@pytest.mark.parametrize("action", ["release", "deny"])
def test_actual_runbook_unchanged_needs_review_rejection_is_not_success(action):
    output = run_ps("test_runbook_irreversible_action.ps1", "-Action", action,
                    "-SelectionMode", "needs_review", "-StatusSequence", "NotReleased",
                    "-AuthorizationFailure")
    assert output["error_code"] == "disposition_rejected"
    utils = make_utils(quarantine_selection_mode="needs_review")
    utils._validate_runbook_result(output, action, IDENTITY)
    with pytest.raises(RunbookActionError):
        utils._raise_for_runbook_error(output, action, IDENTITY)

@pytest.mark.parametrize("mode", ["release_requested", "needs_review"])
@pytest.mark.parametrize("count", [0, 1, 2, 1000])
def test_actual_list_transport_preserves_selection_and_empty_array(mode, count):
    executable = shutil.which("pwsh")
    if not executable:
        pytest.skip("PowerShell is not available")
    result = subprocess.run([
        executable, "-NoLogo", "-NoProfile", "-File",
        str(ROOT / "test_runbook_list_contract.ps1"), "-SelectionMode", mode,
        "-MessageCount", str(count), "-SubjectLength", "1200", "-RawOutput",
    ], text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    utils = make_utils(quarantine_selection_mode=mode)
    output = utils._parse_multiline_job_output(result.stdout)
    utils._validate_runbook_result(output, "list")
    assert output["count"] == count
    assert len(output["messages"]) == count
    assert output["quarantine_selection_mode"] == mode
    expected = "NotReleased" if mode == "needs_review" else "Requested"
    assert all(m["ReleaseStatus"] == expected for m in output["messages"])
    if count == 1000:
        assert '"list_complete"' in result.stdout


@pytest.mark.parametrize("value", [False, 1, [], {}, "all", "NEEDS_REVIEW", ""])
def test_actual_runbook_invalid_mode_connects_to_nothing(value):
    output = run_ps("test_runbook_connection_contract.ps1", "-RequestJson", json.dumps({
        "action": "release", "identity": "__IDENTITY__",
        "quarantine_selection_mode": value,
    }))
    assert output["result"]["error_code"] == "invalid_quarantine_selection_mode"
    assert output["connect_calls"] == []
    assert output["release_calls"] == 0
    assert output["quarantine_reads"] == 0
    assert output["variable_reads"] == []


def test_actual_needs_review_handshake_has_no_exchange_side_effects():
    output = run_ps("test_runbook_connection_contract.ps1", "-RequestJson", json.dumps({
        "action": "config_check", "organization": ORG,
        "auth_method": "ManagedIdentity", "quarantine_selection_mode": "needs_review",
    }))
    utils = make_utils(quarantine_selection_mode="needs_review", exchange_organization=ORG)
    utils._validate_runbook_result(output["result"], "config_check")
    assert output["connect_calls"] == []
    assert output["release_calls"] == output["quarantine_reads"] == 0
    assert output["get_module_calls"] == 0


def test_connectivity_rejects_old_runbook_without_unhandled_exception():
    c = connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {"config_check": config_check_output()})
        assert c._handle_test_connectivity({}) == APP_ERROR
    assert [b["action"] for b in bodies] == ["config_check"]
    assert "Publish Runbook 3.4.3" in ar.get_message()


@pytest.mark.parametrize("mutation", ["trailer", "chunk"])
def test_chunked_selection_mismatch_is_rejected(mutation):
    utils = make_utils(quarantine_selection_mode="needs_review")
    chunk = selected({"action": "list", "mode": "list_chunk", "chunk_index": 0,
                      "messages": [{"Identity": IDENTITY, "ReleaseStatus": "NotReleased"}],
                      **build_metadata()})
    trailer = selected({"action": "list", "mode": "list_complete", "chunk_count": 1,
                        "count": 1, **build_metadata()})
    (trailer if mutation == "trailer" else chunk)["selection_release_status"] = "Requested"
    with pytest.raises(AutomationError, match="selection contract mismatch"):
        utils._parse_chunked_list_records([chunk, trailer])

@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("cmdlet_error", [False, True])
def test_needs_review_unchanged_after_command_stays_unknown_not_success(action, cmdlet_error):
    args = ["-Action", action, "-SelectionMode", "needs_review",
            "-StatusSequence", "NotReleased"]
    if cmdlet_error:
        args.append("-CmdletFailure")
    output = run_ps("test_runbook_irreversible_action.ps1", *args)
    assert output["error_code"] == "postcondition_unconfirmed"
    assert output["details"]["handling"] == "reconcile_before_retry"
    assert output["details"]["cmdlet_invocation_attempted"] is True
    assert output["details"]["observed_release_status"] == "NotReleased"
    utils = make_utils(quarantine_selection_mode="needs_review")
    utils._validate_runbook_result(output, action, IDENTITY)
    with pytest.raises(RunbookActionError):
        utils._raise_for_runbook_error(output, action, IDENTITY)


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("mode", ["release_requested", "needs_review"])
def test_disposition_result_must_match_selected_mode(action, mode):
    utils = make_utils(quarantine_selection_mode=mode)
    output = selected(released_output(action))
    if mode == "needs_review":
        output.update(quarantine_selection_mode="release_requested",
                      selection_release_status="Requested")
    with pytest.raises(AutomationError, match="selection contract mismatch"):
        utils._validate_runbook_result(output, action, IDENTITY)


@pytest.mark.parametrize("action", ["release", "deny"])
def test_needs_review_disposition_requires_selection_echo(action):
    utils = make_utils(quarantine_selection_mode="needs_review")
    with pytest.raises(AutomationError, match="selection contract mismatch"):
        utils._validate_runbook_result(released_output(action), action, IDENTITY)


@pytest.mark.parametrize("action", ["list", "config_check"])
def test_default_mode_rejects_nondefault_echo(action):
    output = config_check_output() if action == "config_check" else {
        "action": "list", "count": 0, "messages": [], **build_metadata(),
    }
    with pytest.raises(AutomationError, match="selection contract mismatch"):
        make_utils()._validate_runbook_result(selected(output), action)


@pytest.mark.parametrize("mutation", ["none", "mode", "status", "count", "action"])
def test_connectivity_validates_paired_list_contract(mutation):
    c = connector()
    ar = patch_ar(c)
    output = selected({"action": "list", "count": 1, "messages": [
        {"Identity": IDENTITY, "ReleaseStatus": "NotReleased"},
    ], **build_metadata()})
    if mutation == "mode":
        output.update(quarantine_selection_mode="release_requested",
                      selection_release_status="Requested")
    elif mutation == "status":
        output["messages"][0]["ReleaseStatus"] = "Requested"
    elif mutation == "count":
        output["count"] = 2
    elif mutation == "action":
        output["action"] = "export"
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {
            "config_check": selected(config_check_output()), "list": output,
        })
        rc = c._handle_test_connectivity({})
    assert rc == (APP_SUCCESS if mutation == "none" else APP_ERROR), ar.get_message()
    assert [b["action"] for b in bodies] == ["config_check", "list"]


@pytest.mark.parametrize("original_mode", ["release_requested", "needs_review"])
@pytest.mark.parametrize("action", ["release", "deny"])
def test_pending_operation_requires_original_mode_and_recovers_without_write(
        tmp_path, original_mode, action):
    state_path = tmp_path / "asset_state.json"
    params = {"azure_job_id": JOB_ID, "expected_action": action,
              "expected_identity": IDENTITY, "operation_id": "mode-switch",
              "refresh_exchange_status": True}
    other_mode = "needs_review" if original_mode == "release_requested" else "release_requested"
    output = released_output(action)
    if original_mode == "needs_review":
        output = selected(output)
    for mode, azure_status, expected in (
        (original_mode, "Running", APP_SUCCESS),
        (other_mode, "Completed", APP_ERROR),
        (original_mode, "Completed", APP_SUCCESS),
    ):
        c = make_connector(state_path=state_path, config_overrides={
            "quarantine_selection_mode": mode,
        })
        ar = patch_ar(c)
        with requests_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": azure_status}})
            m.get(job_output_url(), text=json.dumps(output))
            assert c._handle_reconcile_quarantine_operation(params) == expected, ar.get_message()
            assert not any(r.url == WEBHOOK_URL for r in m.request_history)
        if mode == other_mode:
            assert ar.get_summary()["status"] == "outcome_unknown"
            assert "restore its original asset selection mode" in ar.get_message()
        elif azure_status == "Completed":
            assert ar.get_summary()["status"] == "confirmed_success"
