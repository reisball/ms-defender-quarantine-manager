"""Requested-only intake contracts, exercised offline with mocked Exchange."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest
import requests_mock

if __package__:
    from .test_connector import (
        APP_SUCCESS, IDENTITY, ORG, RunbookActionError,
        build_metadata, config_check_output, dispatch_flow, make_connector,
        make_utils, patch_ar, released_output,
    )
else:
    from test_connector import (
        APP_SUCCESS, IDENTITY, ORG, RunbookActionError,
        build_metadata, config_check_output, dispatch_flow, make_connector,
        make_utils, patch_ar, released_output,
    )

ROOT = Path(__file__).resolve().parents[1] / "powershell"


@pytest.mark.parametrize("value", [None, "", "release_requested", "needs_review", "all"])
def test_obsolete_asset_setting_cannot_change_requested_intake(value):
    c = make_connector(config_overrides={
        "quarantine_selection_mode": value, "exchange_organization": ORG,
    })
    assert c._utils.selection_release_status == "Requested"
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {
            "config_check": config_check_output(),
            "list": {"action": "list", "count": 1, "messages": [
                {"Identity": IDENTITY, "ReleaseStatus": "Requested"},
            ], **build_metadata()},
        })
        assert c._handle_list_quarantine_requests({}) == APP_SUCCESS, ar.get_message()
    assert [b["action"] for b in bodies] == ["list"]
    assert all("quarantine_selection_mode" not in b for b in bodies)
    assert ar.get_data()[0]["ReleaseStatus"] == "Requested"


@pytest.mark.parametrize("action,handler", [
    ("release", "_handle_release_quarantine_message"),
    ("deny", "_handle_deny_quarantine_release"),
])
def test_disposition_does_not_require_or_send_selection_handshake(action, handler):
    c = make_connector(config_overrides={
        "quarantine_selection_mode": "needs_review", "exchange_organization": ORG,
    })
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        bodies = dispatch_flow(m, {
            "config_check": config_check_output(), action: released_output(action),
        })
        assert getattr(c, handler)({
            "identity": IDENTITY, "operation_id": "requested-only-" + action,
        }) == APP_SUCCESS, ar.get_message()
    assert [b["action"] for b in bodies] == ["config_check", action]
    assert all("quarantine_selection_mode" not in b for b in bodies)


def run_ps(filename, *args):
    executable = shutil.which("pwsh")
    if not executable:
        pytest.skip("PowerShell is not available")
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-File", str(ROOT / filename), *args],
        text=True, capture_output=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize("action,terminal", [("release", "Released"), ("deny", "Denied")])
def test_requested_disposition_validates_without_selection_echo(action, terminal):
    raw = run_ps("test_runbook_irreversible_action.ps1", "-Action", action,
                 "-SelectionMode", "needs_review",
                 "-StatusSequence", f"Requested,{terminal}")
    output = [json.loads(line) for line in raw.splitlines() if line.startswith("{")][-1]
    utils = make_utils()
    utils._validate_runbook_result(output, action, IDENTITY)
    utils._raise_for_runbook_error(output, action, IDENTITY)
    assert output["cmdlet_invocation_attempted"] is True
    assert output["observed_release_status"] == terminal
    assert json.loads(output["precondition_trace"])[0]["observed_release_status"] == "Requested"
    assert "quarantine_selection_mode" not in output


@pytest.mark.parametrize("action", ["release", "deny"])
def test_legacy_needs_review_cannot_invoke_disposition_for_notreleased(action):
    raw = run_ps("test_runbook_irreversible_action.ps1", "-Action", action,
                 "-SelectionMode", "needs_review", "-StatusSequence", "NotReleased",
                 "-ForbidCmdlet")
    output = [json.loads(line) for line in raw.splitlines() if line.startswith("{")][-1]
    assert output["error_code"] == "precondition_unconfirmed"
    utils = make_utils()
    utils._validate_runbook_result(output, action, IDENTITY)
    with pytest.raises(RunbookActionError):
        utils._raise_for_runbook_error(output, action, IDENTITY)
    assert output["details"]["cmdlet_invocation_attempted"] is False


@pytest.mark.parametrize("count", [0, 1, 1000])
def test_runbook_lists_requested_only_despite_legacy_webhook_setting(count):
    raw = run_ps("test_runbook_list_contract.ps1", "-SelectionMode", "needs_review",
                 "-MessageCount", str(count), "-SubjectLength", "1200", "-RawOutput")
    utils = make_utils()
    output = utils._parse_multiline_job_output(raw)
    utils._validate_runbook_result(output, "list")
    assert output["count"] == len(output["messages"]) == count
    assert all(m["ReleaseStatus"] == "Requested" for m in output["messages"])
    assert "quarantine_selection_mode" not in output
    if count == 1000:
        assert '"list_complete"' in raw


def test_config_check_ignores_obsolete_selection_field():
    raw = run_ps("test_runbook_connection_contract.ps1", "-RequestJson", json.dumps({
        "action": "config_check", "organization": ORG,
        "auth_method": "ManagedIdentity", "quarantine_selection_mode": "needs_review",
    }))
    output = [json.loads(line) for line in raw.splitlines() if line.startswith("{")][-1]
    make_utils(exchange_organization=ORG)._validate_runbook_result(output["result"], "config_check")
    assert "quarantine_selection_contract" not in output["result"]
    assert output["connect_calls"] == []
    assert output["release_calls"] == output["quarantine_reads"] == 0
