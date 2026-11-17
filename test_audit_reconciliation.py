# Copyright (c) 2026 Kai Seidenschnur
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Regression probes for audit #112/#113, without live Azure/Exchange calls."""

import json

import pytest


if __package__:
    from . import test_connector as t
else:
    import test_connector as t

T = t.TestIrreversibleOperationReconciliation


@pytest.mark.parametrize("requested", ["release", "deny"])
@pytest.mark.parametrize("error", [False, True])
def test_refresh_rejects_opposite_operation_on_the_real_wire_path(requested, error):
    c = t.make_connector()
    other = "deny" if requested == "release" else "release"
    response = T.read_only_refresh_error(other) if error else T.read_only_refresh_result(other)
    with t.req_mock.Mocker() as m:
        t.mock_full_flow(m, response)
        with pytest.raises(t.AutomationError, match=r"operation_action.*request"):
            c._utils.run_action("reconcile", t.IDENTITY, operation_action=requested)


@pytest.mark.parametrize("requested", ["release", "deny"])
def test_matching_refresh_preserves_existing_contract(requested):
    c = t.make_connector()
    response = T.read_only_refresh_result(requested)
    with t.req_mock.Mocker() as m:
        t.mock_full_flow(m, response)
        assert c._utils.run_action("reconcile", t.IDENTITY, operation_action=requested) == response


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("later", ["historical", "status_error", "running"])
def test_confirmed_refresh_survives_later_job_observations(tmp_path, action, later):
    path = tmp_path / "state.json"
    c = t.make_connector(state_path=path)
    ar = t.patch_ar(c)
    c._utils.get_job_status = lambda *a, **k: {"status": "Completed", "exception": ""}

    def historical(*a, **k):
        raise t.RunbookActionError("unconfirmed", t.postcondition_error_output(action=action))

    c._utils.get_validated_job_output = historical
    c._utils.run_action = lambda *a, **k: T.read_only_refresh_result(action)
    params = T.reconcile_params(operation_id="stable-" + action, action=action)
    params["refresh_exchange_status"] = True
    assert c._handle_reconcile_quarantine_operation(params) == t.APP_SUCCESS
    confirmed = ar.get_data()[-1]
    # Restart must preserve the same durable evidence contract.
    c = t.make_connector(state_path=path)
    ar = t.patch_ar(c)
    c._utils.get_job_status = lambda *a, **k: {"status": "Completed", "exception": ""}
    c._utils.get_validated_job_output = historical
    if later == "status_error":

        def fail(*a, **k):
            raise t.AutomationError("synthetic lookup failed")

        c._utils.get_job_status = fail
    elif later == "running":
        c._utils.get_job_status = lambda *a, **k: {"status": "Running", "exception": ""}
    params["refresh_exchange_status"] = False
    assert c._handle_reconcile_quarantine_operation(params) == t.APP_SUCCESS
    row = ar.get_data()[-1]
    for key in ["state", "status", "handling", "observed_release_status", "last_job_status"]:
        assert row[key] == confirmed[key]
    assert "retained" in ar.get_message().lower()


@pytest.mark.parametrize("action", ["release", "deny"])
def test_failed_azure_job_also_checks_error_operation_binding(action):
    c = t.make_connector()
    other = "deny" if action == "release" else "release"

    def failed(*a, **kw):
        raise t.JobFailedError("synthetic failed job")

    c._utils.poll_job = failed
    c._utils.get_job_output = lambda *a, **kw: T.read_only_refresh_error(other)
    with pytest.raises(t.AutomationError, match=r"operation_action.*request"):
        c._utils.wait_for_action_result(t.JOB_ID, "reconcile", t.IDENTITY, requested_operation_action=action)


@pytest.mark.parametrize("clock", ["forward", "equal", "rollback"])
def test_stale_concurrent_refresh_cannot_replace_newer_confirmation(tmp_path, clock):
    path = tmp_path / "state.json"
    slow = t.make_connector(state_path=path)
    fast = t.make_connector(state_path=path)
    slow_ar = t.patch_ar(slow)
    fast_ar = t.patch_ar(fast)
    op, record = slow._find_or_create_reconciliation_record("concurrent", "release", t.IDENTITY, t.JOB_ID)
    slow._utc_now = lambda: "2026-11-11T10:00:00+00:00"
    fast._utc_now = lambda: {
        "forward": "2026-11-11T10:00:01+00:00",
        "equal": "2026-11-11T10:00:00+00:00",
        "rollback": "2026-11-11T09:59:59+00:00",
    }[clock]
    fast._utils.run_action = lambda *a, **k: T.read_only_refresh_result("release")

    def delayed(*a, **kw):
        # Dispatch happens only after a durable reservation, with the lock released.
        assert slow.load_state()[t.OPERATION_STATE_KEY][op]["exchange_refresh_sequence"] == 1
        assert fast._refresh_operation_exchange_status(fast_ar, record) == t.APP_SUCCESS
        return T.read_only_refresh_result("release", "Denied")

    slow._utils.run_action = delayed
    assert slow._refresh_operation_exchange_status(slow_ar, record) == t.APP_SUCCESS
    assert slow_ar.get_data()[-1]["state"] == "confirmed_success"
    assert slow_ar.get_data()[-1]["observed_release_status"] == "Released"
    saved = slow.load_state()[t.OPERATION_STATE_KEY][op]
    assert saved["observed_release_status"] == "Released"
    assert saved["exchange_refresh_sequence"] == 2
    assert saved["exchange_observation_sequence"] == 2
    assert "_retained_terminal" not in saved


@pytest.mark.parametrize("failure", ["unknown", "transport"])
def test_explicit_failed_refresh_retains_confirmation(tmp_path, failure):
    c = t.make_connector(state_path=tmp_path / "state.json")
    ar = t.patch_ar(c)
    op, record = c._find_or_create_reconciliation_record("keep", "release", t.IDENTITY, t.JOB_ID)
    c._utils.run_action = lambda *a, **k: T.read_only_refresh_result("release")
    assert c._refresh_operation_exchange_status(ar, record) == t.APP_SUCCESS
    ar = t.patch_ar(c)
    _, record = c._find_or_create_reconciliation_record(op, "release", t.IDENTITY, t.JOB_ID)

    def result(*a, **kw):
        if failure == "transport":
            raise t.AutomationError("synthetic read failure")
        return T.read_only_refresh_result("release", "Requested")

    c._utils.run_action = result
    assert c._refresh_operation_exchange_status(ar, record) == t.APP_SUCCESS
    assert ar.get_data()[-1]["observed_release_status"] == "Released"
    assert ar.get_data()[-1]["state"] == "confirmed_success"


@pytest.mark.parametrize("clock", ["equal", "rollback"])
def test_newer_valid_refresh_can_report_a_changed_terminal_observation(tmp_path, clock):
    c = t.make_connector(state_path=tmp_path / "state.json")
    ar = t.patch_ar(c)
    op, record = c._find_or_create_reconciliation_record("newer", "release", t.IDENTITY, t.JOB_ID)
    c._utc_now = lambda: "2026-11-11T10:00:00+00:00"
    c._utils.run_action = lambda *a, **k: T.read_only_refresh_result("release")
    assert c._refresh_operation_exchange_status(ar, record) == t.APP_SUCCESS
    # A process restart must not reset the ordering counter.
    c = t.make_connector(state_path=tmp_path / "state.json")
    c._utc_now = lambda: "2026-11-11T10:00:00+00:00" if clock == "equal" else "2026-11-11T09:59:59+00:00"
    ar = t.patch_ar(c)
    _, record = c._find_or_create_reconciliation_record(op, "release", t.IDENTITY, t.JOB_ID)
    c._utils.run_action = lambda *a, **k: T.read_only_refresh_result("release", "Denied")
    assert c._refresh_operation_exchange_status(ar, record) == t.APP_SUCCESS
    assert ar.get_data()[-1]["state"] == "confirmed_failed"
    assert ar.get_data()[-1]["observed_release_status"] == "Denied"


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("failure", ["postcondition", "rejected", "timeout", "protocol", "webhook"])
def test_original_action_errors_survive_a_concurrent_confirmation(tmp_path, action, failure):
    path = tmp_path / "state.json"
    original = t.make_connector(state_path=path)
    peer = t.make_connector(state_path=path)
    ar = t.patch_ar(original)
    peer_ar = t.patch_ar(peer)
    original._utils.verify_connection_contract = lambda: None
    original._utils.fire_webhook = lambda *a, **k: t.JOB_ID
    peer._utils.run_action = lambda *a, **k: T.read_only_refresh_result(action)
    op = "original-" + action
    errors = {
        "postcondition": t.RunbookActionError("unconfirmed", t.postcondition_error_output(action)),
        "rejected": t.RunbookActionError("rejected", t.disposition_rejected_output(action)),
        "timeout": t.JobTimeoutError("timeout", job_id=t.JOB_ID, last_status="Running"),
        "protocol": t.AutomationError("synthetic protocol failure"),
        "webhook": t.WebhookError("synthetic transport failure"),
    }

    def delayed_error(*a, **k):
        _, record = peer._find_or_create_reconciliation_record(op, action, t.IDENTITY, t.JOB_ID)
        assert peer._refresh_operation_exchange_status(peer_ar, record) == t.APP_SUCCESS
        raise errors[failure]

    if failure == "webhook":
        original._utils.fire_webhook = delayed_error
    else:
        original._utils.wait_for_action_result = delayed_error
    assert original._execute_irreversible_operation(ar, {"operation_id": op}, action, t.IDENTITY) == t.APP_ERROR
    if failure in {"postcondition", "rejected"}:
        assert ar.get_message() == errors[failure].result["message"]
    else:
        assert {"timeout": "timed out", "protocol": "synthetic protocol failure", "webhook": "Webhook outcome"}[failure] in ar.get_message()
    assert "No release or deny cmdlet was executed by reconciliation" not in ar.get_message()
    saved = original.load_state()[t.OPERATION_STATE_KEY][op]
    assert saved["state"] == "confirmed_success"
    assert saved["observed_release_status"] == ("Released" if action == "release" else "Denied")


@pytest.mark.parametrize("source", ["job", "exchange"])
def test_private_observations_redact_and_bound_without_changing_public_diagnostics(tmp_path, source):
    c = t.make_connector(state_path=tmp_path / "state.json")
    ar = t.patch_ar(c)
    op, record = c._find_or_create_reconciliation_record("private-evidence", "release", t.IDENTITY, t.JOB_ID)
    huge = "Authorization: Bearer synthetic-access-token; " + t.CLIENT_SECRET + "🌍" * 20000
    output = T.read_only_refresh_result("release")
    output.update(cmdlet_error=huge, last_verification_error=huge, runbook_version=huge)
    if source == "exchange":
        c._utils.run_action = lambda *a, **k: output
        assert c._refresh_operation_exchange_status(ar, record) == t.APP_SUCCESS
    else:
        c._update_irreversible_operation(
            op, "release", t.IDENTITY, state="outcome_unknown", runbook_version=huge, **c._postcondition_operation_updates(output)
        )
    saved = c.load_state()[t.OPERATION_STATE_KEY][op]
    snapshot = saved["original_job_observation" if source == "job" else "last_exchange_refresh_attempt"]
    encoded = json.dumps(snapshot).encode("utf-8")
    assert len(encoded) <= 4096
    assert t.CLIENT_SECRET not in encoded.decode()
    assert "synthetic-access-token" not in encoded.decode()
    assert "[REDACTED]" in snapshot["runbook_version"]
    assert "cmdlet_error" not in snapshot
    assert "last_verification_error" not in snapshot
    assert snapshot["observed_release_status"] == "Released"
    # Only the new private copies are sanitized; established public diagnostics stay exact.
    assert saved["cmdlet_error"] == huge
    assert saved["last_verification_error"] == huge
    assert c._public_operation_data(saved)["cmdlet_error"] == huge


def test_timestamp_only_registry_can_accept_new_refresh_after_clock_rollback(tmp_path):
    c = t.make_connector(state_path=tmp_path / "state.json")
    ar = t.patch_ar(c)
    op, record = c._find_or_create_reconciliation_record("legacy", "release", t.IDENTITY, t.JOB_ID)
    state = c.load_state()
    state[t.OPERATION_STATE_KEY][op].update(
        state="confirmed_success", observed_release_status="Released", exchange_observation_started_at="2026-11-11T10:00:00+00:00"
    )
    assert c.save_state(state)
    c._utc_now = lambda: "2026-11-11T09:00:00+00:00"
    c._utils.run_action = lambda *a, **k: T.read_only_refresh_result("release", "Denied")
    assert c._refresh_operation_exchange_status(ar, record) == t.APP_SUCCESS
    assert ar.get_data()[-1]["observed_release_status"] == "Denied"
    saved = c.load_state()[t.OPERATION_STATE_KEY][op]
    assert saved["exchange_observation_sequence"] == 1


def test_failed_refresh_reservation_does_not_dispatch(tmp_path):
    c = t.make_connector(state_path=tmp_path / "state.json")
    ar = t.patch_ar(c)
    _, record = c._find_or_create_reconciliation_record("save-fails", "release", t.IDENTITY, t.JOB_ID)
    c.save_state = lambda state: False

    def unexpected_dispatch(*a, **k):
        pytest.fail("Refresh must not dispatch without a durable ordering reservation")

    c._utils.run_action = unexpected_dispatch
    with pytest.raises(t.AutomationError, match="could not be saved"):
        c._refresh_operation_exchange_status(ar, record)
