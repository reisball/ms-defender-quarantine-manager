"""Release audit: case-stable claims, immutable jobs and idempotent evidence."""
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests_mock

from test_connector import (
    APP_ERROR, APP_SUCCESS, IDENTITY, JOB_ID, MOCK_TOKEN, TOKEN_URL,
    AutomationError, TestIrreversibleOperationReconciliation as Fixtures,
    job_url, job_output_url, make_connector, patch_ar, make_utils,
    mock_preflight_then_unfinished_operation, RunbookActionError,
    postcondition_error_output, precondition_error_output,
    disposition_rejected_output, disposition_capability_error_output,
    cmdlet_failure_output,
)
from ms_quarantine_for_splunk_soar_connector import OPERATION_STATE_KEY


@pytest.mark.parametrize("action", ["release", "deny"])
def test_fallback_operation_id_is_case_stable(action):
    c = make_connector()
    assert c._resolve_operation_id({}, action, IDENTITY.upper()) == (
        c._resolve_operation_id({}, action, IDENTITY.lower())
    )


@pytest.mark.parametrize("action", ["release", "deny"])
def test_explicit_binding_accepts_case_only_identity_change(action):
    c = make_connector()
    _, record = c._claim_irreversible_operation(
        "case-binding", action, IDENTITY.upper()
    )
    assert record["identity"] == IDENTITY.lower()
    assert c._lookup_irreversible_operation(
        "case-binding", action, IDENTITY.lower()
    )["operation_id"] == "case-binding"
    claimed, _ = c._claim_irreversible_operation(
        "case-binding", action, IDENTITY.lower()
    )
    assert not claimed
    c._update_irreversible_operation(
        "case-binding", action, IDENTITY.lower(), state="pending"
    )


@pytest.mark.parametrize("action", ["release", "deny"])
def test_legacy_uppercase_unresolved_auto_claim_blocks_replay(action):
    c = make_connector()
    old_id = "auto-" + hashlib.sha256(
        f"{c.get_container_id()}|{action}|{IDENTITY.upper()}".encode()
    ).hexdigest()[:32]
    # Seed the exact pre-upgrade format without relying on the new claim helper.
    c.save_state({OPERATION_STATE_KEY: {old_id: {
        "operation_id": old_id, "action": action,
        "identity": IDENTITY.upper(), "state": "outcome_unknown",
        "azure_job_id": JOB_ID,
    }}})
    before = Path(c.get_state_file_path()).read_bytes()
    new_id = c._resolve_operation_id({}, action, IDENTITY.lower())
    assert c._lookup_irreversible_operation(new_id, action, IDENTITY.lower())[
        "operation_id"
    ] == old_id
    claimed, record = c._claim_irreversible_operation(
        new_id, action, IDENTITY.lower()
    )
    assert not claimed
    assert record["operation_id"] == old_id
    assert Path(c.get_state_file_path()).read_bytes() == before
    c._utils.verify_connection_contract = Mock(
        side_effect=AssertionError("A replay must not perform preflight")
    )
    c._utils.fire_webhook = Mock(
        side_effect=AssertionError("A replay must not fire a webhook")
    )
    patch_ar(c)
    handler = (c._handle_release_quarantine_message if action == "release"
               else c._handle_deny_quarantine_release)
    assert handler({"identity": IDENTITY.lower()}) == APP_ERROR
    c._utils.verify_connection_contract.assert_not_called()
    c._utils.fire_webhook.assert_not_called()


@pytest.mark.parametrize("state", ["pending", "outcome_unknown", "confirmed_success"])
def test_reconcile_wrong_job_rejected_without_any_mutation_or_query(state):
    c = make_connector()
    c._claim_irreversible_operation("bound-job", "release", IDENTITY)
    c._update_irreversible_operation(
        "bound-job", "release", IDENTITY, state=state, azure_job_id=JOB_ID
    )
    before = Path(c.get_state_file_path()).read_bytes()
    c._utils.get_job_status = Mock()
    ar = patch_ar(c)
    params = Fixtures.reconcile_params("bound-job")
    params["azure_job_id"] = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert c._handle_reconcile_quarantine_operation(params) == APP_ERROR
    assert Path(c.get_state_file_path()).read_bytes() == before
    c._utils.get_job_status.assert_not_called()
    assert "does not match" in ar.get_message()


def test_update_cannot_replace_established_job():
    c = make_connector()
    c._claim_irreversible_operation("immutable-job", "release", IDENTITY)
    c._update_irreversible_operation(
        "immutable-job", "release", IDENTITY, azure_job_id=JOB_ID
    )
    before = Path(c.get_state_file_path()).read_bytes()
    with pytest.raises(AutomationError):
        c._update_irreversible_operation(
            "immutable-job", "release", IDENTITY,
            azure_job_id="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
    assert Path(c.get_state_file_path()).read_bytes() == before


@pytest.mark.parametrize("action", ["release", "deny"])
def test_reconcile_validated_completed_idempotent_result(action):
    c = make_connector()
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
        m.get(job_url(), json={"properties": {"status": "Completed"}})
        m.get(job_output_url(), text=json.dumps(Fixtures.idempotent_result(action)))
        assert c._handle_reconcile_quarantine_operation(
            Fixtures.reconcile_params("idempotent", action)
        ) == APP_SUCCESS
        assert all(request.method == "GET" or request.url == TOKEN_URL
                   for request in m.request_history)
    assert ar.get_summary()["status"] == "confirmed_success"
    assert c.load_state()[OPERATION_STATE_KEY]["idempotent"]["idempotent"] is True


@pytest.mark.parametrize("field,value", [
    ("idempotent", False), ("cmdlet_executed", True),
    ("observed_release_status", "Requested"),
])
def test_reconcile_rejects_contradictory_idempotent_evidence(field, value):
    c = make_connector()
    ar = patch_ar(c)
    result = Fixtures.idempotent_result()
    result[field] = value
    with requests_mock.Mocker() as m:
        m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
        m.get(job_url(), json={"properties": {"status": "Completed"}})
        m.get(job_output_url(), text=json.dumps(result))
        assert c._handle_reconcile_quarantine_operation(
            Fixtures.reconcile_params("bad-idempotent")
        ) == APP_ERROR
    assert ar.get_summary()["status"] == "outcome_unknown"


@pytest.mark.parametrize("binding", ["identity", "action"])
def test_reconcile_wrong_binding_does_not_demote_confirmed_success(binding):
    c = make_connector()
    c._claim_irreversible_operation("bound-success", "release", IDENTITY)
    c._update_irreversible_operation(
        "bound-success", "release", IDENTITY,
        azure_job_id=JOB_ID, state="confirmed_success",
    )
    before = Path(c.get_state_file_path()).read_bytes()
    params = Fixtures.reconcile_params("bound-success")
    params["expected_" + binding] = (
        "deny" if binding == "action"
        else IDENTITY.replace("c14401cf", "a14401cf")
    )
    c._utils.get_job_status = Mock()
    patch_ar(c)
    assert c._handle_reconcile_quarantine_operation(params) == APP_ERROR
    assert Path(c.get_state_file_path()).read_bytes() == before
    c._utils.get_job_status.assert_not_called()


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize(
    "completed_result", ["successful_result", "idempotent_result"]
)
def test_uppercase_wire_timeout_reconciles_with_canonical_identity(
    action, completed_result,
):
    c = make_connector()
    ar = patch_ar(c)
    webhook_calls = []
    handler = (c._handle_release_quarantine_message if action == "release"
               else c._handle_deny_quarantine_release)
    with requests_mock.Mocker() as m:
        mock_preflight_then_unfinished_operation(m, c, webhook_calls)
        assert handler({"identity": IDENTITY.upper(),
                        "operation_id": "upper-timeout"}) == APP_ERROR
    row = ar.get_data()[0]
    assert row["status"] == "outcome_unknown"
    assert row["identity"] == IDENTITY.lower()
    assert webhook_calls[-1]["identity"] == IDENTITY.upper()
    output = getattr(Fixtures, completed_result)(action)
    output["identity"] = IDENTITY.upper()
    output["observed_identity"] = IDENTITY.upper()
    c._utils._poll_timeout = 600
    ar = patch_ar(c)
    with requests_mock.Mocker() as m:
        m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
        m.get(job_url(), json={"properties": {"status": "Completed"}})
        m.get(job_output_url(), text=json.dumps(output))
        params = Fixtures.reconcile_params("upper-timeout", action)
        params["expected_identity"] = row["identity"]
        assert c._handle_reconcile_quarantine_operation(params) == APP_SUCCESS
        assert all(r.method == "GET" or r.url == TOKEN_URL
                   for r in m.request_history)
    assert ar.get_summary()["status"] == "confirmed_success"
    record = c.load_state()[OPERATION_STATE_KEY]["upper-timeout"]
    assert record["identity"] == IDENTITY.lower()
    assert record["azure_job_id"] == JOB_ID
    # Canonical dedup continues to block a second irreversible webhook.
    before = Path(c.get_state_file_path()).read_bytes()
    c._utils.fire_webhook = Mock(side_effect=AssertionError("No replay"))
    patch_ar(c)
    assert handler({"identity": IDENTITY.upper(),
                    "operation_id": "upper-timeout"}) == APP_SUCCESS
    c._utils.fire_webhook.assert_not_called()
    assert Path(c.get_state_file_path()).read_bytes() == before


ERROR_FACTORIES = [
    lambda action: precondition_error_output(action=action),
    postcondition_error_output,
    disposition_rejected_output,
    disposition_capability_error_output,
    cmdlet_failure_output,
    Fixtures.read_only_refresh_error,
]


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("factory", ERROR_FACTORIES)
@pytest.mark.parametrize("request_upper", [False, True])
def test_structured_error_accepts_only_semantically_matching_guid_identity(
    action, factory, request_upper,
):
    utils = make_utils()
    output = factory(action)
    request_identity = IDENTITY.upper() if request_upper else IDENTITY.lower()
    output["details"]["identity"] = (
        IDENTITY.lower() if request_upper else IDENTITY.upper()
    )
    requested_action = output["action"]
    utils.get_job_output = Mock(return_value=output)
    with pytest.raises(RunbookActionError) as exc:
        utils.get_validated_job_output(JOB_ID, requested_action, request_identity)
    assert exc.value.result is output
    for foreign in [IDENTITY.replace("c14401cf", "a14401cf"), "not-a-guid"]:
        output["details"]["identity"] = foreign
        with pytest.raises(AutomationError) as exc:
            utils.get_validated_job_output(JOB_ID, requested_action, request_identity)
        assert not isinstance(exc.value, RunbookActionError)


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("factory", [
    Fixtures.successful_result,
    Fixtures.idempotent_result,
    Fixtures.read_only_refresh_result,
])
@pytest.mark.parametrize("request_upper", [False, True])
def test_success_envelope_accepts_only_semantically_matching_guid_identity(
    action, factory, request_upper,
):
    utils = make_utils()
    output = factory(action)
    utils.get_job_output = Mock(return_value=output)
    request_identity = IDENTITY.upper() if request_upper else IDENTITY.lower()
    output["identity"] = IDENTITY.lower() if request_upper else IDENTITY.upper()
    output["observed_identity"] = output["identity"]
    assert utils.get_validated_job_output(
        JOB_ID, output["action"], request_identity
    ) is output
    for foreign in [IDENTITY.replace("c14401cf", "a14401cf"), "not-a-guid", None]:
        output["identity"] = foreign
        with pytest.raises(AutomationError):
            utils.get_validated_job_output(
                JOB_ID, output["action"], request_identity
            )


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("binding", ["identity", "action"])
def test_claim_and_update_reject_foreign_binding_without_state_write(
    action, binding,
):
    c = make_connector()
    c._claim_irreversible_operation("binding-guard", action, IDENTITY.upper())
    c._update_irreversible_operation(
        "binding-guard", action, IDENTITY.lower(), azure_job_id=JOB_ID,
        state="outcome_unknown",
    )
    before = Path(c.get_state_file_path()).read_bytes()
    wrong_identity = (IDENTITY.replace("c14401cf", "a14401cf")
                      if binding == "identity" else IDENTITY.lower())
    wrong_action = action
    if binding == "action":
        wrong_action = "deny" if action == "release" else "release"
    for method in (
        c._claim_irreversible_operation, c._update_irreversible_operation,
    ):
        with pytest.raises(AutomationError):
            method("binding-guard", wrong_action, wrong_identity)
        assert Path(c.get_state_file_path()).read_bytes() == before
