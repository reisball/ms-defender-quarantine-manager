"""Issue 19: one submission, bounded normal Azure waits, native result semantics.

All HTTP and time are mocked; these tests do not exercise a customer tenant.
"""
import base64
import hashlib
import json
from unittest.mock import Mock

import pytest
import requests

import ms_quarantine_for_splunk_soar_utils as u

IDENTITY = r"c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
JOB_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def response(data=None, status=200, text=None, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = (text if text is not None else json.dumps(data)).encode()
    result.headers.update(headers or {})
    return result


def job(status, exception=""):
    return response({"properties": {"status": status, "exception": exception}})


@pytest.fixture
def clock(monkeypatch):
    class Clock:
        now = 1000.0
        sleeps = []

        def sleep(self, seconds):
            assert seconds >= 0
            self.sleeps.append(seconds)
            self.now += seconds

    value = Clock()
    monkeypatch.setattr(u.time, "monotonic", lambda: value.now)
    monkeypatch.setattr(u.time, "sleep", value.sleep)
    return value


@pytest.fixture
def utils():
    value = u.MSQuarantineForSplunkSOARUtils(
        webhook_url="https://example.invalid/webhook?token=synthetic",
        tenant_id="tenant", client_id="client", client_secret="secret",
        subscription_id="subscription", resource_group="group",
        automation_account="account",
    )
    value._mgmt_token = "cached"
    value._session = Mock()
    value._session.post.return_value = response({"JobIds": [JOB_ID]}, status=202)
    return value


def disposition(action="release", **changes):
    status = "released" if action == "release" else "denied"
    return {
        "action": action, "identity": IDENTITY, "status": status,
        "observed_identity": IDENTITY, "observed_release_status": status.title(),
        **changes,
    }


def test_defaults_and_one_webhook_for_a_slow_job(utils, clock):
    assert utils._poll_timeout == 600
    assert utils._poll_interval == 5
    notices = []
    utils.progress_callback = lambda message: notices.append((clock.now, message))
    states = ["New", "Activating", "Queued", "Starting", "Running"] + ["Running"] * 85
    utils._session.get.side_effect = [job(status) for status in states] + [
        job("Completed"), response(disposition()),
    ]
    assert utils.run_action("release", IDENTITY)["status"] == "released"
    utils._session.post.assert_called_once()
    assert utils._session.post.call_args.kwargs["json"]["action"] == "release"
    assert clock.now == 1450
    assert len(notices) >= 15
    assert all(JOB_ID in message for _, message in notices)
    assert all(b[0] - a[0] >= 30 for a, b in zip(notices, notices[1:]))


@pytest.mark.parametrize("state", ["Failed", "Stopped", "Suspended", "Disconnected"])
def test_native_azure_failure_never_reads_failed_output(utils, clock, state):
    native = "Microsoft.Exchange.Management: RBAC target scope denied"
    utils._session.get.side_effect = [job(state, native), response(disposition())]
    with pytest.raises(u.JobFailedError) as caught:
        utils.run_action("release", IDENTITY)
    assert caught.value.exception == native
    assert caught.value.job_id == JOB_ID
    assert caught.value.last_status == state
    assert native in str(caught.value)
    assert utils._session.get.call_count == 1
    assert utils._session.post.call_count == 1


def test_status_and_output_share_deadline_and_timeout_is_unknown(utils, clock):
    utils._poll_timeout = 20
    utils._session.get.side_effect = [
        job("Running"), job("Running"), job("Completed"),
        response(status=429, headers={"Retry-After": "100"}),
    ]
    with pytest.raises(u.JobTimeoutError) as caught:
        utils.run_action("release", IDENTITY)
    assert clock.now == 1020
    assert caught.value.job_id == JOB_ID
    assert caught.value.last_status == "Completed"
    assert caught.value.phase == "output"
    assert "unknown" in str(caught.value) and "not been stopped" in str(caught.value)
    utils._session.post.assert_called_once()


def test_status_timeout_keeps_last_nonterminal_state(utils, clock):
    utils._poll_timeout = 12
    utils._session.get.return_value = job("Running")
    with pytest.raises(u.JobTimeoutError) as caught:
        utils.run_action("release", IDENTITY)
    assert clock.now == 1012
    assert caught.value.last_status == "Running"
    assert caught.value.phase == "status"
    assert utils._session.get.call_count == 3


def test_retry_after_is_not_shortened_to_thirty_seconds_and_progress_continues(utils, clock):
    calls = []
    utils.progress_callback = lambda message: calls.append((clock.now, message))
    utils._session.get.side_effect = [
        response(status=429, headers={"Retry-After": "95"}),
        job("Completed"), response(disposition()),
    ]
    assert utils.run_action("release", IDENTITY)["status"] == "released"
    assert clock.now == 1095
    assert len(calls) >= 4
    utils._session.post.assert_called_once()


def test_retry_after_http_date(utils, clock, monkeypatch):
    monkeypatch.setattr(u.time, "time", lambda: 0.0)
    assert utils._throttle_delay(
        response(status=429, headers={"Retry-After": "Thu, 01 Jan 1970 00:02:00 GMT"}), 0
    ) == 120


@pytest.mark.parametrize("phase", ["status", "output"])
@pytest.mark.parametrize("failure", [
    requests.ConnectionError("offline"), requests.Timeout("slow"),
    response(status=408), response(status=429), response(status=500),
    response(status=502), response(status=503), response(status=504),
])
def test_transient_reads_retry_without_reposting(utils, clock, phase, failure):
    tail = [job("Completed"), response(disposition())]
    sequence = [failure, *tail] if phase == "status" else [tail[0], failure, tail[1]]
    utils._session.get.side_effect = sequence
    assert utils.run_action("release", IDENTITY)["status"] == "released"
    assert clock.now == 1005
    utils._session.post.assert_called_once()


@pytest.mark.parametrize("failure", [
    requests.ConnectionError("offline"), response(status=429, headers={"Retry-After": "9"}),
    response(status=503),
])
def test_persistent_read_errors_are_bounded_by_current_deadline(utils, clock, failure):
    utils._poll_timeout = 12
    if isinstance(failure, Exception):
        utils._session.get.side_effect = failure
    else:
        utils._session.get.return_value = failure
    with pytest.raises(u.JobTimeoutError):
        utils.run_action("release", IDENTITY)
    assert clock.now == 1012
    utils._session.post.assert_called_once()


def test_requests_are_capped_to_remaining_wait(utils, clock):
    utils._poll_timeout = 2
    utils._session.get.side_effect = [job("Completed"), response(disposition())]
    utils.run_action("release", IDENTITY)
    assert all(call.kwargs["timeout"] <= 2 for call in utils._session.get.call_args_list)


def test_token_acquisition_uses_remaining_budget(utils, clock):
    utils._mgmt_token = None
    utils._poll_timeout = 2
    utils._session.post.side_effect = [
        response({"JobIds": [JOB_ID]}, status=202),
        response({"access_token": "new-token"}),
    ]
    utils._session.get.side_effect = [job("Completed"), response(disposition())]
    utils.run_action("release", IDENTITY)
    assert utils._session.post.call_args_list[1].kwargs["timeout"] <= 2


@pytest.mark.parametrize("phase", ["status", "output"])
def test_expired_read_token_is_refreshed_once(utils, clock, phase):
    utils._session.post.side_effect = [
        response({"JobIds": [JOB_ID]}, status=202), response({"access_token": "fresh"}),
    ]
    final = response(disposition())
    utils._session.get.side_effect = (
        [response(status=401), job("Completed"), final] if phase == "status"
        else [job("Completed"), response(status=401), final]
    )
    assert utils.run_action("release", IDENTITY)["status"] == "released"
    assert utils._session.post.call_count == 2
    assert sum("json" in call.kwargs for call in utils._session.post.call_args_list) == 1


@pytest.mark.parametrize("status", [400, 401, 403, 404, 302])
def test_nontransient_read_error_is_not_retried(utils, clock, status):
    utils._session.get.return_value = response(status=status, text="Native API error")
    utils._session.post.side_effect = [
        response({"JobIds": [JOB_ID]}, status=202), response({"access_token": "fresh"}),
    ]
    with pytest.raises(u.AutomationError, match=f"HTTP {status}"):
        utils.run_action("release", IDENTITY)
    assert utils._session.get.call_count == (2 if status == 401 else 1)
    assert clock.now == 1000


@pytest.mark.parametrize("failure", [
    requests.Timeout("lost response"), response(status=429), response(status=503),
    response(status=307),
])
def test_webhook_never_replayed(utils, clock, failure):
    if isinstance(failure, Exception):
        utils._session.post.side_effect = failure
    else:
        utils._session.post.return_value = failure
    with pytest.raises(u.WebhookError):
        utils.run_action("release", IDENTITY)
    utils._session.post.assert_called_once()
    utils._session.get.assert_not_called()


def test_delayed_output_waits_within_same_budget(utils, clock):
    utils._session.get.side_effect = [
        job("Completed"), response(text=""), response(text=" "), response(disposition()),
    ]
    assert utils.run_action("release", IDENTITY)["status"] == "released"
    assert clock.now == 1010


def test_empty_output_expires_without_new_job(utils, clock):
    utils._poll_timeout = 12
    utils._session.get.side_effect = lambda url, **kwargs: (
        response(text="") if "/output?" in url else job("Completed")
    )
    with pytest.raises(u.JobTimeoutError) as caught:
        utils.run_action("release", IDENTITY)
    assert caught.value.phase == "output"
    assert clock.now == 1012
    utils._session.post.assert_called_once()


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("already", [False, True])
def test_minimal_disposition_does_not_require_contract_evidence(utils, action, already):
    value = disposition(action)
    if already:
        value["status"] = "already_" + value["status"]
    value["runbook_version"] = "informational-only"
    utils._validate_runbook_result(value, action, IDENTITY.upper())


@pytest.mark.parametrize("change", [
    {"action": "deny"}, {"identity": IDENTITY[:-1] + "8"},
    {"observed_identity": IDENTITY[:-1] + "8"}, {"observed_release_status": "Requested"},
    {"status": "pending"}, {"error": "false"}, {"error": None},
])
def test_wrong_business_result_is_rejected(utils, change):
    with pytest.raises(u.AutomationError):
        utils._validate_runbook_result(disposition(**change), "release", IDENTITY)


def test_original_exchange_error_preserves_native_fields(utils, clock):
    native = {
        "action": "release", "identity": IDENTITY, "error": True,
        "message": "Exchange cmdlet: target scope access denied",
        "error_code": "exchange_cmdlet_failed", "error_context": "release",
        "fully_qualified_error_id": "Exchange.RbacException", "error_category": "PermissionDenied",
    }
    utils._session.get.side_effect = [job("Completed"), response(native)]
    with pytest.raises(u.RunbookActionError) as caught:
        utils.run_action("release", IDENTITY)
    assert caught.value.result == native
    assert str(caught.value) == native["message"]


@pytest.mark.parametrize("value", [
    {"action": "reconcile", "identity": IDENTITY, "observed_identity": IDENTITY,
     "release_status": "Released"},
    {"action": "reconcile", "identity": IDENTITY, "observed_identity": IDENTITY,
     "observed_release_status": "Requested"},
    {"action": "diagnose", "identity": IDENTITY, "status": "inspected"},
])
def test_read_only_helpers_have_no_operation_or_diagnostic_proof_matrix(utils, value):
    utils._validate_runbook_result(value, value["action"], IDENTITY)


def test_oversized_error_needs_no_evidence_envelope(utils):
    with pytest.raises(u.OversizedExportError, match="Too large"):
        utils._raise_for_runbook_error({
            "action": "export", "identity": IDENTITY, "error": True,
            "error_code": "export_oversized", "message": "Too large",
        }, "export", IDENTITY)


def test_progress_callback_can_be_constructor_argument_or_property(clock):
    callback = Mock()
    value = u.MSQuarantineForSplunkSOARUtils(
        "https://example.invalid/", "tenant", "client", "secret",
        "sub", "group", "account", progress_callback=callback,
    )
    value._progress("Waiting")
    callback.assert_called_once_with("Waiting")
    value.progress_callback = Mock(side_effect=RuntimeError("UI unavailable"))
    clock.now += 31
    value._progress("Still waiting")  # UI failure does not turn a job into failure.


def export_records(raw=b"From: sender@example.test\r\n\r\nComplete message"):
    encoded = base64.b64encode(raw).decode()
    parts = [encoded[i:i+16] for i in range(0, len(encoded), 16)]
    chunks = [{
        "action": "export", "mode": "chunked", "identity": IDENTITY,
        "encoding": "base64", "chunk_count": len(parts), "chunk_index": i, "eml_chunk": part,
    } for i, part in enumerate(parts)]
    trailer = {
        "action": "export", "mode": "chunked_complete", "identity": IDENTITY,
        "chunk_count": len(parts), "eml_base64_length": len(encoded),
        "decoded_size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return chunks + [trailer]


def parse_records(utils, records):
    return utils._parse_multiline_job_output("\n".join(json.dumps(r) for r in records))


def test_eml_transport_reassembly_hash_and_sizes_without_build_gate(utils):
    records = export_records()
    result = parse_records(utils, records)
    assert result["_eml_bytes"] == base64.b64decode(result["eml"])
    assert result["sha256"] == hashlib.sha256(result["_eml_bytes"]).hexdigest()
    records[-1]["runbook_version"] = "informational"
    records[0]["runbook_version"] = "different but not a transport integrity field"
    assert parse_records(utils, records)["runbook_version"] == "informational"


@pytest.mark.parametrize("mutation,match", [
    (lambda rs: rs.pop(), "incomplete"),
    (lambda rs: rs.pop(0), "expected"),
    (lambda rs: rs.insert(0, dict(rs[0])), "expected"),
    (lambda rs: rs[1].update(chunk_index=0), "duplicate"),
    (lambda rs: rs[0].update(identity="wrong"), "identity"),
    (lambda rs: rs[0].update(encoding="utf8"), "encoding"),
    (lambda rs: rs[0].update(chunk_count=99), "chunk_count"),
    (lambda rs: rs[0].update(eml_chunk="!" * 16), "base64"),
    (lambda rs: rs[-1].update(sha256="0" * 64), "sha256"),
    (lambda rs: rs[-1].update(decoded_size=1), "decoded_size"),
    (lambda rs: rs[-1].update(eml_base64_length=1), "base64_length"),
    (lambda rs: rs[-1].update(decoded_size=u.MAX_DECODED_EML_BYTES + 1), "maximum"),
    (lambda rs: rs[-1].update(chunk_count=u.MAX_CHUNK_COUNT + 1), "maximum"),
])
def test_eml_transport_rejects_incomplete_or_corrupt_payloads(utils, mutation, match):
    records = export_records()
    mutation(records)
    with pytest.raises(u.AutomationError, match=match):
        parse_records(utils, records)


def test_inline_limit_and_vault_bytes_are_preserved(utils):
    records = export_records()
    records[-1]["decoded_size"] = u.MAX_INLINE_DECODED_EML_BYTES + 1
    with pytest.raises(u.AutomationError, match="export_mode=vault"):
        parse_records(utils, records)
    utils._retain_chunked_base64 = False
    value = parse_records(utils, export_records())
    assert "_eml_bytes" in value and "eml" not in value


def list_records():
    return [
        {"action": "list", "mode": "list_chunk", "chunk_index": 0,
         "messages": [{"Identity": IDENTITY, "ReleaseStatus": "Requested"}]},
        {"action": "list", "mode": "list_complete", "chunk_count": 1, "count": 1},
    ]


def test_list_transport_requires_complete_objects_but_no_build_metadata(utils):
    result = parse_records(utils, list_records())
    assert result["count"] == 1
    assert result["messages"][0]["Identity"] == IDENTITY


@pytest.mark.parametrize("mutation,match", [
    (lambda rs: rs.pop(), "incomplete"),
    (lambda rs: rs[0].update(chunk_index=5), "range"),
    (lambda rs: rs[-1].update(count=2), "count mismatch"),
    (lambda rs: rs[-1].update(count=u.MAX_LIST_RESULT_COUNT + 1), "between"),
    (lambda rs: rs[-1].update(count=True), "numeric"),
    (lambda rs: rs[0].update(messages=[None]), "only objects"),
    (lambda rs: rs[0].update(messages=[]), "non-empty array"),
])
def test_list_transport_rejects_invalid_or_incomplete_chunks(utils, mutation, match):
    records = list_records()
    mutation(records)
    with pytest.raises(u.AutomationError, match=match):
        parse_records(utils, records)


def test_stream_limit_and_inline_field_compatibility(utils):
    with pytest.raises(u.AutomationError, match="stream limit"):
        utils._raise_if_stream_limit(u.AZURE_STREAM_LIMIT_MESSAGE)
    for field in ("eml", "Eml", "EML"):
        assert utils.extract_eml({field: {"value": "abc"}}) == "abc"
        assert utils.extract_eml({field: "abc"}) == "abc"


def test_consciously_started_new_action_is_not_gated_after_timeout(utils, clock):
    utils._poll_timeout = 6
    utils._session.get.return_value = job("Running")
    with pytest.raises(u.JobTimeoutError):
        utils.run_action("release", IDENTITY)
    utils._session.get.side_effect = [job("Completed"), response(disposition())]
    assert utils.run_action("release", IDENTITY)["status"] == "released"
    assert utils._session.post.call_count == 2


def test_vault_transport_retains_complete_large_eml_without_inline_copy(utils):
    raw = b"From: sender@example.test\r\nSubject: Large\r\n\r\n" + b"x" * (11 * 1024 * 1024)
    encoded = base64.b64encode(raw).decode()
    parts = [encoded[i:i+500_000] for i in range(0, len(encoded), 500_000)]
    records = [{
        "action": "export", "mode": "chunked", "identity": IDENTITY,
        "encoding": "base64", "chunk_count": len(parts), "chunk_index": i,
        "eml_chunk": part,
    } for i, part in enumerate(parts)]
    records.append({
        "action": "export", "mode": "chunked_complete", "identity": IDENTITY,
        "chunk_count": len(parts), "eml_base64_length": len(encoded),
        "decoded_size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    })
    utils._retain_chunked_base64 = False
    result = parse_records(utils, records)
    assert result["_eml_bytes"] == raw
    assert "eml" not in result


@pytest.mark.parametrize('action,payload', [
    ('list', {'action': 'list'}),
    ('list', {'action': 'list', 'messages': None}),
    ('export', {'action': 'export', 'identity': IDENTITY}),
])
def test_missing_business_payload_is_error_with_known_job(utils, clock, action, payload):
    utils._session.get.side_effect = [job('Completed'), response(payload)]
    with pytest.raises(u.AutomationError) as caught:
        utils.run_action(action, IDENTITY if action == 'export' else None)
    assert caught.value.job_id == JOB_ID
    assert caught.value.last_status == 'Completed'
    utils._session.post.assert_called_once()


def test_runbook_error_retains_job_context_for_native_poll(utils, clock):
    payload = {'action': 'export', 'identity': IDENTITY, 'error': True,
               'message': 'Exchange export: permission denied', 'error_code': 'export_failed'}
    utils._session.get.side_effect = [job('Completed'), response(payload)]
    with pytest.raises(u.RunbookActionError) as caught:
        utils.run_action('export', IDENTITY)
    assert caught.value.job_id == JOB_ID
    assert caught.value.last_status == 'Completed'
    assert caught.value.result['message'] == payload['message']
    utils._session.post.assert_called_once()
