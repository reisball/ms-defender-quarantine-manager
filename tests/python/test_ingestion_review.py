"""Regression cases for synchronous native-intake review."""
from datetime import datetime, timedelta, timezone

import pytest

if __package__:
    from . import test_connector as t
    from .test_native_ingestion import setup, poll, candidate
else:
    import test_connector as t
    from test_native_ingestion import setup, poll, candidate

from ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY


def test_legacy_completed_is_migrated_with_casefold_dedup(tmp_path):
    c = setup(tmp_path, limit=1)
    identity = c.candidates[0]["Identity"].upper()
    now = c._utc_now()
    c.save_state({"quarantine_worker_ledger": {"old": {
        "identity": identity, "state": "completed", "container_id": 77,
        "created_at": now, "updated_at": now}}})
    c.candidates = [c.candidates[0]]
    assert poll(c)[0] == t.APP_SUCCESS
    rows = c._ingest_records()
    assert len(rows) == 1
    row = next(iter(rows.values()))
    assert row["status"] == "completed" and row["terminal"] is True
    assert row["identity"] == identity.lower()
    assert not c._saved_containers
    assert not any(x[0] == "export" for x in c.calls)


def test_expired_legacy_precontainer_claim_remains_counted_failure(tmp_path):
    c = setup(tmp_path, limit=1)
    c.save_state({"quarantine_worker_ledger": {"stale": {
        "identity": candidate(1)["Identity"], "state": "creating_container", "container_id": None,
        "lease_expires_at": "2020-01-01T00:00:00+00:00"}}})
    status, ar = poll(c)
    assert status == t.APP_SUCCESS
    assert ar.get_summary()["active_messages"] == 1
    assert ar.get_summary()["failed_imports"] == 1
    assert not c.events


def test_retention_and_capacity_allow_explicit_retry_of_counted_identity(tmp_path, monkeypatch):
    import ms_quarantine_for_splunk_soar_ingestion as ingestion
    c = setup(tmp_path, limit=1)
    c._worker_terminal_retention_days = 1
    c._ingest_settings()
    claim = c._ingest_claim(c.candidates[0], set())
    c._ingest_update(claim["key"], status="failed", last_error="Synthetic failure")
    state = c.load_state()
    records = state[INGEST_STATE_KEY]["records"]
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    records["old"] = {"key": "old", "identity": candidate(999)["Identity"],
                      "status": "completed", "terminal": True, "updated_at": old}
    c.save_state(state)
    monkeypatch.setattr(ingestion, "MAX_INGEST_RECORDS", 2)
    c._is_poll_now = True
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert list(c._ingest_records()) == [claim["key"]]
    assert c._ingest_records()[claim["key"]]["status"] == "completed"
    assert ar.get_summary()["active_messages"] == 1
    assert len(c._saved_containers) == 1


@pytest.mark.parametrize("target", ["soar", "es"])
def test_deterministic_mime_failure_is_visible_and_not_reexported(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    c.eml = b"not an email"
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "headers" in ar.get_message()
    identity = c.candidates[0]["Identity"].lower()
    assert identity in ar.get_message()
    for _ in range(2):
        status, ar = poll(c)
        assert status == t.APP_SUCCESS
        assert ar.get_summary()["failed_imports"] == 1
        assert "scheduled retries disabled" in ar.get_message()
    assert sum(x[0] == "export" for x in c.calls) == 1
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "failed"
    assert "headers" in row["last_error"]


@pytest.mark.parametrize("failure", ["rejected", "lost_response"])
def test_soar_publication_failure_requires_explicit_poll_now(tmp_path, failure):
    c = setup(tmp_path, limit=1)
    save = c.save_artifact
    def reject(artifact):
        if artifact["run_automation"]:
            if failure == "lost_response":
                raise TimeoutError("Synthetic lost receipt")
            return t.APP_ERROR, "Synthetic SOAR rejection", None
        return save(artifact)
    c.save_artifact = reject
    assert poll(c)[0] == t.APP_ERROR
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "failed"
    assert row["publication_started"] is True
    c.save_artifact = save
    assert poll(c)[0] == t.APP_SUCCESS
    assert not [e for e in c.events if e[0] == "publish"]
    c._is_poll_now = True
    assert poll(c)[0] == t.APP_SUCCESS
    assert len([e for e in c.events if e[0] == "publish"]) == 1
    assert poll(c)[0] == t.APP_SUCCESS
    assert len([e for e in c.events if e[0] == "publish"]) == 1


def test_bad_list_row_is_rejected_without_reimporting_completed_identity(tmp_path):
    c = setup(tmp_path, limit=2)
    c._is_poll_now = True
    assert poll(c, container_count=1)[0] == t.APP_SUCCESS
    c.candidates[1]["ReleaseStatus"] = "Denied"
    run = c._utils.run_action
    def action(name, **kwargs):
        if name == "list":
            return {"messages": c.candidates[:2]}
        return run(name, **kwargs)
    c._utils.run_action = action
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "not Requested" in ar.get_message()
    assert len(c._saved_containers) == 1
    assert sum(x[0] == "export" for x in c.calls) == 1


def test_manual_retry_does_not_free_slot_or_import_new_identity(tmp_path):
    c = setup(tmp_path, limit=1)
    valid = c.eml
    c.eml = b"invalid"
    assert poll(c)[0] == t.APP_ERROR
    row = next(iter(c._ingest_records().values()))
    c.eml = valid
    c._is_poll_now = True
    status, ar = poll(c, container_count=50)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert list(c._ingest_records()) == [row["key"]]
    assert ar.get_summary()["active_messages"] == 1
    assert c._ingest_records()[row["key"]]["status"] == "completed"
    assert len(c._saved_containers) == 1


@pytest.mark.parametrize("target", ["soar", "es"])
def test_oversized_export_is_failed_once(tmp_path, target):
    from ms_quarantine_for_splunk_soar_utils import OversizedExportError
    c = setup(tmp_path, target, limit=1)
    original = c._utils.run_action
    calls = []
    def run(name, **kwargs):
        if name == "export":
            calls.append(name)
            raise OversizedExportError("Export exceeds safety cap.", identity=kwargs["identity"],
                                       decoded_size=99999999, max_decoded_size=24000000)
        return original(name, **kwargs)
    c._utils.run_action = run
    assert poll(c)[0] == t.APP_ERROR
    status, ar = poll(c)
    assert status == t.APP_SUCCESS
    assert ar.get_summary()["failed_imports"] == 1
    assert len(calls) == 1
    assert next(iter(c._ingest_records().values()))["status"] == "failed"


@pytest.mark.parametrize("malformed", [False, True])
def test_zero_created_receipt_never_retries_without_poll_now(tmp_path, malformed):
    c = setup(tmp_path, "es", limit=1)
    client = c._ingest_es_client_instance
    good = client.request.side_effect
    receipt = {"status": "error", "created": 0, "failed": 1, "errors": ["field not registered"],
               "findings": [], "container_ids": []}
    if malformed:
        receipt.pop("status")
    client.request.side_effect = lambda *a, **kw: receipt
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert ("did not confirm" if malformed else "field not registered") in ar.get_message()
    assert next(iter(c._ingest_records().values()))["status"] == "failed"
    assert client.request.call_count == 1
    client.request.side_effect = good
    assert poll(c)[0] == t.APP_SUCCESS
    assert client.request.call_count == 1
    c._is_poll_now = True
    assert poll(c)[0] == t.APP_SUCCESS
    assert client.request.call_count == 2
    assert poll(c)[0] == t.APP_SUCCESS
    assert client.request.call_count == 2


def test_poll_budget_stops_further_azure_jobs(tmp_path, monkeypatch):
    import ms_quarantine_for_splunk_soar_ingestion as ingestion
    c = setup(tmp_path, limit=2)
    assert poll(c)[0] == t.APP_SUCCESS
    c.calls.clear()
    ticks = iter([0, 601])
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: next(ticks, 601))
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "budget" in ar.get_message()
    assert not c.calls
    assert len(c._ingest_records()) == 2


def test_literal_false_state_save_never_exports_or_publishes(tmp_path):
    c = setup(tmp_path, limit=1)
    c.save_state = lambda state: False
    assert poll(c)[0] == t.APP_ERROR
    assert not any(call[0] == "export" for call in c.calls)
    assert not c._saved_containers
