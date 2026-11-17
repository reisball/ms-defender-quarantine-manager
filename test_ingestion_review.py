"""Regression cases for the independent native-intake review."""
from datetime import datetime, timedelta, timezone
import pytest
if __package__:
    from . import test_connector as t
    from .test_native_ingestion import setup, poll, candidate
else:
    import test_connector as t
    from test_native_ingestion import setup, poll, candidate
from ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY

def test_legacy_terminal_is_migrated_with_casefold_dedup(tmp_path):
    c = setup(tmp_path, limit=1)
    identity = c.candidates[0]["Identity"].upper()
    now = c._utc_now()
    c.save_state({t.WORKER_STATE_KEY: {"old": {
        "identity": identity, "state": "completed", "container_id": 77,
        "created_at": now, "updated_at": now}}})
    c.candidates = [c.candidates[0]]
    assert poll(c)[0] == t.APP_SUCCESS
    rows = c._ingest_records()
    assert len(rows) == 1 and next(iter(rows.values()))["phase"] == "terminal"
    assert not c._saved_containers
    assert not any(x[0] == "export" for x in c.calls)

def test_expired_legacy_precontainer_claim_does_not_block(tmp_path):
    c = setup(tmp_path, limit=1)
    c.save_state({t.WORKER_STATE_KEY: {"stale": {
        "state": "creating_container", "container_id": None,
        "lease_expires_at": "2020-01-01T00:00:00+00:00"}}})
    assert poll(c)[0] == t.APP_SUCCESS

def test_retention_and_capacity_do_not_block_admitted_work(tmp_path, monkeypatch):
    import ms_quarantine_for_splunk_soar_ingestion as ingestion
    c = setup(tmp_path, limit=1)
    c._worker_terminal_retention_days = 1
    c._ingest_reserve([c.candidates[0]], 1, 1)
    state = c.load_state()
    records = state[INGEST_STATE_KEY]["records"]
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    records["old"] = {"key": "old", "identity": candidate(999)["Identity"],
                      "phase": "terminal", "updated_at": old}
    c.save_state(state)
    monkeypatch.setattr(ingestion, "MAX_INGEST_RECORDS", 2)
    assert poll(c)[0] == t.APP_SUCCESS
    assert "old" not in c._ingest_records()
    assert len(c._saved_containers) == 1

@pytest.mark.parametrize("target", ["soar", "es"])
def test_deterministic_mime_failure_is_visible_and_not_reexported(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    c.eml = b"not an email"
    assert poll(c)[0] == t.APP_ERROR
    identity = c.candidates[0]["Identity"].lower()
    for _ in range(2):
        status, ar = poll(c)
        assert status == t.APP_ERROR and identity in ar.get_message()
        assert "headers" in ar.get_message()
    assert sum(x[0] == "export" for x in c.calls) == 1
    assert next(iter(c._ingest_records().values()))["phase"] == "blocked"

def test_definite_soar_rejection_retries_but_timeout_does_not(tmp_path):
    c = setup(tmp_path, limit=1)
    save = c.save_artifact
    def reject(artifact):
        if artifact["run_automation"]:
            return t.APP_ERROR, "rejected", None
        return save(artifact)
    c.save_artifact = reject
    assert poll(c)[0] == t.APP_ERROR
    assert next(iter(c._ingest_records().values()))["phase"] == "ready"
    c.save_artifact = save
    assert poll(c)[0] == t.APP_SUCCESS
    assert len([e for e in c.events if e[0] == "publish"]) == 1

def test_bad_list_row_does_not_block_previously_reserved_work(tmp_path):
    c = setup(tmp_path, limit=2)
    c._ingest_reserve([c.candidates[0]], 2, 1)
    c.candidates[1]["ReleaseStatus"] = "Denied"
    # Bypass backend filter, emulating a drifted response.
    run = c._utils.run_action
    def action(name, **kwargs):
        if name == "list":
            return {"messages": c.candidates[:2]}
        return run(name, **kwargs)
    c._utils.run_action = action
    status, ar = poll(c)
    assert len(c._saved_containers) == 1
    # Existing pending preparation takes priority over a potentially slow list.
    assert status == t.APP_SUCCESS
    assert not any(call[0] == "list" for call in c.calls)
    # Discovery resumes after pending work completes, and still validates status.
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert len(c._saved_containers) == 1

def test_recovery_does_not_free_slot(tmp_path):
    c = setup(tmp_path, limit=1)
    c.eml = b"invalid"
    assert poll(c)[0] == t.APP_ERROR
    row = next(iter(c._ingest_records().values()))
    t.patch_ar(c)
    assert c._handle_ingest_recovery({"identity": row["identity"], "resolution": "retry_preparation",
                                      "operator_note": "Fixed source, retry authorized"}) == t.APP_SUCCESS
    assert next(iter(c._ingest_records().values()))["phase"] == "reserved"
    assert next(iter(c._ingest_records().values()))["recovery_audit"]

@pytest.mark.parametrize("target", ["soar", "es"])
def test_oversized_export_is_blocked_once(tmp_path, target):
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
    assert poll(c)[0] == t.APP_ERROR
    assert len(calls) == 1
    assert next(iter(c._ingest_records().values()))["phase"] == "blocked"

@pytest.mark.parametrize("malformed", [False, True])
def test_exact_zero_created_receipt_retries_only_if_well_formed(tmp_path, malformed):
    c = setup(tmp_path, "es", limit=1)
    client = c._ingest_es_client_instance
    good = client.request.side_effect
    receipt = {"status": "error", "created": 0, "failed": 1, "errors": ["field not registered"],
               "findings": [], "container_ids": []}
    if malformed:
        receipt.pop("status")
    client.request.side_effect = lambda *a, **kw: receipt
    assert poll(c)[0] == t.APP_ERROR
    assert next(iter(c._ingest_records().values()))["phase"] == ("publishing" if malformed else "ready")
    client.request.side_effect = good
    assert poll(c)[0] == (t.APP_ERROR if malformed else t.APP_SUCCESS)

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
