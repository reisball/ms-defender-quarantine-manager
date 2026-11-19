"""Issue 19 synchronous intake: synthetic native SOAR/Vault and Azure boundaries."""
from datetime import datetime, timedelta, timezone

import pytest

from test_native_ingestion import setup, poll, candidate, t
from ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY
from ms_quarantine_for_splunk_soar_utils import AutomationError


@pytest.fixture(params=["soar", "es"])
def target(request):
    return request.param


def seed(c, *, status="failed", terminal=False, **extra):
    c._ingest_settings()
    identity = c.candidates[0]["Identity"].lower()
    key = c._worker_identity_key(identity, c.get_asset_id())
    row = dict(key=key, identity=identity, status=status, terminal=terminal,
               container_id=None, created_at=c._utc_now(), updated_at=c._utc_now(),
               last_error="Synthetic failure", **extra)
    c.save_state({INGEST_STATE_KEY: {"scope": c._ingest_scope(),
                                   "version": 2, "records": {key: row}}})
    return key


@pytest.mark.parametrize("phase", ["reserved", "preparing", "ready", "publishing", "blocked"])
def test_old_pending_work_becomes_failed_without_automatic_replay(tmp_path, target, phase):
    c = setup(tmp_path, target, limit=1)
    key = seed(c)
    state = c.load_state()
    data = state[INGEST_STATE_KEY]
    data.pop("version")
    row = data["records"][key]
    row.update(phase=phase, files={"0": {"vault_id": "old"}}, email_artifact={"cef": {}},
               message=c.candidates[0], recovery_audit=[{}], lease_expires_at="old")
    data["scheduler"] = {"prepare": key}
    c.save_state(state)
    assert poll(c)[0] == t.APP_SUCCESS
    assert not any(action == "export" for action, *_ in c.calls)
    row = c._ingest_records()[key]
    assert row["status"] == "failed"
    assert not {"phase", "files", "email_artifact", "message", "recovery_audit", "lease_expires_at"} & row.keys()
    assert "scheduler" not in c.load_state()[INGEST_STATE_KEY]
    c._is_poll_now = True
    assert poll(c)[0] == t.APP_SUCCESS
    assert c._ingest_records()[key]["status"] == "completed"
    assert len(c._saved_containers) == 1


@pytest.mark.parametrize("old_state", ["creating_container", "exported", "failed", "oversized", "completed"])
def test_legacy_workers_migrate_without_replaying_pending_work(tmp_path, target, old_state):
    c = setup(tmp_path, target, limit=1)
    c.candidates = c.candidates[:1]
    c.save_state({"quarantine_worker_ledger": {"old": {
        "identity": c.candidates[0]["Identity"], "state": old_state,
        "created_at": c._utc_now(), "updated_at": c._utc_now(), "container_id": 77}}})
    assert poll(c)[0] == t.APP_SUCCESS
    assert not c.events
    assert not any(action == "export" for action, *_ in c.calls)
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == ("completed" if old_state == "completed" else "failed")
    assert row["terminal"] is (old_state in {"completed", "failed", "oversized"})
    assert row["container_id"] == 77
    if row["terminal"]:
        assert not any(action == "reconcile" for action, *_ in c.calls)


def test_crashed_attempt_is_failed_without_replay_then_manual_retry_works(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    key = seed(c, status="running", publication_started=True)
    assert poll(c)[0] == t.APP_SUCCESS
    assert c._ingest_records()[key]["status"] == "failed"
    assert not c.events
    c._is_poll_now = True
    assert poll(c)[0] == t.APP_SUCCESS
    assert c._ingest_records()[key]["status"] == "completed"


def test_manual_poll_cannot_take_over_live_process_lock(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    key = seed(c, status="running")
    c._is_poll_now = True
    with c._ingest_poll_lock():
        status, ar = poll(c)
        assert status == t.APP_ERROR
        assert "running" in ar.get_message()
        assert c._ingest_records()[key]["status"] == "running"
    assert not c.calls


def test_manual_snapshot_does_not_retry_new_failure_or_duplicate_row(tmp_path, target):
    c = setup(tmp_path, target, limit=2)
    c.candidates = [candidate(1), candidate(1)]
    c._is_poll_now = True
    c._store_in_vault = lambda *args, **kwargs: (False, "failure")
    assert poll(c)[0] == t.APP_ERROR
    assert sum(action == "export" for action, *_ in c.calls) == 1
    assert poll(c)[0] == t.APP_ERROR
    assert sum(action == "export" for action, *_ in c.calls) == 2
    assert len(c._ingest_records()) == 1


def test_retry_at_full_capacity_does_not_allocate_extra_slot(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    key = seed(c)
    c._is_poll_now = True
    status, ar = poll(c, container_count=50)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["active_messages"] == 1
    assert list(c._ingest_records()) == [key]
    assert c._ingest_records()[key]["status"] == "completed"
    assert len(c._saved_containers) == 1
    assert poll(c, container_count=50)[0] == t.APP_SUCCESS
    assert sum(action == "export" for action, *_ in c.calls) == 1


def test_es_lost_response_never_automatically_reposts_but_manual_is_new_attempt(tmp_path):
    c = setup(tmp_path, "es", limit=1)
    client = c._ingest_es_client_instance
    original = client.request.side_effect
    client.request.side_effect = TimeoutError("lost response")
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "may duplicate" in ar.get_message()
    assert client.request.call_count == 1
    assert poll(c)[0] == t.APP_SUCCESS
    assert client.request.call_count == 1
    c._is_poll_now = True
    client.request.side_effect = original
    assert poll(c)[0] == t.APP_SUCCESS
    assert client.request.call_count == 2
    assert poll(c)[0] == t.APP_SUCCESS
    assert client.request.call_count == 2


@pytest.mark.parametrize("field", ["SenderAddress", "RecipientAddress"])
@pytest.mark.parametrize("value", [None, "", "   "])
def test_required_microsoft_context_never_falls_back_to_rfc_headers(tmp_path, target, field, value):
    c = setup(tmp_path, target, limit=1)
    c.candidates[0][field] = value
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert not c.artifacts
    assert not c._ingest_es_client_instance.request.called
    assert not c._saved_containers


def test_unconfirmed_vault_id_never_starts_automation(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    c._store_in_vault = lambda *args, **kwargs: (True, {"vault_id": ""})
    assert poll(c)[0] == t.APP_ERROR
    assert not [e for e in c.events if e[0] in {"publish", "es_publish"}]


@pytest.mark.parametrize("fail_after_save", [False, True])
def test_completion_save_fault_does_not_enable_scheduled_republication(tmp_path, target, fail_after_save):
    c = setup(tmp_path, target, limit=1)
    original = c._ingest_update
    def update(key, **changes):
        if changes.get("status") == "completed":
            if fail_after_save:
                original(key, **changes)
            raise AutomationError("Synthetic completion-state save failure")
        return original(key, **changes)
    c._ingest_update = update
    assert poll(c)[0] == t.APP_ERROR
    c._ingest_update = original
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == ("completed" if fail_after_save else "failed")
    assert poll(c)[0] == t.APP_SUCCESS
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 1


def test_state_save_failure_precedes_side_effects(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    c.save_state = lambda state: False
    assert poll(c)[0] == t.APP_ERROR
    assert not c.calls
    assert not c.events


def test_expired_terminal_retention_does_not_drop_failed_active_identity(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    key = seed(c)
    state = c.load_state()
    old = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    state[INGEST_STATE_KEY]["records"][key]["updated_at"] = old
    other = {**state[INGEST_STATE_KEY]["records"][key], "key": "old-terminal",
             "identity": candidate(99)["Identity"], "terminal": True, "status": "completed"}
    state[INGEST_STATE_KEY]["records"]["old-terminal"] = other
    c.save_state(state)
    assert poll(c)[0] == t.APP_SUCCESS
    assert list(c._ingest_records()) == [key]
    assert not c.events


def test_slow_export_may_finish_but_no_publication_after_poll_budget(tmp_path, target, monkeypatch):
    import ms_quarantine_for_splunk_soar_ingestion as ingestion
    c = setup(tmp_path, target, limit=2)
    now = [0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    original = c._utils.run_action
    def run(action, **kwargs):
        result = original(action, **kwargs)
        if action == "export":
            now[0] = 601
        return result
    c._utils.run_action = run
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert sum(action == "export" for action, *_ in c.calls) == 1
    assert not c.events
    assert next(iter(c._ingest_records().values()))["status"] == "failed"


def test_slow_status_read_does_not_launch_more_azure_jobs_after_budget(tmp_path, target, monkeypatch):
    import ms_quarantine_for_splunk_soar_ingestion as ingestion
    c = setup(tmp_path, target, limit=2)
    assert poll(c)[0] == t.APP_SUCCESS
    c.calls.clear()
    now = [0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    original = c._utils.run_action
    def run(action, **kwargs):
        result = original(action, **kwargs)
        now[0] = 601
        return result
    c._utils.run_action = run
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert [action for action, *_ in c.calls] == ["reconcile"]


def test_import_error_keeps_known_azure_job_without_labeling_native_errors(tmp_path):
    from ms_quarantine_for_splunk_soar_utils import JobTimeoutError
    c = setup(tmp_path, limit=1)
    timeout = JobTimeoutError("Synthetic slow export", job_id=t.JOB_ID, last_status="Running")
    formatted = c._ingest_error(timeout)
    assert t.JOB_ID in formatted
    assert "unknown" in formatted
    assert "Azure job" not in c._ingest_error(AutomationError("SOAR Vault upload failed"))


@pytest.mark.parametrize("origin", ["legacy_failed", "legacy_oversized"])
def test_previous_migrator_failed_terminal_stays_retired_without_claiming_success(tmp_path, origin):
    c = setup(tmp_path, limit=1)
    key = seed(c)
    c.candidates = c.candidates[:1]
    state = c.load_state()
    data = state[INGEST_STATE_KEY]
    data.pop("version")
    data["records"][key].update(phase="terminal", migration_origin=origin)
    c.save_state(state)
    assert poll(c)[0] == t.APP_SUCCESS
    row = c._ingest_records()[key]
    assert row["status"] == "failed"
    assert row["terminal"] is True
    assert not c.events
    assert not any(action == "reconcile" for action, *_ in c.calls)


@pytest.mark.parametrize('boundary', ['container', 'artifact', 'vault', 'disk'])
def test_native_failure_preserves_actual_cause_without_azure_attribution(tmp_path, boundary):
    c = setup(tmp_path, limit=1)
    cause = 'synthetic storage quota exceeded'
    if boundary == 'container':
        c.save_container = lambda *a, **k: (t.APP_ERROR, cause, None)
    elif boundary == 'artifact':
        c.save_artifact = lambda *a, **k: (t.APP_ERROR, cause, None)
    elif boundary == 'vault':
        c._store_in_vault = lambda *a, **k: (False, cause)
    else:
        def failed_disk(*a, **k):
            raise OSError(28, cause)
        c._store_in_vault = failed_disk
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert cause in ar.get_message()
    assert 'Azure Automation' not in ar.get_message()
    before = len([x for x in c.calls if x[0] == 'export'])
    poll(c)
    assert len([x for x in c.calls if x[0] == 'export']) == before


@pytest.mark.parametrize("read_fails", [False, True])
def test_status_sweep_rotates_after_slow_or_failed_reads(tmp_path, target, monkeypatch, read_fails):
    import ms_quarantine_for_splunk_soar_ingestion as ingestion
    c = setup(tmp_path, target, limit=20)
    assert poll(c, container_count=20)[0] == t.APP_SUCCESS
    rows = list(c._ingest_records().values())
    now = [0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    original = c._utils.run_action
    def run(action, **kwargs):
        if action == "reconcile":
            now[0] += 50
        return original(action, **kwargs)
    c._utils.run_action = run
    if read_fails:
        c.observed[rows[0]["identity"]] = AutomationError("unreadable old identity")
    c.calls.clear()
    assert poll(c)[0] == t.APP_ERROR
    checked = [identity for action, identity, _ in c.calls if action == "reconcile"]
    assert checked == [r["identity"] for r in rows[:1 if read_fails else 12]]
    next_row = rows[len(checked)]
    c.observed[next_row["identity"]] = "Released"
    c.calls.clear()
    poll(c)
    assert c.calls[0] == ("reconcile", next_row["identity"], {})
    assert c._ingest_records()[next_row["key"]]["terminal"] is True


def test_poll_now_retry_gets_budget_before_slow_status_sweep(tmp_path, target, monkeypatch):
    import ms_quarantine_for_splunk_soar_ingestion as ingestion
    c = setup(tmp_path, target, limit=1)
    key = seed(c)
    now = [0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    original = c._utils.run_action
    def run(action, **kwargs):
        if action == "reconcile":
            now[0] += 601
        return original(action, **kwargs)
    c._utils.run_action = run
    c._is_poll_now = True
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert [action for action, *_ in c.calls] == ["list", "export"]
    assert c._ingest_records()[key]["status"] == "completed"
    assert ar.get_summary()["active_messages"] == 1
    c._is_poll_now = False
    c.calls.clear()
    poll(c)
    assert c.calls[0][0] == "reconcile"
