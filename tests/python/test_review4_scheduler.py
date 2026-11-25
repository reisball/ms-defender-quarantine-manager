"""Failed attempts keep slots; explicit retries do not restart a scheduler."""
import pytest

if __package__:
    from .test_native_ingestion import setup, poll, t
else:
    from test_native_ingestion import setup, poll, t

import ms_quarantine_for_splunk_soar_ingestion as ingestion
from ms_quarantine_for_splunk_soar_utils import AutomationError


@pytest.mark.parametrize("target", ["soar", "es"])
def test_failed_import_does_not_prevent_terminal_status_and_refill(tmp_path, target):
    c = setup(tmp_path, target)
    first = c.candidates[0]["Identity"].lower()
    last = c.candidates[9]["Identity"].lower()
    store = c._store_in_vault

    def fail_first(content, identity, **kwargs):
        if identity == first:
            return False, {}
        return store(content, identity, **kwargs)

    c._store_in_vault = fail_first
    assert poll(c)[0] == t.APP_ERROR
    rows = c._ingest_records()
    assert sum(row["status"] == "completed" for row in rows.values()) == 9
    assert next(row for row in rows.values() if row["identity"] == first)["status"] == "failed"
    c.observed[last] = "Released"
    c.calls.clear()
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert [identity for action, identity, _ in c.calls if action == "reconcile"] == [last]
    rows = c._ingest_records()
    assert next(row for row in rows.values() if row["identity"] == last)["terminal"] is True
    assert next(row for row in rows.values() if row["identity"] == first)["status"] == "failed"
    assert ar.get_summary()["active_messages"] == 10
    assert all(identity != first for action, identity, _ in c.calls if action == "export")
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 10


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("failure", ["export", "vault"])
@pytest.mark.parametrize("restart", [False, True])
def test_slow_explicit_retry_failure_does_not_resume_automatically(
        tmp_path, monkeypatch, target, failure, restart):
    c = setup(tmp_path, target, limit=2)
    store = c._store_in_vault
    c._store_in_vault = lambda *args, **kwargs: (False, {})
    assert poll(c)[0] == t.APP_ERROR
    rows = list(c._ingest_records().values())
    assert len(rows) == 2
    assert all(row["status"] == "failed" for row in rows)
    first, healthy = (row["identity"] for row in rows)
    c._store_in_vault = store
    if restart:
        c = setup(tmp_path, target, limit=2)
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action
    store = c._store_in_vault

    def slow(action, identity=None, **kwargs):
        if action == "export" and identity == first:
            now[0] += 400
            if failure == "export":
                c.calls.append((action, identity, kwargs))
                raise AutomationError("Synthetic slow export failure")
        return run(action, identity=identity, **kwargs)

    c._utils.run_action = slow
    c._store_in_vault = lambda content, identity, **kwargs: (
        (False, {}) if identity == first else store(content, identity, **kwargs))
    c._is_poll_now = True
    c.calls.clear()
    c.events.clear()
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert ar.get_summary()["active_messages"] == 2
    records = list(c._ingest_records().values())
    assert next(row for row in records if row["identity"] == healthy)["status"] == "completed"
    assert next(row for row in records if row["identity"] == first)["status"] == "failed"
    assert sum(action == "export" and identity == first for action, identity, _ in c.calls) == 1
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 1

    c._is_poll_now = False
    c.calls.clear()
    assert poll(c)[0] == t.APP_SUCCESS
    assert not any(action == "export" for action, *_ in c.calls)
