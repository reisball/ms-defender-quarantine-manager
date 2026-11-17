"""Pending preparation must not reset unrelated status reconciliation progress."""
import pytest
if __package__:
    from .test_native_ingestion import setup, poll
else:
    from test_native_ingestion import setup, poll
import ms_quarantine_for_splunk_soar_ingestion as ingestion

@pytest.mark.parametrize("target", ["soar", "es"])
def test_failed_pending_import_does_not_starve_terminal_status(tmp_path, monkeypatch, target):
    c = setup(tmp_path, target)
    first = c.candidates[0]["Identity"].lower()
    last = c.candidates[9]["Identity"].lower()
    store = c._store_in_vault
    def fail_first(content, identity, **kwargs):
        if identity == first:
            return False, {}
        return store(content, identity, **kwargs)
    c._store_in_vault = fail_first
    poll(c)
    rows = c._ingest_records()
    assert sum(r["phase"] == "published" for r in rows.values()) == 9
    assert next(r for r in rows.values() if r["identity"] == first)["phase"] == "preparing"
    c.observed[last] = "Released"
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action
    def slow(action, **kwargs):
        result = run(action, **kwargs)
        if action == "reconcile":
            now[0] += 100
        return result
    c._utils.run_action = slow
    checked = set()
    for _ in range(4):
        c.calls.clear()
        poll(c)
        checked.update(x[1] for x in c.calls if x[0] == "reconcile")
    rows = c._ingest_records()
    assert checked >= {r["identity"] for r in rows.values()}
    assert next(r for r in rows.values() if r["identity"] == last)["phase"] == "terminal"
    assert next(r for r in rows.values() if r["identity"] == first)["phase"] == "preparing"
    assert sum(r["phase"] != "terminal" for r in rows.values()) == 9
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 9

@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("failure", ["export", "vault"])
@pytest.mark.parametrize("restart", [False, True])
def test_slow_retry_does_not_skip_healthy_preparation(tmp_path, monkeypatch, target, failure, restart):
    c = setup(tmp_path, target, limit=2)
    c._store_in_vault = lambda *args, **kwargs: (False, {})
    poll(c)
    rows = list(c._ingest_records().values())
    assert len(rows) == 2
    assert all(r["phase"] == "preparing" for r in rows)
    first, healthy = (r["identity"] for r in rows)
    original_eml = c.eml
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    def configure(connector):
        connector.eml = original_eml
        store = connector._store_in_vault
        connector._store_in_vault = lambda content, identity, **kwargs: (
            (False, {}) if identity == first else store(content, identity, **kwargs))
        run = connector._utils.run_action
        def slow(action, identity=None, **kwargs):
            if action == "reconcile":
                now[0] += 100
            elif action == "export" and identity == first:
                now[0] += 400
                if failure == "export":
                    from ms_quarantine_for_splunk_soar_utils import AutomationError
                    raise AutomationError("Synthetic slow export failure")
            return run(action, identity=identity, **kwargs)
        connector._utils.run_action = slow
    # Recreate even the first retry so its healthy Vault helper is restored.
    c = setup(tmp_path, target, limit=2)
    configure(c)
    published = []
    for attempt in range(4):
        if restart and attempt:
            c = setup(tmp_path, target, limit=2)
            configure(c)
        c.events.clear()
        poll(c)
        published.extend(e for e in c.events if e[0] in {"publish", "es_publish"})
    rows = list(c._ingest_records().values())
    assert next(r for r in rows if r["identity"] == healthy)["phase"] == "published"
    assert next(r for r in rows if r["identity"] == first)["phase"] == "preparing"
    assert len(published) == 1
