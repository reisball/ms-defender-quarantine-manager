"""Synthetic slow-call regressions: pending work and status reads must both progress."""
import pytest
if __package__:
    from .test_native_ingestion import setup, poll
else:
    from test_native_ingestion import setup, poll
import ms_quarantine_for_splunk_soar_ingestion as ingestion

@pytest.mark.parametrize("target", ["soar", "es"])
def test_slow_calls_do_not_starve_pending_imports(tmp_path, monkeypatch, target):
    c = setup(tmp_path, target)
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action
    def slow(action, **kwargs):
        result = run(action, **kwargs)
        if action in {"export", "reconcile"}:
            now[0] += 100
        return result
    c._utils.run_action = slow
    poll(c)
    assert any(r["phase"] in {"reserved", "preparing", "ready"} for r in c._ingest_records().values())
    before = len([x for x in c.calls if x[0] == "export"])
    reconciled = set()
    # Separate polls reload the persisted scheduling cursor, not in-memory iteration state.
    for _ in range(12):
        c.calls.clear()
        poll(c)
        reconciled.update(x[1] for x in c.calls if x[0] == "reconcile")
        if all(r["phase"] == "published" for r in c._ingest_records().values()):
            break
    rows = c._ingest_records()
    assert len(rows) == 10
    assert all(r["phase"] == "published" for r in rows.values())
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 10
    assert reconciled
    for _ in range(4):
        c.calls.clear()
        poll(c)
        reconciled.update(x[1] for x in c.calls if x[0] == "reconcile")
    assert reconciled == {r["identity"] for r in rows.values()}

def test_reconcile_cursor_rotates_past_repeated_remote_failure(tmp_path):
    c = setup(tmp_path, limit=3)
    poll(c)
    identities = [r["identity"] for r in c._ingest_records().values()]
    from ms_quarantine_for_splunk_soar_utils import AutomationError
    c.observed[identities[0]] = AutomationError("synthetic failure")
    c.calls.clear()
    poll(c)
    assert [x[1] for x in c.calls if x[0] == "reconcile"] == [identities[0]]
    c.calls.clear()
    poll(c)
    assert {x[1] for x in c.calls if x[0] == "reconcile"} >= set(identities[1:])

@pytest.mark.parametrize("target", ["soar", "es"])
def test_unequal_slow_calls_finish_pending_imports(tmp_path, monkeypatch, target):
    c = setup(tmp_path, target)
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action
    def slow(action, **kwargs):
        result = run(action, **kwargs)
        now[0] += {"reconcile": 100, "export": 400}.get(action, 0)
        return result
    c._utils.run_action = slow
    poll(c)
    # Pending classes alternate: allow one preparation-first poll per identity.
    for _ in range(2 * 10):
        if all(r["phase"] == "published" for r in c._ingest_records().values()):
            break
        poll(c)
    assert len(c._ingest_records()) == 10
    assert all(r["phase"] == "published" for r in c._ingest_records().values())
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 10
