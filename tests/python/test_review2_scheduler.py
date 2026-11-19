"""Slow synchronous calls respect one poll budget without resumable work."""
import pytest

if __package__:
    from .test_native_ingestion import setup, poll, t
else:
    from test_native_ingestion import setup, poll, t

import ms_quarantine_for_splunk_soar_ingestion as ingestion


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("export_seconds,completed", [(100, 5), (400, 1)])
def test_slow_exports_finish_with_failed_marker_not_pending_scheduler_work(
        tmp_path, monkeypatch, target, export_seconds, completed):
    c = setup(tmp_path, target, limit=10)
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action

    def slow(action, **kwargs):
        result = run(action, **kwargs)
        if action == "export":
            now[0] += export_seconds
        return result

    c._utils.run_action = slow
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "budget" in ar.get_message()
    rows = c._ingest_records()
    assert len(rows) == completed + 1
    assert sum(row["status"] == "completed" for row in rows.values()) == completed
    assert sum(row["status"] == "failed" for row in rows.values()) == 1
    failed = next(row for row in rows.values() if row["status"] == "failed")
    assert not any(row["status"] == "running" for row in rows.values())
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == completed
    assert "scheduler" not in c.load_state()[ingestion.INGEST_STATE_KEY]

    # A fresh process can fill unused slots, never automatically retry the failure.
    restarted = setup(tmp_path, target, limit=10)
    # Native containers survive connector replacement; preserve that fixture state.
    restarted._saved_containers = c._saved_containers
    restarted._next_container_id = c._next_container_id
    status, ar = poll(restarted)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert len(restarted._ingest_records()) == 10
    assert ar.get_summary()["active_messages"] == 10
    assert ar.get_summary()["failed_imports"] == 1
    assert all(identity != failed["identity"] for action, identity, _ in restarted.calls
               if action == "export")
    assert restarted._ingest_records()[failed["key"]]["status"] == "failed"


def test_status_read_failure_blocks_new_intake_until_observation_recovers(tmp_path):
    from ms_quarantine_for_splunk_soar_utils import AutomationError
    c = setup(tmp_path, limit=3)
    c._is_poll_now = True
    assert poll(c, container_count=2)[0] == t.APP_SUCCESS
    identities = [row["identity"] for row in c._ingest_records().values()]
    c.observed[identities[0]] = AutomationError("synthetic failure")
    c.calls.clear()
    c.events.clear()
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert ar.get_summary()["active_messages"] == 2
    assert [call[0] for call in c.calls] == ["reconcile"]
    assert not c.events

    c.observed[identities[0]] = "Requested"
    c.calls.clear()
    assert poll(c)[0] == t.APP_SUCCESS
    assert [identity for action, identity, _ in c.calls if action == "reconcile"] == identities[1:] + identities[:1]
    assert len(c._ingest_records()) == 3
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 1
