"""Synchronous poll budgets; the retired phase scheduler has no replay contract."""
import pytest

if __package__:
    from .test_native_ingestion import setup, poll, t
else:
    from test_native_ingestion import setup, poll, t

import ms_quarantine_for_splunk_soar_ingestion as ingestion
from ms_quarantine_for_splunk_soar_utils import AutomationError


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("terminal", ["Released", "Denied"])
def test_failed_export_is_not_resumed_and_terminal_observation_frees_slot(
        tmp_path, monkeypatch, target, terminal):
    c = setup(tmp_path, target, limit=1)
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action

    def slow_failure(action, **kwargs):
        if action == "export":
            c.calls.append((action, kwargs["identity"], {}))
            now[0] += 500
            raise AutomationError("Synthetic poison export")
        return run(action, **kwargs)

    c._utils.run_action = slow_failure
    assert poll(c)[0] == t.APP_ERROR
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "failed"
    # A restarted scheduled poll observes status but never retries the failed job.
    c = setup(tmp_path, target, limit=1)
    assert poll(c)[0] == t.APP_SUCCESS
    assert [call[0] for call in c.calls] == ["reconcile"]
    assert not c.events
    c.observed[row["identity"]] = terminal
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert c._ingest_records()[row["key"]]["terminal"] is True
    assert c._ingest_records()[row["key"]]["status"] == "failed"
    assert ar.get_summary()["active_messages"] == 1
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 1
    assert all(identity != row["identity"] for action, identity, _ in c.calls if action == "export")


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("elapsed", [600, 650])
@pytest.mark.parametrize("boundary", [
    "export", "container", "vault", "file", "last_file", "metadata", "es_prepare", "publication",
])
def test_budget_stops_next_effect_and_persists_only_attempt_result(
        tmp_path, monkeypatch, target, elapsed, boundary):
    if target == "soar" and boundary == "es_prepare":
        pytest.skip("Only ES has bulk-payload preparation")
    c = setup(tmp_path, target, limit=1, config_overrides=(
        {"artifact_layout": "separate"} if boundary in {"file", "last_file", "metadata"} else {}
    ))
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    effects = []

    def invoke(label, fn, *args, **kwargs):
        assert now[0] < 600, (label, effects)
        result = fn(*args, **kwargs)
        effects.append(label)
        if label == boundary:
            now[0] += elapsed
        return result

    run = c._utils.run_action
    c._utils.run_action = lambda action, **kw: invoke(action, run, action, **kw)
    container = c.save_container
    c.save_container = lambda value: invoke("container", container, value)
    store = c._store_in_vault
    c._store_in_vault = lambda *a, **kw: invoke("vault", store, *a, **kw)
    artifact = c.save_artifact

    def save_artifact(value):
        sdi = value["source_data_identifier"]
        label = ("publication" if value["run_automation"] else
                 "last_file" if sdi.endswith("-file-2") else
                 "file" if "-file-" in sdi else "metadata")
        return invoke(label, artifact, value)

    c.save_artifact = save_artifact
    client = c._ingest_es_client_instance
    prepare = client.prepare_bulk_payload.side_effect
    client.prepare_bulk_payload.side_effect = lambda value: invoke("es_prepare", prepare, value)
    publish = client.request.side_effect
    client.request.side_effect = lambda *a, **kw: invoke("publication", publish, *a, **kw)
    status, ar = poll(c)
    assert boundary in effects, (boundary, effects)
    assert effects[-1] == boundary
    assert now[0] == elapsed
    row = next(iter(c._ingest_records().values()))
    if boundary == "publication":
        assert status == t.APP_SUCCESS, ar.get_message()
        assert row["status"] == "completed"
        assert row["finding_id"] if target == "es" else row["email_artifact_id"]
    else:
        assert status == t.APP_ERROR, ar.get_message()
        assert "budget" in ar.get_message()
        assert row["status"] == "failed"
    assert row["container_id"] is None if boundary == "export" else row["container_id"]
    assert not {"files", "phase", "message", "_es_payload", "email_artifact"} & row.keys()
    restored = setup(tmp_path, target, limit=1)
    restored._ingest_settings()
    assert restored._ingest_records()[row["key"]] == row
    assert poll(restored)[0] == t.APP_SUCCESS
    assert [call[0] for call in restored.calls] == ["reconcile"]
    assert not restored.events


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("terminal", ["Released", "Denied"])
def test_slow_status_read_persists_terminal_evidence_without_further_jobs(
        tmp_path, monkeypatch, target, terminal):
    c = setup(tmp_path, target, limit=2)
    assert poll(c)[0] == t.APP_SUCCESS
    rows = list(c._ingest_records().values())
    c.calls.clear()
    c.observed[rows[0]["identity"]] = terminal
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action

    def slow(action, **kwargs):
        result = run(action, **kwargs)
        now[0] += 600
        return result

    c._utils.run_action = slow
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "budget" in ar.get_message()
    assert [call[0] for call in c.calls] == ["reconcile"]
    assert c._ingest_records()[rows[0]["key"]]["terminal"] is True
    assert c._ingest_records()[rows[0]["key"]]["status"] == "completed"
    assert c._ingest_records()[rows[1]["key"]]["terminal"] is False


@pytest.mark.parametrize("target", ["soar", "es"])
def test_unavailable_status_keeps_window_and_stops_additional_remote_work(tmp_path, target):
    c = setup(tmp_path, target, limit=2)
    assert poll(c)[0] == t.APP_SUCCESS
    rows = list(c._ingest_records().values())
    c.calls.clear()
    c.events.clear()
    c.observed[rows[0]["identity"]] = AutomationError("Synthetic status unavailable")
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert ar.get_summary()["active_messages"] == 2
    assert [call[0] for call in c.calls] == ["reconcile"]
    assert not c.events
    assert all(row["status"] == "completed" and not row["terminal"]
               for row in c._ingest_records().values())


@pytest.mark.parametrize("save_result", [False, t.APP_ERROR])
def test_attempt_state_persistence_failure_never_starts_remote_work(tmp_path, save_result):
    c = setup(tmp_path, limit=1)
    c.save_state = lambda state: save_result
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "state could not be saved" in ar.get_message()
    assert not c.calls
    assert not c.events
