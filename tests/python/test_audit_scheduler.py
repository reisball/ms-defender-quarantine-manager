"""Issue #117: deterministic clocks, real ledger reloads, no external services."""
import pytest

if __package__:
    from .test_native_ingestion import setup, poll, t
else:
    from test_native_ingestion import setup, poll, t

import ms_quarantine_for_splunk_soar_ingestion as ingestion
from ms_quarantine_for_splunk_soar_utils import AutomationError


def reserve(c, count):
    c._ingest_settings()
    c._ingest_reserve(c.candidates[:count], count, count)
    return list(c._ingest_records().values())


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("terminal", ["Released", "Denied"])
@pytest.mark.parametrize("restart", [False, True])
def test_exact_100_status_500_poison_export_cannot_starve_status(
        tmp_path, monkeypatch, target, terminal, restart):
    c = setup(tmp_path, target, limit=3)
    first, middle, last = reserve(c, 3)
    c._ingest_update(middle["key"], phase="published")
    c._ingest_update(last["key"], phase="published")
    eml = c.eml
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])

    def configure(connector):
        connector.eml = eml
        connector.observed[last["identity"]] = terminal
        run = connector._utils.run_action

        def slow(action, **kwargs):
            if action == "export":
                assert kwargs["identity"] == first["identity"]
                connector.calls.append((action, kwargs["identity"], {}))
                now[0] += 500
                raise AutomationError("Synthetic poison export")
            result = run(action, **kwargs)
            if action == "reconcile":
                now[0] += 100
            return result

        connector._utils.run_action = slow

    configure(c)
    poll(c)
    assert [(x[0], x[1]) for x in c.calls] == [
        ("reconcile", first["identity"]), ("export", first["identity"])]
    assert now[0] == 600
    # Only persisted scheduling state survives a connector restart.
    if restart:
        c = setup(tmp_path, target, limit=3)
        configure(c)
    c.calls.clear()
    poll(c)
    assert c._ingest_records()[last["key"]]["phase"] == "terminal"
    assert c._ingest_records()[first["key"]]["phase"] == "reserved"
    assert not any(x[0] == "list" for x in c.calls)
    assert not c.events


@pytest.mark.parametrize("target", ["soar", "es"])
def test_repeated_poison_preparations_and_restarts_still_publish_healthy(
        tmp_path, monkeypatch, target):
    c = setup(tmp_path, target, limit=3)
    rows = reserve(c, 3)
    eml = c.eml
    poisons = {r["identity"] for r in rows[:2]}
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    seen = set()
    publications = []
    for _ in range(6):
        c = setup(tmp_path, target, limit=3)
        c.eml = eml
        run = c._utils.run_action

        def slow(action, **kwargs):
            if action == "export" and kwargs["identity"] in poisons:
                c.calls.append((action, kwargs["identity"], {}))
                now[0] += 500
                raise AutomationError("Synthetic poison export")
            result = run(action, **kwargs)
            if action == "reconcile":
                now[0] += 100
            return result

        c._utils.run_action = slow
        poll(c)
        seen.update(x[1] for x in c.calls if x[0] == "reconcile")
        publications.extend(e for e in c.events if e[0] in {"publish", "es_publish"})
        assert not any(x[0] == "list" for x in c.calls)
    assert seen == {r["identity"] for r in rows}
    assert c._ingest_records()[rows[-1]["key"]]["phase"] == "published"
    assert all(c._ingest_records()[r["key"]]["phase"] == "reserved" for r in rows[:2])
    assert len(publications) == 1


@pytest.mark.parametrize("target", ["soar", "es"])
def test_global_status_cursor_survives_failures_and_unknowns_with_pending(tmp_path, monkeypatch, target):
    c = setup(tmp_path, target, limit=4)
    rows = reserve(c, 4)
    for row in rows[1:]:
        c._ingest_update(row["key"], phase="published")
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    seen = set()
    for _ in range(8):
        c = setup(tmp_path, target, limit=4)
        c.observed[rows[1]["identity"]] = AutomationError("Synthetic unavailable observation")
        c.observed[rows[2]["identity"]] = "NotReleased"
        c.observed[rows[3]["identity"]] = "Released"
        run = c._utils.run_action

        def slow(action, **kwargs):
            assert action != "list"
            if action == "export":
                now[0] += 500
                raise AutomationError("Synthetic poison export")
            # Failed reads consume time and advance only the global status cursor.
            now[0] += 100
            return run(action, **kwargs)

        c._utils.run_action = slow
        poll(c)
        seen.update(x[1] for x in c.calls if x[0] == "reconcile")
    persisted = c._ingest_records()
    assert seen == {r["identity"] for r in rows}
    assert [persisted[r["key"]]["phase"] for r in rows] == [
        "reserved", "published", "published", "terminal"]
    assert not c.events


@pytest.mark.parametrize("target", ["soar", "es"])
def test_global_cursor_rotates_before_excluding_pending_identity(tmp_path, monkeypatch, target):
    c = setup(tmp_path, target, limit=4)
    rows = reserve(c, 4)
    cursor = rows[1]["key"]
    c._ingest_schedule_attempt("reconcile", cursor)
    # Recreate to establish that rotation comes from disk, not a local iterator.
    c = setup(tmp_path, target, limit=4)
    c._ingest_settings()
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    c._ingest_deadline = 600
    run = c._utils.run_action

    def slow(action, **kwargs):
        result = run(action, **kwargs)
        now[0] += 300
        return result

    c._utils.run_action = slow
    c._ingest_reconcile(c._ingest_records(), exclude={cursor})
    assert [x[1] for x in c.calls] == [r["identity"] for r in rows[2:]]
    assert c.load_state()[ingestion.INGEST_STATE_KEY]["scheduler"]["reconcile"] == rows[3]["key"]


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("elapsed", [600, 650])
@pytest.mark.parametrize("boundary", [
    "export", "container", "vault", "file", "last_file", "metadata", "es_prepare", "publication",
])
def test_budget_stops_next_effect_but_keeps_completed_receipts(
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
        # Every scheduler-owned effect starts before the same poll deadline.
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
        assert row["phase"] == "published"
        assert row["finding_id"] if target == "es" else row["email_artifact_id"]
    else:
        assert status == t.APP_ERROR, ar.get_message()
        assert "budget" in ar.get_message()
        assert row["phase"] in {"preparing", "ready"}
    if boundary == "export":
        assert row["container_id"] is None
        assert row["files"] == {}
    else:
        assert row["container_id"]
        assert len(row["files"]) == (
            0 if boundary == "container" else 1 if boundary in {"vault", "file"} else 3)
    # Persisted container/Vault/publication receipts survive process replacement.
    restored = setup(tmp_path, target, limit=1)
    restored._ingest_settings()
    assert restored._ingest_records()[row["key"]] == row


@pytest.mark.parametrize("target", ["soar", "es"])
def test_status_exhaustion_keeps_preparation_cursor_and_terminal_evidence(
        tmp_path, monkeypatch, target):
    c = setup(tmp_path, target, limit=2)
    rows = reserve(c, 2)
    cursor = rows[-1]["key"]
    c._ingest_schedule_attempt("prepare", cursor)
    now = [0.0]
    monkeypatch.setattr(ingestion.time, "monotonic", lambda: now[0])
    run = c._utils.run_action

    def slow(action, **kwargs):
        result = run(action, **kwargs)
        now[0] += 600
        return result

    c._utils.run_action = slow
    poll(c)
    assert [x[0] for x in c.calls] == ["reconcile"]
    assert c.load_state()[ingestion.INGEST_STATE_KEY]["scheduler"]["prepare"] == cursor
    assert c._ingest_records()[rows[0]["key"]]["observed_release_status"] == "requested"
    # The next (status-first) poll persists terminal evidence even at its deadline.
    c.calls.clear()
    c.observed[rows[0]["identity"]] = "Denied"
    poll(c)
    assert [x[0] for x in c.calls] == ["reconcile"]
    assert c._ingest_records()[rows[0]["key"]]["phase"] == "terminal"
    assert c.load_state()[ingestion.INGEST_STATE_KEY]["scheduler"]["prepare"] == cursor


@pytest.mark.parametrize("target", ["soar", "es"])
def test_pending_at_poll_start_never_discovers_even_when_all_retire(tmp_path, target):
    c = setup(tmp_path, target, limit=2)
    rows = reserve(c, 2)
    for row in rows:
        c.observed[row["identity"]] = "Released"
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert [x[0] for x in c.calls] == ["reconcile", "reconcile"]
    assert all(r["phase"] == "terminal" for r in c._ingest_records().values())


@pytest.mark.parametrize("priority", [None, "unknown", [], 1])
def test_malformed_class_priority_fails_before_remote_effects(tmp_path, priority):
    c = setup(tmp_path, limit=1)
    reserve(c, 1)
    state = c.load_state()
    state[ingestion.INGEST_STATE_KEY]["scheduler"] = {"next_priority": priority}
    c.save_state(state)
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "priority is malformed" in ar.get_message()
    assert not c.calls
    assert not c.events


@pytest.mark.parametrize("save_result", [False, t.APP_ERROR])
def test_priority_persistence_failure_never_starts_remote_work(tmp_path, save_result):
    c = setup(tmp_path, limit=1)
    reserve(c, 1)
    c.save_state = lambda state: save_result
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "scheduling priority" in ar.get_message()
    assert not c.calls
    assert not c.events
