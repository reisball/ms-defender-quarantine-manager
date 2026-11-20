"""Review guards using synthetic intake state/mail only; no production endpoints."""
from copy import deepcopy
from email.message import EmailMessage

import pytest

if __package__:
    from . import test_connector as t
    from .test_native_ingestion import ES, candidate, poll, setup
else:
    import test_connector as t
    from test_native_ingestion import ES, candidate, poll, setup

import ms_quarantine_for_splunk_soar_ingestion as ingestion
from ms_quarantine_for_splunk_soar_utils import AutomationError
from ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY, mail_files


def publications(c):
    return [event for event in c.events if event[0] in {"publish", "es_publish"}]


@pytest.mark.parametrize("worker_state", [
    "claimed", "running", "creating_container", "pending", "unknown",
])
def test_unresolved_legacy_workers_migrate_as_failed_without_replay(tmp_path, worker_state):
    c = setup(tmp_path, limit=1)
    state = {"quarantine_worker_ledger": {"old": {
        "state": worker_state, "identity": candidate(1)["Identity"],
        "container_id": 77, "lease_expires_at": "2020-01-01T00:00:00+00:00",
    }}}
    before = deepcopy(state)
    row = next(iter(c._ingest_load(state)["records"].values()))
    assert row["status"] == "failed" and row["terminal"] is False
    assert row["container_id"] == 77
    assert "lease_expires_at" not in row
    assert state == before
    c.save_state(state)
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["failed_imports"] == 1
    assert [call[0] for call in c.calls] == ["reconcile"]
    assert not c.events


@pytest.mark.parametrize("lease", [None, "not-a-time", "2099-01-01T00:00:00+00:00"])
def test_legacy_precontainer_claim_is_failed_regardless_of_old_lease(tmp_path, lease):
    c = setup(tmp_path, limit=1)
    state = {"quarantine_worker_ledger": {"old": {
        "identity": candidate(1)["Identity"],
        "state": "creating_container", "container_id": None,
        "lease_expires_at": lease,
    }}}
    c.save_state(state)
    assert poll(c)[0] == t.APP_SUCCESS
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "failed"
    assert row["container_id"] is None
    assert not c.events
    assert not any(call[0] == "export" for call in c.calls)


def test_legacy_es_delivery_state_requires_migration_before_any_intake(tmp_path):
    c = setup(tmp_path, "es", limit=1)
    state = {"quarantine_es_deliveries": {"old-delivery": {"state": "pending"}}}
    c.save_state(state)
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "controlled migration" in ar.get_message()
    assert c.load_state() == state
    assert not c.calls and not c.events
    c._ingest_es_client_instance.request.assert_not_called()


@pytest.mark.parametrize("state", [
    None, [], "unavailable",
    {"quarantine_worker_ledger": []},
    {"quarantine_worker_ledger": {"old": None}},
    {"quarantine_worker_ledger": {"old": {"state": "completed"}}},
    {INGEST_STATE_KEY: []},
    {INGEST_STATE_KEY: {"scope": {}, "records": []}},
])
def test_malformed_state_is_rejected_without_mutation(tmp_path, state):
    c = setup(tmp_path, limit=1)
    before = deepcopy(state)
    with pytest.raises(AutomationError):
        c._ingest_load(state)
    assert state == before
    assert not c.calls and not c.events


@pytest.mark.parametrize("row", [
    None, [], {},
    {"key": "row", "phase": "invented", "identity": "identity"},
    {"key": "other", "phase": "reserved", "identity": "identity"},
    {"key": "row", "phase": "reserved", "identity": None},
    {"key": "row", "phase": "reserved", "identity": 7},
])
def test_malformed_native_record_blocks_intake(tmp_path, row):
    c = setup(tmp_path, limit=1)
    c.save_state({INGEST_STATE_KEY: {"scope": c._ingest_scope(), "records": {"row": row}}})
    before = c.load_state()
    assert poll(c)[0] == t.APP_ERROR
    assert c.load_state() == before
    assert not c.calls and not c.events


@pytest.mark.parametrize("field", [
    "asset_id", "tenant", "organization", "target",
])
def test_every_persisted_scope_component_is_binding(tmp_path, field):
    c = setup(tmp_path, limit=1)
    scope = c._ingest_scope()
    scope[field] = "different-scope"
    state = {INGEST_STATE_KEY: {"scope": scope, "records": {}}}
    c.save_state(state)
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "scope mismatch" in ar.get_message()
    assert c.load_state() == state
    assert not c.calls and not c.events


def wide_mail(children):
    message = EmailMessage()
    message["Subject"] = "Synthetic MIME breadth"
    message.make_mixed()
    for _ in range(children):
        part = EmailMessage()
        part.set_content("ordinary body, not a file")
        message.attach(part)
    return message.as_bytes()


def deep_mail(depth):
    message = EmailMessage()
    message["Subject"] = "Synthetic MIME depth"
    current = message
    for _ in range(depth):
        current.make_mixed()
        child = EmailMessage()
        current.attach(child)
        current = child
    current.set_content("leaf")
    return message.as_bytes()


def test_mime_part_budget_counts_nonattachment_body_parts():
    # Root counts as a part. No attachments: this must exercise the MIME
    # structure bound rather than the separate attachment-count guard.
    assert mail_files(wide_mail(ingestion.MAX_MIME_PARTS - 1)) == []
    with pytest.raises(AutomationError, match="MIME structure limits"):
        mail_files(wide_mail(ingestion.MAX_MIME_PARTS))


def test_mime_depth_boundary_is_enforced_independently_of_part_count():
    assert ingestion.MAX_MIME_DEPTH + 2 < ingestion.MAX_MIME_PARTS
    assert mail_files(deep_mail(ingestion.MAX_MIME_DEPTH)) == []
    with pytest.raises(AutomationError, match="MIME structure limits"):
        mail_files(deep_mail(ingestion.MAX_MIME_DEPTH + 1))


@pytest.mark.parametrize("setting", [
    "use_es_ingest", "es_run_threat_analysis", "es_launch_automation",
])
@pytest.mark.parametrize("value", [0, 1, "true", "false", None, [], {}])
def test_es_boolean_settings_reject_truthy_and_falsy_nonbooleans(tmp_path, setting, value):
    c = setup(tmp_path, "es", limit=1)
    c._config["ingest"][setting] = value
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "boolean" in ar.get_message()
    assert not c.calls and not c.events
    c._ingest_es_client_instance.request.assert_not_called()


@pytest.mark.parametrize("value", [None, "", "  ", 7, True, [], {}])
def test_es_security_domain_is_required_before_side_effects(tmp_path, value):
    c = setup(tmp_path, "es", limit=1)
    c._config["ingest"]["es_security_domain"] = value
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "es_security_domain" in ar.get_message()
    assert not c.calls and not c.events
    c._ingest_es_client_instance.request.assert_not_called()


def test_es_security_domain_cannot_be_omitted(tmp_path):
    c = setup(tmp_path, "es", limit=1)
    del c._config["ingest"]["es_security_domain"]
    assert poll(c)[0] == t.APP_ERROR
    assert not c.calls and not c.events


@pytest.mark.parametrize("optional", [
    ("es_urgency",), ("es_investigation_type",),
    ("es_urgency", "es_investigation_type"),
])
def test_es_optional_urgency_and_type_do_not_prevent_publication(tmp_path, optional):
    c = setup(tmp_path, "es", limit=1)
    for setting in optional:
        c._config["ingest"].pop(setting)
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert len(publications(c)) == 1
    finding = c._ingest_es_client_instance.request.call_args.kwargs["json"]["findings"][0]
    for setting in optional:
        assert {"es_urgency": "urgency",
                "es_investigation_type": "investigation_type"}[setting] not in finding
    assert finding["security_domain"] == ES["es_security_domain"]
    assert finding["run_threat_analysis"] is False
    assert finding["launch_automation"] is True


def test_es_poll_requires_es_target(tmp_path):
    c = setup(tmp_path, limit=1)
    ar = t.patch_ar(c)
    assert c._handle_on_es_poll({}) == t.APP_ERROR
    assert "Enable native ES ingestion" in ar.get_message()
    assert not c.calls and not c.events
    c._ingest_es_client_instance.request.assert_not_called()


@pytest.mark.parametrize("target", ["soar", "es"])
def test_ledger_cap_preserves_active_and_fresh_terminal_without_republication(tmp_path, monkeypatch, target):
    c = setup(tmp_path, target, limit=3)
    c._is_poll_now = True
    assert poll(c, container_count=1)[0] == t.APP_SUCCESS
    state = c.load_state()
    records = state[INGEST_STATE_KEY]["records"]
    completed_key = next(iter(records))
    terminal_identity = candidate(999)["Identity"].lower()
    terminal_key = c._worker_identity_key(terminal_identity, c.get_asset_id())
    terminal = {"key": terminal_key, "identity": terminal_identity,
                "status": "completed", "terminal": True, "updated_at": c._utc_now()}
    records[terminal_key] = dict(terminal)
    c.save_state(state)
    monkeypatch.setattr(ingestion, "MAX_INGEST_RECORDS", 2)

    for _ in range(2):
        status, ar = poll(c)
        assert status == t.APP_ERROR
        assert "ledger capacity reached" in ar.get_message()
        rows = c._ingest_records()
        assert set(rows) == {completed_key, terminal_key}
        assert rows[terminal_key] == terminal
        assert rows[completed_key]["status"] == "completed"
    assert len(c._saved_containers) == 1 and len(publications(c)) == 1
    assert sum(call[0] == "export" for call in c.calls) == 1


# Durable attempt faults never cause scheduled resume or repeated publication.
@pytest.mark.parametrize("boundary,when,expected_status,expected_count", [
    ("container_id", "before", "failed", 0),
    ("container_id", "after", "failed", 0),
    ("missing_artifact_fields", "before", "failed", 0),
    ("missing_artifact_fields", "after", "failed", 0),
    ("publication_started", "before", "failed", 0),
    ("publication_started", "after", "failed", 0),
    ("status", "before", "failed", 1),
    ("status", "after", "completed", 1),
])
@pytest.mark.parametrize("target", ["soar", "es"])
def test_durable_attempt_fault_does_not_automatically_resume(
    tmp_path, target, boundary, when, expected_status, expected_count
):
    c = setup(tmp_path, target, limit=1)
    original = c._ingest_update
    fired = False

    def interrupt(key, **changes):
        nonlocal fired
        if not fired and boundary in changes:
            fired = True
            if when == "after":
                original(key, **changes)
            raise AutomationError("synthetic durable attempt interruption")
        return original(key, **changes)

    c._ingest_update = interrupt
    assert poll(c)[0] == t.APP_ERROR
    assert fired
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == expected_status
    c._ingest_update = original
    for _ in range(2):
        status, ar = poll(c)
        assert status == t.APP_SUCCESS, ar.get_message()
        rows = c._ingest_records()
        assert len(rows) == 1
        row = next(iter(rows.values()))
        assert row["status"] == expected_status
        assert row["terminal"] is False
        assert len(publications(c)) == expected_count
        assert len(c._saved_containers) == 1
        assert ar.get_summary()["active_messages"] == 1
        if expected_status == "failed":
            assert row["last_error"]
        assert not {"files", "phase", "message"} & row.keys()
    assert sum(call[0] == "export" for call in c.calls) == 1
