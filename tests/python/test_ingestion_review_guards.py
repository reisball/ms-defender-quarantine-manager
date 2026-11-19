"""Review guards using synthetic intake state/mail only; no production endpoints."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
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
def test_unresolved_legacy_workers_block_migration_without_mutation(tmp_path, worker_state):
    c = setup(tmp_path, limit=1)
    state = {t.WORKER_STATE_KEY: {"old": {
        "state": worker_state, "identity": candidate(1)["Identity"],
        "container_id": 77,
        "lease_expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
    }}}
    before = deepcopy(state)
    with pytest.raises(AutomationError, match="unresolved workers") as error:
        c._ingest_load(state)
    assert "Disable intake" in str(error.value)
    assert "previous app version before upgrading" in str(error.value)
    assert "This version cannot update legacy workers" in str(error.value)
    assert state == before
    assert not c.calls and not c.events


@pytest.mark.parametrize("lease", [None, "not-a-time", "2099-01-01T00:00:00+00:00"])
def test_unproven_legacy_precontainer_claim_is_not_silently_dropped(tmp_path, lease):
    c = setup(tmp_path, limit=1)
    with pytest.raises(AutomationError, match="unresolved workers|invalid timestamp"):
        c._ingest_load({t.WORKER_STATE_KEY: {"old": {
            "state": "creating_container", "container_id": None,
            "lease_expires_at": lease,
        }}})


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
    {t.WORKER_STATE_KEY: []},
    {t.WORKER_STATE_KEY: {"old": None}},
    {t.WORKER_STATE_KEY: {"old": {"state": "completed"}}},
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
def test_ledger_cap_preserves_active_and_fresh_terminal_and_processes_pending(
    tmp_path, monkeypatch, target
):
    c = setup(tmp_path, target, limit=3)
    c._ingest_settings()
    c._ingest_reserve([c.candidates[0]], 3, 1)
    state = c.load_state()
    records = state[INGEST_STATE_KEY]["records"]
    pending_key = next(iter(records))
    terminal_identity = candidate(999)["Identity"].lower()
    terminal_key = c._worker_identity_key(terminal_identity, c.get_asset_id())
    terminal = {"key": terminal_key, "identity": terminal_identity, "phase": "terminal",
                "updated_at": c._utc_now()}
    records[terminal_key] = dict(terminal)
    c.save_state(state)
    monkeypatch.setattr(ingestion, "MAX_INGEST_RECORDS", 2)

    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "ledger capacity reached" in ar.get_message()
    rows = c._ingest_records()
    assert set(rows) == {pending_key, terminal_key}
    assert rows[terminal_key] == terminal
    assert rows[pending_key]["phase"] == "published"
    assert rows[pending_key]["identity"] == c.candidates[0]["Identity"].lower()
    assert ar.get_summary()["active_messages"] == 1
    assert len(c._saved_containers) == 1 and len(publications(c)) == 1
    assert sum(call[0] == "export" for call in c.calls) == 1
    assert poll(c)[0] == t.APP_ERROR
    assert len(publications(c)) == 1
    assert set(c._ingest_records()) == {pending_key, terminal_key}


# An intent saved before the request, or an unknown final receipt, cannot be
# retried automatically. All earlier boundaries must finish exactly once.
@pytest.mark.parametrize("phase,when,first_phase,recovered_phase,expected_count", [
    ("preparing", "before", "reserved", "published", 1),
    ("preparing", "after", "preparing", "published", 1),
    ("ready", "before", "preparing", "published", 1),
    ("ready", "after", "ready", "published", 1),
    ("publishing", "before", "ready", "published", 1),
    ("publishing", "after", "publishing", "publishing", 0),
    ("published", "before", "publishing", "publishing", 1),
    ("published", "after", "published", "published", 1),
])
@pytest.mark.parametrize("target", ["soar", "es"])
def test_fault_recovery_requires_complete_publication_or_explicit_uncertainty(
    tmp_path, target, phase, when, first_phase, recovered_phase, expected_count
):
    c = setup(tmp_path, target, limit=1)
    original = c._ingest_update
    fired = False

    def interrupt(key, **changes):
        nonlocal fired
        if not fired and changes.get("phase") == phase:
            fired = True
            if when == "after":
                original(key, **changes)
            raise AutomationError("synthetic durable phase interruption")
        return original(key, **changes)

    c._ingest_update = interrupt
    assert poll(c)[0] == t.APP_ERROR
    assert fired
    assert next(iter(c._ingest_records().values()))["phase"] == first_phase
    c._ingest_update = original
    for _ in range(2):
        status, ar = poll(c)
        assert status == (t.APP_ERROR if recovered_phase == "publishing" else t.APP_SUCCESS), ar.get_message()
        rows = c._ingest_records()
        assert len(rows) == 1
        row = next(iter(rows.values()))
        assert row["phase"] == recovered_phase
        assert row["phase"] != "terminal"
        assert len(publications(c)) == expected_count
        assert len(c._saved_containers) == 1
        assert ar.get_summary()["active_messages"] == 1
        if recovered_phase == "publishing":
            assert row["last_error"]
