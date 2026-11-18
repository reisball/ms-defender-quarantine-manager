"""Second-review MIME and canonical migration regressions; synthetic input only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

if __package__:
    from . import test_connector as t
    from .test_native_ingestion import poll, setup
else:
    import test_connector as t
    from test_native_ingestion import poll, setup

from ms_quarantine_for_splunk_soar_utils import AutomationError
from ms_quarantine_for_splunk_soar_ingestion import mail_files


def malformed_mail(kind):
    if kind == "nested_multipart":
        body = (
            b"Content-Type: multipart/mixed; boundary=missing\r\n\r\n"
            b"This multipart has no boundary.\r\n"
        )
    elif kind == "body_decode":
        # Decoding defects appear only on get_payload(decode=True). A body
        # without a filename used to skip the subsequent defect check.
        body = (
            b"Content-Type: text/plain\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n%%%%\r\n"
        )
    elif kind == "attached_mail":
        body = b"Content-Type: message/rfc822\r\n\r\n" + malformed_mail("body_decode")
    elif kind == "attached_multipart":
        body = b"Content-Type: message/rfc822\r\n\r\n" + malformed_mail("nested_multipart")
    else:
        raise AssertionError(kind)
    return (
        b"Subject: synthetic malformed MIME\r\n"
        b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n"
        b"--outer\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=first.bin\r\n\r\none\r\n"
        b"--outer\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=second.bin\r\n\r\ntwo\r\n"
        b"--outer\r\n" + body + b"--outer--\r\n"
    )


@pytest.mark.parametrize("kind", [
    "nested_multipart", "body_decode", "attached_mail", "attached_multipart",
])
def test_every_mime_node_must_validate_even_without_extracted_file(kind):
    with pytest.raises(AutomationError, match="Malformed MIME"):
        mail_files(malformed_mail(kind))


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("kind", [
    "nested_multipart", "body_decode", "attached_mail", "attached_multipart",
])
def test_malformed_mime_never_reaches_either_publication_target(tmp_path, target, kind):
    c = setup(tmp_path, target, limit=1)
    c.candidates = c.candidates[:1]
    c.eml = malformed_mail(kind)
    for _ in range(2):
        status, ar = poll(c)
        assert status == t.APP_ERROR
        assert "Malformed MIME" in ar.get_message()
    assert not c.events  # No container, artifact, Vault or publication writes.
    assert not c._saved_containers
    c._ingest_es_client_instance.request.assert_not_called()
    assert sum(action == "export" for action, _, _ in c.calls) == 1
    row = next(iter(c._ingest_records().values()))
    assert row["phase"] == "blocked"
    assert row["container_id"] is None


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("reverse", [False, True])
def test_canonical_migration_preserves_newest_terminal_evidence(tmp_path, target, reverse):
    c = setup(tmp_path, target, limit=1)
    c._ingest_settings()
    c.candidates = c.candidates[:1]
    identity = c.candidates[0]["Identity"]
    now = datetime.now(timezone.utc)
    stale = (now - timedelta(days=c._worker_terminal_retention_days + 1)).isoformat()
    fresh = now.isoformat()
    newest = {"state": "completed", "identity": identity.upper(),
              "container_id": 77, "created_at": fresh, "updated_at": fresh}
    oldest = {"state": "failed", "identity": " " + identity.lower() + " ",
              "container_id": 22, "created_at": stale, "updated_at": stale}
    entries = [("new", newest), ("old", oldest)]
    if reverse:
        entries.reverse()
    state = {t.WORKER_STATE_KEY: dict(entries)}
    before = deepcopy(state)
    row = next(iter(c._ingest_load(state)["records"].values()))
    assert state == before
    assert row["identity"] == identity.lower()
    assert row["updated_at"] == fresh
    assert row["created_at"] == fresh
    assert row["container_id"] == 77
    assert row["migration_origin"] == "legacy_completed"
    c.save_state(state)
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert not c.events
    assert all(action != "export" for action, _, _ in c.calls)
    assert next(iter(c._ingest_records().values())) == row


@pytest.mark.parametrize("timestamps", [
    ("2026-11-07T10:00:00+00:00", "2026-11-07T11:00:00+01:00"),
    (None, None),
    ("2026-11-07T10:00:00+00:00", None),
])
def test_migration_ties_offsets_and_missing_times_are_order_independent(tmp_path, timestamps):
    c = setup(tmp_path, limit=1)
    identity = c.candidates[0]["Identity"]
    entries = [(str(i), {"state": state, "identity": identity,
                        "container_id": i + 1, "updated_at": stamp})
               for i, (state, stamp) in enumerate(zip(("failed", "completed"), timestamps))]
    rows = [c._ingest_load({t.WORKER_STATE_KEY: dict(order)})["records"]
            for order in (entries, list(reversed(entries)))]
    assert rows[0] == rows[1]
    if timestamps[1] is None and timestamps[0] is not None:
        assert next(iter(rows[0].values()))["container_id"] == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_invalid_terminal_timestamp_refuses_migration_without_mutating_source(tmp_path, reverse):
    c = setup(tmp_path, limit=1)
    identity = c.candidates[0]["Identity"]
    entries = [(str(i), {"state": "completed", "identity": identity,
                        "updated_at": stamp})
               for i, stamp in enumerate(("2026-11-07T10:00:00Z", "not-a-time"))]
    if reverse:
        entries.reverse()
    state = {t.WORKER_STATE_KEY: dict(entries)}
    before = deepcopy(state)
    with pytest.raises(AutomationError, match="invalid timestamp"):
        c._ingest_load(state)
    assert state == before
