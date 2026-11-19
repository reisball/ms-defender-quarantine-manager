"""Fault boundaries and native ES transport. No production endpoints."""
import json
from unittest.mock import Mock

import pytest
import requests_mock

if __package__:
    from . import test_connector as t
    from .test_native_ingestion import setup, poll
else:
    import test_connector as t
    from test_native_ingestion import setup, poll

from ms_quarantine_for_splunk_soar_utils import AutomationError
from ms_quarantine_for_splunk_soar_es_ingestion import NativeESClient


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("phase", ["container", "publishing", "completed"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_durable_boundary_fault_never_duplicates_dispatch(tmp_path, target, phase, when):
    c = setup(tmp_path, target, limit=1)
    original = c._ingest_update
    fired = False

    def update(key, **changes):
        nonlocal fired
        matches = ((phase == "container" and changes.get("container_id"))
                   or (phase == "publishing" and changes.get("publication_started"))
                   or (phase == "completed" and changes.get("status") == "completed"))
        if not fired and matches:
            fired = True
            if when == "after":
                original(key, **changes)
            raise AutomationError("synthetic state-write interruption")
        return original(key, **changes)
    c._ingest_update = update
    assert poll(c)[0] == t.APP_ERROR
    assert fired
    c._ingest_update = original
    poll(c)
    publications = [event for event in c.events if event[0] in {"publish", "es_publish"}]
    expected = 1 if phase == "completed" else 0
    assert len(publications) == expected
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == ("completed" if phase == "completed" and when == "after" else "failed")
    assert len([x for x in c.calls if x[0] == "export"]) == 1
    assert len(c._saved_containers) <= 1
    assert len([r for r in c._ingest_records().values() if not r["terminal"]]) == 1


@pytest.mark.parametrize("target", ["soar", "es"])
def test_lost_container_binding_waits_for_manual_retry_and_reuses_container(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    original = c._ingest_update
    fired = False
    def update(key, **changes):
        nonlocal fired
        if changes.get("container_id") and not fired:
            fired = True
            raise AutomationError("lost binding receipt")
        return original(key, **changes)
    c._ingest_update = update
    assert poll(c)[0] == t.APP_ERROR
    c._ingest_update = original
    assert poll(c)[0] == t.APP_SUCCESS
    assert len(c._saved_containers) == 1
    assert len([x for x in c.calls if x[0] == "export"]) == 1
    assert not [x for x in c.events if x[0] in {"publish", "es_publish"}]
    c.is_poll_now = lambda: True
    assert poll(c)[0] == t.APP_SUCCESS
    assert len(c._saved_containers) == 1
    assert len([x for x in c.events if x[0] in {"publish", "es_publish"}]) == 1


@pytest.mark.parametrize("target", ["soar", "es"])
def test_incomplete_attachment_upload_never_publishes(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    original = c._store_in_vault
    count = 0
    def upload(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 3:
            return False, "last attachment failed"
        return original(*args, **kwargs)
    c._store_in_vault = upload
    assert poll(c)[0] == t.APP_ERROR
    assert not [x for x in c.events if x[0] in {"publish", "es_publish"}]
    c._store_in_vault = original
    assert poll(c)[0] == t.APP_SUCCESS
    assert len(c._saved_containers) == 1


@pytest.mark.parametrize("target", ["soar", "es"])
def test_separate_metadata_artifact_failure_never_publishes(tmp_path, target):
    c = setup(tmp_path, target, limit=1, config_overrides={"artifact_layout": "separate"})
    original = c.save_artifact
    def save(artifact):
        if "-metadata-" in artifact["source_data_identifier"]:
            return t.APP_ERROR, "failed", None
        return original(artifact)
    c.save_artifact = save
    assert poll(c)[0] == t.APP_ERROR
    assert not [x for x in c.events if x[0] in {"publish", "es_publish"}]
    c.save_artifact = original
    assert poll(c)[0] == t.APP_SUCCESS


@pytest.mark.parametrize("target", ["soar", "es"])
def test_changed_eml_is_only_exported_again_on_explicit_poll_now(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    original = c._store_in_vault
    c._store_in_vault = lambda *a, **k: (False, "failed")
    assert poll(c)[0] == t.APP_ERROR
    c._store_in_vault = original
    c.eml = c.eml.replace(b"Synthetic body", b"Different body")
    assert poll(c)[0] == t.APP_SUCCESS
    assert not [x for x in c.events if x[0] in {"publish", "es_publish"}]
    assert len([x for x in c.calls if x[0] == "export"]) == 1
    c.is_poll_now = lambda: True
    assert poll(c)[0] == t.APP_SUCCESS
    assert len([x for x in c.calls if x[0] == "export"]) == 2
    assert len([x for x in c.events if x[0] in {"publish", "es_publish"}]) == 1


def test_native_es_asset_settings_override_missing_connector_config(tmp_path):
    c = setup(tmp_path, "es", limit=1)
    saved = c._config.pop("ingest")
    c._ingest_runtime = {"asset_id": 8}
    client = c._ingest_es_client_instance
    original = client.request.side_effect
    def request(method, path, **kwargs):
        if method == "GET":
            assert path == "/rest/asset/8"
            return {"configuration": {"ingest": saved}}
        return original(method, path, **kwargs)
    client.request.side_effect = request
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["ingest_target"] == "es"


def test_native_es_resolution_failure_does_not_fall_back_to_soar(tmp_path):
    c = setup(tmp_path, limit=1)
    c._ingest_runtime = {"asset_id": 8}
    c._ingest_es_client_instance.request.side_effect = AutomationError("asset read refused")
    assert poll(c)[0] == t.APP_ERROR
    assert not c.calls
    assert not c._saved_containers


def test_es_payload_validation_failure_does_not_mark_publication_intent(tmp_path):
    c = setup(tmp_path, "es", limit=1)
    c._ingest_es_client_instance.prepare_bulk_payload.side_effect = AutomationError("schema error")
    assert poll(c)[0] == t.APP_ERROR
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "failed"
    assert row["publication_started"] is False
    assert not c._ingest_es_client_instance.request.called


@pytest.mark.parametrize("failure", ["wrong_container", "two_findings", "missing_receipt", "partial"])
def test_es_ambiguous_receipts_are_not_resubmitted(tmp_path, failure):
    c = setup(tmp_path, "es", limit=1)
    receipt = {"status": "success", "created": 1, "failed": 0,
               "errors": [], "container_ids": [100], "findings": ["one"]}
    if failure == "wrong_container":
        receipt["container_ids"] = [999]
    if failure == "two_findings":
        receipt["findings"] = ["one", "two"]
    if failure == "missing_receipt":
        receipt.pop("findings")
    if failure == "partial":
        receipt.update(created=0, failed=1)
    client = c._ingest_es_client_instance
    client.request.side_effect = lambda *a, **kw: receipt
    assert poll(c)[0] == t.APP_ERROR
    row = next(iter(c._ingest_records().values()))
    assert row["status"] == "failed" and row["publication_started"]
    assert poll(c)[0] == t.APP_SUCCESS
    assert client.request.call_count == 1


def test_native_es_client_uses_runtime_session_and_csrf():
    base = "https://soar.example.test"
    with requests_mock.Mocker() as m:
        m.get(base + "/login", headers={"Set-Cookie": "csrftoken=csrf-fixture; Path=/"})
        def create(request, context):
            assert "sessionid=synthetic-native-session" in request.headers.get("Cookie", "")
            assert request.headers["X-CSRFToken"] == "csrf-fixture"
            assert request.headers["Referer"] == base + "/"
            return {"status": "success"}
        m.post(base + "/rest/enterprise_security/findings/bulk_create", json=create)
        client = NativeESClient({"user_session_token": "synthetic-native-session"}, base)
        assert client.request("POST", "/rest/enterprise_security/findings/bulk_create",
                              json={"findings": []})["status"] == "success"


def test_native_es_client_rejects_external_login_redirect():
    base = "https://soar.example.test"
    with requests_mock.Mocker() as m:
        m.get(base + "/login", status_code=302,
              headers={"Location": "https://other.example.test/login"})
        with pytest.raises(AutomationError, match="outside"):
            NativeESClient({"user_session_token": "synthetic"}, base)
        assert m.call_count == 1


@pytest.mark.parametrize("url", ["http://soar.example.test", "https://user:pass@soar.example.test",
                                "https://soar.example.test/?token=one"])
def test_native_es_client_rejects_unsafe_base(url):
    with pytest.raises(AutomationError):
        NativeESClient({"user_session_token": "synthetic"}, url)
