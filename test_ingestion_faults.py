# Copyright (c) 2026 Kai Seidenschnur
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Fault boundaries and native ES transport. No production endpoints."""

import pytest
import requests_mock


if __package__:
    from . import test_connector as t
    from .test_native_ingestion import poll, setup
else:
    import test_connector as t
    from test_native_ingestion import poll, setup

from ms_quarantine_for_splunk_soar_es_ingestion import NativeESClient
from ms_quarantine_for_splunk_soar_utils import AutomationError


@pytest.mark.parametrize("target", ["soar", "es"])
@pytest.mark.parametrize("phase", ["preparing", "ready", "publishing", "published"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_durable_boundary_fault_never_duplicates_dispatch(tmp_path, target, phase, when):
    c = setup(tmp_path, target, limit=1)
    original = c._ingest_update
    fired = False

    def update(key, **changes):
        nonlocal fired
        if not fired and changes.get("phase") == phase:
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
    expected = 0 if phase == "publishing" and when == "after" else 1
    assert len(publications) == expected
    if expected == 0:
        assert next(iter(c._ingest_records().values()))["phase"] == "publishing"
    assert len(c._saved_containers) <= 1
    assert len([r for r in c._ingest_records().values() if r["phase"] != "terminal"]) == 1


@pytest.mark.parametrize("target", ["soar", "es"])
def test_lost_container_binding_recovers_same_container(tmp_path, target):
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
def test_metadata_artifact_failure_never_publishes(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
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
def test_changed_eml_during_recovery_is_not_published(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    original = c._store_in_vault
    c._store_in_vault = lambda *a, **k: (False, "failed")
    assert poll(c)[0] == t.APP_ERROR
    c._store_in_vault = original
    c.eml = c.eml.replace(b"Synthetic body", b"Different body")
    assert poll(c)[0] == t.APP_ERROR
    assert not [x for x in c.events if x[0] in {"publish", "es_publish"}]


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
    assert next(iter(c._ingest_records().values()))["phase"] == "ready"
    assert not c._ingest_es_client_instance.request.called


@pytest.mark.parametrize("failure", ["wrong_container", "two_findings", "missing_receipt", "partial"])
def test_es_ambiguous_receipts_are_not_resubmitted(tmp_path, failure):
    c = setup(tmp_path, "es", limit=1)
    receipt = {"status": "success", "created": 1, "failed": 0, "errors": [], "container_ids": [100], "findings": ["one"]}
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
    assert next(iter(c._ingest_records().values()))["phase"] == "publishing"
    assert poll(c)[0] == t.APP_ERROR
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
        assert client.request("POST", "/rest/enterprise_security/findings/bulk_create", json={"findings": []})["status"] == "success"


def test_native_es_client_rejects_external_login_redirect():
    base = "https://soar.example.test"
    with requests_mock.Mocker() as m:
        m.get(base + "/login", status_code=302, headers={"Location": "https://other.example.test/login"})
        with pytest.raises(AutomationError, match="outside"):
            NativeESClient({"user_session_token": "synthetic"}, base)
        assert m.call_count == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://soar.example.test",
        "https://user:pass@soar.example.test",  # pragma: allowlist secret - synthetic rejected URL
        "https://soar.example.test/?token=one",
    ],
)
def test_native_es_client_rejects_unsafe_base(url):
    with pytest.raises(AutomationError):
        NativeESClient({"user_session_token": "synthetic"}, url)
