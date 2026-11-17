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
"""Public Vault links must not inherit native loopback transport URLs."""

from unittest.mock import Mock
from urllib.parse import quote

import pytest
import requests_mock


if __package__:
    from . import test_connector as t
    from .test_es_transport_review import BASE, login
    from .test_native_ingestion import ES, poll, sample_mail, setup
else:
    import test_connector as t
    from test_es_transport_review import BASE, login
    from test_native_ingestion import ES, poll, sample_mail, setup

import ms_quarantine_for_splunk_soar_es_ingestion as es
from ms_quarantine_for_splunk_soar_utils import AutomationError


PUBLIC = "https://soar.example.test:8443"


def test_loopback_transport_publishes_only_public_download_links(platform, tmp_path):
    c = setup(tmp_path, "es", limit=1)
    with requests_mock.Mocker() as m:
        login(m)
        m.get(BASE + "/rest/version", json={"version": "8.6.0"})
        info = m.get(BASE + "/rest/system_info", json={"base_url": PUBLIC + "/"})
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        c._ingest_es_client_instance = client
        post = m.post(
            BASE + "/rest/enterprise_security/findings/bulk_create",
            json={"status": "success", "created": 1, "failed": 0, "errors": [], "container_ids": [100], "findings": ["one"]},
        )
        status, ar = poll(c)
        assert status == t.APP_SUCCESS, ar.get_message()
        email = post.last_request.json()["findings"][0]["email"]
        assert len(email["attachments"]) == 3
        links = [a["url"] for a in email["attachments"]] + [email["raw_email_link"]]
        assert all(link.startswith(PUBLIC + "/rest/download_attachment?vault_id=") for link in links)
        assert email["raw_email_link"] == email["attachments"][0]["url"]
        assert client.base_url == BASE
        assert info.call_count == 1
        assert all(r.url.startswith(BASE + "/") for r in m.request_history)


def prepared(client):
    upload = Mock(side_effect=["raw /?&", "one /?&", "two /?&"])
    finding = es.build_finding({}, sample_mail(), "id", "work", "source", ES, upload, client.base_url)
    original = {"findings": [finding], "container_ids": [100]}
    return original, client.prepare_bulk_payload(original)


def test_download_origin_cached_without_mutating_input_or_vault_ids(platform):
    with requests_mock.Mocker() as m:
        login(m)
        m.get(BASE + "/rest/version", json={"version": "8.7.0"})
        info = m.get(BASE + "/rest/system_info", json={"base_url": PUBLIC})
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        for _ in range(2):
            original, wire = prepared(client)
            email = wire["findings"][0]["email"]
            for attachment, vault_id in zip(email["attachments"], ["raw /?&", "one /?&", "two /?&"]):
                assert attachment["url"] == PUBLIC + "/rest/download_attachment?vault_id=" + quote(vault_id, safe="")
            assert original["findings"][0]["email"]["raw_email_link"].startswith(BASE + "/")
        assert info.call_count == 1


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "",
        1,
        "http://soar.example.test",
        BASE,
        "https://localhost",
        "https://x.localhost",
        "https://[::1]",
        "https://0.0.0.0",
        "https://127.1",
        "https://2130706433",
        "https://0x7f000001",
        "https://[::ffff:127.0.0.1]",
        "https://user:secret@soar.example.test",  # pragma: allowlist secret - synthetic rejected URL
        "https://soar.example.test/path",
        "https://soar.example.test?query=1",
        "https://soar.example.test/#fragment",
        "https://soar.example.test:bad",
        "https://soar.example.test\\evil",
        "https://soar.example.test\n",
    ],
)
def test_invalid_public_origin_fails_before_submission(platform, origin):
    with requests_mock.Mocker() as m:
        login(m)
        m.get(BASE + "/rest/version", json={"version": "8.7.0"})
        m.get(BASE + "/rest/system_info", json={"base_url": origin})
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        with pytest.raises(AutomationError, match="download origin"):
            prepared(client)
        assert all(r.method == "GET" for r in m.request_history)


def test_findings_without_email_need_no_origin_lookup(platform):
    with requests_mock.Mocker() as m:
        login(m)
        m.get(BASE + "/rest/version", json={"version": "8.7.0"})
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        assert client.prepare_bulk_payload({"findings": [{"rule_title": "one"}]}) == {"findings": [{"rule_title": "one"}]}
        assert all(r.path != "/rest/system_info" for r in m.request_history)
