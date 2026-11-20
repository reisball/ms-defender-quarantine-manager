"""Transport regressions against SDK 6.1.5 semantics; no production endpoints."""
import json
import sys
import types
from unittest.mock import Mock

import pytest
import requests
import requests_mock

if __package__:
    from . import test_connector as t
    from .test_native_ingestion import setup, ES
else:
    import test_connector as t
    from test_native_ingestion import setup, ES

import ms_quarantine_for_splunk_soar_es_ingestion as es
from ms_quarantine_for_splunk_soar_utils import AutomationError

BASE = "https://127.0.0.1:9999"


@pytest.fixture
def platform(monkeypatch):
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    info = types.ModuleType("phantom_common.install_info")
    info.get_verify_ssl_setting = lambda: True
    info.is_onprem_broker_install = lambda: False
    package = types.ModuleType("phantom_common")
    package.install_info = info
    monkeypatch.setitem(sys.modules, "phantom_common", package)
    monkeypatch.setitem(sys.modules, "phantom_common.install_info", info)
    return info


def login(m, base=BASE):
    m.get(base + "/login", headers={"Set-Cookie": "csrftoken=csrf; Path=/"})


@pytest.mark.parametrize("base,verify", [
    (BASE, False), ("https://localhost:9999", True),
    ("https://soar.example.test", True),
    ("https://127.0.0.2:9999", True),
    ("https://127.0.0.1.evil.test:9999", True),
])
def test_verified_native_transport_policy(platform, base, verify):
    with requests_mock.Mocker() as m:
        login(m, base)
        m.get(base + "/rest/asset/8", json={"configuration": {"ingest": {}}})
        client = es.NativeESClient({"user_session_token": "native"}, base)
        client.request("GET", "/rest/asset/8")
        assert all(r.verify is verify for r in m.request_history)


def test_explicit_platform_verify_setting_is_honored(platform):
    platform.get_verify_ssl_setting = lambda: False
    with requests_mock.Mocker() as m:
        login(m, "https://soar.example.test")
        es.NativeESClient({"user_session_token": "native"}, "https://soar.example.test")
        assert m.last_request.verify is False


@pytest.mark.parametrize("runtime", [
    {"user_session_token": "native", "broker_ph_auth_token": "broker"},
    {"user_session_token": "native"},
])
def test_broker_install_or_token_fails_before_network(platform, runtime):
    platform.is_onprem_broker_install = lambda: True
    with requests_mock.Mocker() as m, pytest.raises(AutomationError, match="Broker"):
        es.NativeESClient(runtime, BASE)
    assert m.call_count == 0


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 413, 422])
def test_http_rejection_is_reported_without_automatic_repost(platform, status):
    with requests_mock.Mocker() as m:
        login(m)
        m.post(BASE + "/rest/enterprise_security/findings/bulk_create",
               status_code=status, text="DO NOT EXPOSE BODY OR COOKIE")
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        with pytest.raises(AutomationError) as caught:
            client.request("POST", "/rest/enterprise_security/findings/bulk_create", json={})
        assert f"HTTP {status}" in str(caught.value)
        assert sum(r.method == "POST" for r in m.request_history) == 1
        assert "DO NOT EXPOSE" not in str(caught.value)


@pytest.mark.parametrize("status", [408, 425, 429, 499, 500, 502, 503, 504])
def test_uncertain_http_outcomes_are_reported_without_automatic_repost(platform, status):
    with requests_mock.Mocker() as m:
        login(m)
        m.post(BASE + "/rest/enterprise_security/findings/bulk_create", status_code=status)
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        with pytest.raises(AutomationError) as caught:
            client.request("POST", "/rest/enterprise_security/findings/bulk_create", json={})
        assert sum(r.method == "POST" for r in m.request_history) == 1


@pytest.mark.parametrize("failure", [requests.Timeout("secret"), requests.ConnectionError("secret")])
def test_network_outcomes_are_uncertain_and_sanitized(platform, failure):
    with requests_mock.Mocker() as m:
        login(m)
        m.post(BASE + "/rest/enterprise_security/findings/bulk_create", exc=failure)
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        with pytest.raises(AutomationError) as caught:
            client.request("POST", "/rest/enterprise_security/findings/bulk_create", json={})
        assert type(failure).__name__ in str(caught.value)
        assert sum(r.method == "POST" for r in m.request_history) == 1
        assert "secret" not in str(caught.value)


def test_native_handle_action_captures_runtime_and_reads_live_asset(platform, monkeypatch, tmp_path):
    # The closed-source BaseConnector dispatcher is unavailable locally. Simulate
    # only its dispatch boundary; exercise the actual mixin, transport and poll.
    c = setup(tmp_path, limit=1)
    c._get_phantom_base_url = lambda: BASE
    c._ingest_es_client_instance = Mock()  # must be discarded by native entrypoint

    def platform_dispatch(connector, in_json, *args):
        envelope = json.loads(in_json)
        connector._asset_id = envelope["asset_id"]
        connector._action_id = "on_poll"
        return connector.handle_action(envelope["parameters"][0])

    monkeypatch.setattr(t._BaseConnector, "_handle_action", platform_dispatch, raising=False)
    with requests_mock.Mocker() as m:
        login(m)
        m.get(BASE + "/rest/asset/8", json={"configuration": {"ingest": dict(ES)}})
        m.get(BASE + "/rest/system_info", json={"base_url": "https://soar.example.test"})
        m.get(BASE + "/rest/version", json={"version": "8.6.0"})
        m.post(BASE + "/rest/enterprise_security/findings/bulk_create", json={
            "status": "success", "created": 1, "failed": 0, "errors": [],
            "container_ids": [100], "findings": ["one"]})
        result = c._handle_action(json.dumps({
            "asset_id": 8, "user_session_token": "native", "parameters": [{}]}), None)
        assert result == t.APP_SUCCESS
        assert isinstance(c._ingest_es_client_instance, es.NativeESClient)
        posts = [r for r in m.request_history if r.method == "POST"]
        assert len(posts) == 1
        assert isinstance(posts[0].json()["findings"][0]["additional_fields"], list)
        assert all(r.verify is False for r in m.request_history)


@pytest.mark.parametrize("setting,value", [
    ("es_drilldown_searches", "not a list"),
    ("es_drilldown_searches", [{}]),
    ("es_drilldown_searches", [{"name": "x", "search": "index=x", "earliest": 0, "latest": "now"}]),
    ("es_drilldown_dashboards", [{"name": "x", "app": "search"}]),
    ("es_drilldown_dashboards", [{"name": "x", "app": "search", "dashboard_id": "x", "tokens": ["bad"]}]),
])
def test_invalid_drilldowns_rejected_before_upload(setting, value):
    upload = Mock(return_value="vault")
    ingest = dict(ES, **{setting: value})
    with pytest.raises(AutomationError, match="drilldown"):
        es.build_finding({}, b"From: a@example.test\r\n\r\nbody", "id", "work", "source",
                         ingest, upload, BASE)
    upload.assert_not_called()


@pytest.mark.parametrize("location", [
    "https://127.0.0.1:10000/login", "https://localhost:9999/login",
    "https://other.example.test/login",
])
def test_login_cannot_move_loopback_exception_to_other_origin(platform, location):
    with requests_mock.Mocker() as m:
        m.get(BASE + "/login", status_code=302, headers={"Location": location})
        with pytest.raises(AutomationError, match="outside"):
            es.NativeESClient({"user_session_token": "native"}, BASE)
        assert m.call_count == 1


def test_runtime_verify_false_does_not_disable_external_tls(platform):
    base = "https://soar.example.test"
    with requests_mock.Mocker() as m:
        login(m, base)
        client = es.NativeESClient({"user_session_token": "native", "verify": False}, base)
        assert m.last_request.verify is True
        with pytest.raises(AutomationError, match="fixed-origin"):
            client.request("GET", "/rest/asset/8", verify=False)
        assert m.call_count == 1


@pytest.mark.parametrize("version,field_type", [("8.6.0", list), ("8.7.0", dict), ("9.0.0", dict)])
def test_version_wire_adaptation_preserves_internal_shape(platform, version, field_type):
    with requests_mock.Mocker() as m:
        login(m)
        m.get(BASE + "/rest/version", json={"version": version})
        client = es.NativeESClient({"user_session_token": "native"}, BASE)
        original = {"findings": [{"rule_title": "one", "additional_fields": {"nested": {"id": 1}}}]}
        wire = client.prepare_bulk_payload(original)
        assert isinstance(wire["findings"][0]["additional_fields"], field_type)
        assert original["findings"][0]["additional_fields"] == {"nested": {"id": 1}}


def test_native_loopback_real_tls_with_non_ip_certificate(platform, monkeypatch, tmp_path):
    """Exercise an actual TLS handshake, not just a mock's verify argument."""
    import shutil
    import ssl
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl unavailable for ephemeral TLS certificate fixture")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=soar.example.test",
    ], check=True, capture_output=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            assert "sessionid=native" in self.headers.get("Cookie", "")
            self.send_response(200)
            if self.path == "/login":
                self.send_header("Set-Cookie", "csrftoken=csrf; Path=/")
                body = b"login"
            else:
                assert self.headers["X-CSRFToken"] == "csrf"
                body = b'{"configuration": {"ingest": {}}}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    base = "https://127.0.0.1:" + str(server.server_port)
    try:
        with pytest.raises(requests.exceptions.SSLError):
            requests.get(base + "/login", verify=True, timeout=3)
        with pytest.warns(requests.packages.urllib3.exceptions.InsecureRequestWarning):
            client = es.NativeESClient({"user_session_token": "native"}, base)
            assert client.request("GET", "/rest/asset/8") == {"configuration": {"ingest": {}}}
        client.session.close()
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
