"""Synthetic data only; no Azure or SOAR service is contacted."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
import requests

import ms_quarantine_for_splunk_soar_utils as transport

from ms_quarantine_for_splunk_soar_utils import AutomationError, JobTimeoutError, OversizedExportError

if __package__:
    from .test_connector import JOB_ID, make_utils
else:
    from test_connector import JOB_ID, make_utils

PS = Path(__file__).resolve().parents[1] / "powershell"


def public_key(key):
    return base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode("ascii")


def run_fixture(name, *args, success=True):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell is not available")
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(PS / name), *args],
        capture_output=True, text=True, timeout=120,
    )
    assert (result.returncode == 0) == success, result.stderr[:1000]
    return result.stdout, result.stderr


def test_protected_list_has_no_readable_metadata_and_rejects_modified_records():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw, err = run_fixture(
        "test_runbook_list_contract.ps1", "-MessageCount", "6", "-SubjectLength", "90000",
        "-ProtectedOutputPublicKey", public_key(key),
    )
    assert not err
    assert "sender0@example.com" not in raw and "測測測" not in raw
    lines = raw.strip().splitlines()
    assert len(lines) > 2
    assert max(len(line.encode("utf-8")) for line in lines) < 1024 * 1024
    utils = make_utils()
    decode = utils._decrypt_job_records
    output = utils._parse_multiline_job_output(decode(raw.strip(), "list", key))
    assert output["count"] == 6 and output["messages"][0]["SenderAddress"] == "sender0@example.com"
    record = json.loads(lines[0])
    record["final"] = True
    altered = json.loads(lines[0])
    ciphertext = bytearray(base64.b64decode(altered["ciphertext"]))
    ciphertext[0] ^= 1
    altered["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
    for invalid in (
        lines[:-1],
        [lines[1], lines[0], *lines[2:]],
        [json.dumps(record), *lines[1:]],
        [json.dumps(altered), *lines[1:]],
        [*lines, lines[-1]],
        ['{"action":"list","messages":[]}'],
    ):
        with pytest.raises(AutomationError, match="invalid or incomplete"):
            decode("\n".join(invalid), "list", key)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AutomationError, match="invalid or incomplete"):
        decode(raw.strip(), "list", other_key)


def test_exact_24_mib_export_is_protected_and_keeps_chunk_and_digest_contract(tmp_path, monkeypatch):
    prefix = b"Subject: Synthetic-private-marker\r\n\r\nSynthetic-body"
    eml = prefix.ljust(24 * 1024 * 1024, b"x")
    path = tmp_path / "synthetic.b64"
    path.write_bytes(base64.b64encode(eml))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw, err = run_fixture(
        "test_runbook_export_transport.ps1", "-Base64Path", str(path),
        "-ExpectedDecodedSize", str(len(eml)), "-ProtectedOutputPublicKey", public_key(key),
    )
    assert not err and "Synthetic-private-marker" not in raw and "eml_chunk" not in raw
    assert max(len(line.encode("utf-8")) for line in raw.splitlines()) < 1024 * 1024
    utils = make_utils(retain_chunked_base64=False)
    body = raw.encode("utf-8")
    stream = OutputStream(
        body[offset:offset + transport.JOB_OUTPUT_READ_BYTES]
        for offset in range(0, len(body), transport.JOB_OUTPUT_READ_BYTES)
    )
    mock_output(monkeypatch, utils, stream, headers={"Content-Length": str(len(body))})
    output = utils.get_job_output(JOB_ID, "export", output_private_key=key)
    assert output["chunk_count"] == 132
    assert output["_eml_bytes"] == eml
    assert output["sha256"] == hashlib.sha256(eml).hexdigest()


def test_cap_plus_one_uses_production_export_and_returns_only_protected_error(tmp_path):
    cap = 24 * 1024 * 1024
    path = tmp_path / "oversized.b64"
    path.write_bytes(base64.b64encode(b"x" * (cap + 1)))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw, err = run_fixture(
        "test_runbook_connection_contract.ps1", "-LiteralRequest",
        "-RequestJson", json.dumps({
            "action": "protected_export_v1", "identity": "__IDENTITY__",
            "output_public_key": public_key(key),
        }),
        "-OrganizationVariable", "fixture.onmicrosoft.com",
        "-SyntheticExportBase64Path", str(path),
    )
    assert not err and len(raw.strip().splitlines()) == 1
    assert "export_oversized" not in raw
    utils = make_utils()
    result = json.loads(utils._decrypt_job_records(raw.strip(), "export", key))
    assert result["error_code"] == "export_oversized"
    assert result["handling"] == "fail_closed"
    assert "eml" not in result
    with pytest.raises(OversizedExportError) as exc:
        utils._raise_for_runbook_error(result, "export", result["identity"])
    assert exc.value.decoded_size == cap + 1
    assert exc.value.max_decoded_size == cap


@pytest.mark.parametrize("requested,code", [
    ("list", "protected_output_required"),
    ("export", "protected_output_required"),
    ("protected_list_v1", "protected_output_unavailable"),
    ("protected_export_v1", "protected_output_unavailable"),
])
def test_missing_protection_fails_before_exchange(requested, code):
    raw, err = run_fixture(
        "test_runbook_connection_contract.ps1", "-LiteralRequest",
        "-RequestJson", json.dumps({"action": requested, "identity": "__IDENTITY__"}),
        "-OrganizationVariable", "fixture.onmicrosoft.com",
    )
    assert not err
    result = json.loads(raw)
    assert result["connect_calls"] == [] and result["quarantine_reads"] == 0
    assert result["result"]["error_code"] == code

class OutputStream:
    """Synthetic urllib3 adapter stream; no DNS or HTTP service is used."""

    def __init__(self, chunks):
        self.chunks = chunks
        self.opened = False
        self.closed = False
        self.read_count = 0

    def stream(self, size, decode_content):
        assert decode_content and size == transport.JOB_OUTPUT_READ_BYTES
        self.opened = True
        for chunk in self.chunks:
            self.read_count += 1
            yield chunk

    def close(self):
        self.closed = True

    def release_conn(self):
        self.closed = True


def mock_output(monkeypatch, utils, stream, status=200, headers=None, on_send=None):
    url = utils._job_output_url(JOB_ID)
    utils._mgmt_token = "synthetic-token"
    calls = []

    def send(request, **kwargs):
        assert request.url == url
        assert request.headers["Accept-Encoding"] == "identity"
        assert kwargs["stream"] and kwargs["verify"]
        calls.append(kwargs)
        if on_send:
            on_send()
        response = requests.Response()
        response.status_code = status
        response.url = url
        response.request = request
        response.raw = stream
        response.headers.update(headers or {})
        return response

    monkeypatch.setattr(utils._session.get_adapter(url), "send", send)
    return calls


@pytest.mark.parametrize("declared_length", [None, "bad", "2", "00000008", "9" * 5000])
def test_stream_size_bound_closes_without_decoding(monkeypatch, declared_length):
    utils = make_utils()
    monkeypatch.setattr(transport, "MAX_JOB_OUTPUT_BYTES", 7)
    stream = OutputStream([b"abc", b"private", b"must not be read"])
    calls = mock_output(
        monkeypatch, utils, stream,
        headers={} if declared_length is None else {"Content-Length": declared_length},
    )
    with pytest.raises(AutomationError, match="7-byte download limit") as error:
        utils.get_job_output(JOB_ID, "list")
    assert "private" not in str(error.value)
    assert stream.closed and len(calls) == 1
    assert stream.read_count == (0 if declared_length in {"00000008", "9" * 5000} else 2)


def test_exact_http_byte_limit_allows_split_utf8(monkeypatch):
    payload = '{"action":"reconcile","label":"測"}'
    encoded = payload.encode("utf-8")
    monkeypatch.setattr(transport, "MAX_JOB_OUTPUT_BYTES", len(encoded))
    split = encoded.index("測".encode("utf-8")) + 1
    utils = make_utils()
    stream = OutputStream([encoded[:split], encoded[split:]])
    mock_output(monkeypatch, utils, stream)
    assert utils.get_job_output(JOB_ID, "reconcile") == json.loads(payload)
    assert stream.closed


@pytest.mark.parametrize("late_at", ["headers", "chunk", "eof"])
def test_output_cannot_succeed_after_shared_deadline(monkeypatch, late_at):
    utils = make_utils()
    now = [9.0]
    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: now[0]))

    def send_headers():
        if late_at == "headers":
            now[0] = 10.0

    def chunks():
        if late_at == "chunk":
            now[0] = 10.0
        yield b'{"action":"reconcile"}'
        if late_at == "eof":
            now[0] = 10.0

    stream = OutputStream(chunks())
    calls = mock_output(monkeypatch, utils, stream, on_send=send_headers)
    with pytest.raises(JobTimeoutError) as error:
        utils.get_job_output(JOB_ID, "reconcile", deadline=10.0)
    assert error.value.phase == "output"
    assert error.value.last_status == "Completed"
    assert error.value.job_id == JOB_ID
    assert stream.closed and stream.opened == (late_at != "headers")
    assert len(calls) == 1 and calls[0]["timeout"] == 1.0


@pytest.mark.parametrize("status,headers,message", [
    (302, {"Location": "https://example.invalid/redirect"}, "HTTP 302"),
    (403, {}, "HTTP 403"),
    (200, {"Content-Encoding": "gzip"}, "unsupported HTTP content encoding"),
])
def test_rejected_http_output_body_is_never_consumed(monkeypatch, status, headers, message):
    utils = make_utils()
    stream = OutputStream([b"private"])
    calls = mock_output(monkeypatch, utils, stream, status=status, headers=headers)
    with pytest.raises(AutomationError, match=message) as error:
        utils.get_job_output(JOB_ID, "list")
    assert "private" not in str(error.value)
    assert not stream.opened and stream.closed and len(calls) == 1


def test_incomplete_http_body_is_closed_before_retry(monkeypatch):
    utils = make_utils(poll_interval=1)
    now = [0.0]
    sleeps = []

    def broken_chunks():
        yield b'{"private":"partial body'
        raise requests.exceptions.ConnectionError("synthetic transport failure")

    first = OutputStream(broken_chunks())
    second = OutputStream([b'{"action":"reconcile"}'])
    calls = mock_output(monkeypatch, utils, first)
    adapter = utils._session.get_adapter(utils._job_output_url(JOB_ID))
    original_send = adapter.send

    def send(request, **kwargs):
        response = original_send(request, **kwargs)
        if len(calls) > 1:
            assert first.closed
            response.raw = second
        return response

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(adapter, "send", send)
    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=sleep))
    assert utils.get_job_output(JOB_ID, "reconcile", deadline=3.0) == {"action": "reconcile"}
    assert first.closed and second.closed
    assert sleeps == [1.0]
    assert [call["timeout"] for call in calls] == [3.0, 2.0]
