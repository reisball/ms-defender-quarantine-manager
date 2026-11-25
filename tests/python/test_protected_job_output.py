"""Synthetic data only; no Azure or SOAR service is contacted."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from ms_quarantine_for_splunk_soar_utils import AutomationError, OversizedExportError

if __package__:
    from .test_connector import make_utils
else:
    from test_connector import make_utils

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


def test_exact_24_mib_export_is_protected_and_keeps_chunk_and_digest_contract(tmp_path):
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
    output = utils._parse_multiline_job_output(utils._decrypt_job_records(raw.strip(), "export", key))
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
