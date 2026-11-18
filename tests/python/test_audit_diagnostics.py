"""Synthetic diagnostics regressions; no tenant credentials or network."""
import json
import subprocess
import shutil
from pathlib import Path
import pytest
if __package__:
    from . import test_connector as t
else:
    import test_connector as t
from ms_quarantine_for_splunk_soar_utils import redact_sensitive_text

MARKER = "AUDIT_SYNTHETIC_SECRET_123"
HEADERS = [
    '{"Authorization":"Bearer ' + MARKER + '"}',
    '{"Cookie":"session=' + MARKER + '; other=value"}',
    'Authorization: "Bearer ' + MARKER + '"',
    "Authorization: 'Bearer " + MARKER + "'",
    '{"Set-Cookie":"session=' + MARKER + '; HttpOnly"}',
    '{"authorization":"Basic ' + MARKER + '", "note":"keep this"}',
    '{"Cookie":"session=escaped\\\"' + MARKER + '"}',
]


@pytest.mark.parametrize("output", [
    {"action": "list", "error": True, "message": "failure client_secret=" + MARKER},
    {"diagnostic": "client_secret=" + MARKER},
])
def test_connectivity_redacts_structured_and_unexpected_output(output):
    c = t.make_connector()
    ar = t.patch_ar(c)
    with t.req_mock.Mocker() as m:
        t.mock_full_flow(m, output)
        assert c._handle_test_connectivity({}) == t.APP_ERROR
    assert MARKER not in ar.get_message()


@pytest.mark.parametrize("text", HEADERS)
def test_python_quoted_headers_are_complete(text):
    result = redact_sensitive_text(text)
    assert MARKER not in result
    if text.startswith("{"):
        assert json.loads(result)  # retain valid surrounding JSON
    if "keep this" in text:
        assert "keep this" in result


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
def test_powershell_quoted_headers_match_python(tmp_path):
    payload = tmp_path / "headers.json"
    payload.write_text(json.dumps(HEADERS))
    script = tmp_path / "redact.ps1"
    script.write_text("""
param($Runbook, $Data)
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Runbook, [ref]$tokens, [ref]$errors)
foreach ($name in @('Test-JwtCompactSerialization', 'ConvertTo-SecretRedactedText')) {
    $node = $ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}, $true)
    Invoke-Expression $node.Extent.Text
}
$rows = Get-Content -Raw $Data | ConvertFrom-Json
@($rows | ForEach-Object { ConvertTo-SecretRedactedText $_ }) | ConvertTo-Json -Compress
""")
    result = subprocess.run(["pwsh", "-NoLogo", "-NoProfile", "-File", str(script),
                             str((Path(__file__).resolve().parents[2] / "runbook" / "runbook.ps1")), str(payload)],
                            check=True, text=True, capture_output=True, timeout=30)
    values = json.loads(result.stdout)
    assert len(values) == len(HEADERS)
    for original, value in zip(HEADERS, values):
        assert MARKER not in value
        if original.startswith("{"):
            assert json.loads(value)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
@pytest.mark.parametrize('mode', ['unavailable', 'token_failure', 'missing_guids', 'malformed_guids'])
def test_unresolved_rbac_identity_remains_unknown(mode):
    result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-File',
                             str((Path(__file__).resolve().parents[1] / "powershell" / "test_runbook_diagnostics.ps1")),
                             '-IdentityMode', mode], check=True, text=True, capture_output=True, timeout=30)
    envelope = json.loads(result.stdout)
    data = envelope.get('details', envelope)
    assert data['rbac_diagnostics_status'] == 'partial'
    for field in ['role_assignment_matches_identity', 'quarantine_group_membership_confirmed',
                  'quarantine_administrator_membership_confirmed']:
        assert data[field] is None


# Each tuple specifies the complete preserved text around the redacted value.
# Unterminated quotes stop at the physical line boundary, never the next line.
MALFORMED_HEADERS = [
    (f'prefix Authorization: "{MARKER}', 'prefix Authorization: "[REDACTED]'),
    (f"prefix Authorization: '{MARKER}", "prefix Authorization: '[REDACTED]"),
    (f'prefix Authorization: "{MARKER}\nnext diagnostic stays',
     'prefix Authorization: "[REDACTED]\nnext diagnostic stays'),
    (f"prefix Authorization: '{MARKER}\r\nnext diagnostic stays",
     "prefix Authorization: '[REDACTED]\r\nnext diagnostic stays"),
    (f'prefix Authorization: "Bearer {MARKER}', 'prefix Authorization: "[REDACTED]'),
    (f'prefix "Authorization": "{MARKER}', 'prefix "Authorization": "[REDACTED]'),
]
ESCAPED_HEADERS = [
    (f'prefix "Authorization": "escaped`"{MARKER}" suffix', 'prefix "Authorization": "[REDACTED]" suffix'),
    (f'prefix "Cookie": "escaped""{MARKER}" suffix', 'prefix "Cookie": "[REDACTED]" suffix'),
    (f"prefix Cookie='session=escaped''{MARKER}' suffix", "prefix Cookie='[REDACTED]' suffix"),
    (f'prefix Cookie="session=escaped`"{MARKER}" suffix', 'prefix Cookie="[REDACTED]" suffix'),
    (f'prefix Cookie="session=escaped\\"{MARKER}" suffix', 'prefix Cookie="[REDACTED]" suffix'),
    (f'prefix Authorization: "escaped""{MARKER}" suffix', 'prefix Authorization: "[REDACTED]" suffix'),
    (f"prefix Set-Cookie='session=escaped`'{MARKER}' suffix", "prefix Set-Cookie='[REDACTED]' suffix"),
    (f"prefix Cookie='session=escaped\\'{MARKER}' suffix", "prefix Cookie='[REDACTED]' suffix"),
    (f'prefix Cookie="escaped`"{MARKER}\nnext diagnostic stays',
     'prefix Cookie="[REDACTED]\nnext diagnostic stays'),
    (f'prefix Cookie="{MARKER}\\\nnext diagnostic stays',
     'prefix Cookie="[REDACTED]\nnext diagnostic stays'),
    (f'prefix Cookie="{MARKER}`\r\nnext diagnostic stays',
     'prefix Cookie="[REDACTED]\r\nnext diagnostic stays'),
]


@pytest.mark.parametrize('text,expected', MALFORMED_HEADERS + ESCAPED_HEADERS)
def test_python_incomplete_and_escaped_header_values(text, expected):
    assert redact_sensitive_text(text) == expected


@pytest.mark.parametrize('text,expected', MALFORMED_HEADERS + ESCAPED_HEADERS)
def test_connectivity_incomplete_and_escaped_header_values(text, expected):
    c = t.make_connector()
    ar = t.patch_ar(c)
    output = {"action": "list", "error": True, "message": text}
    with t.req_mock.Mocker() as m:
        t.mock_full_flow(m, output)
        assert c._handle_test_connectivity({}) == t.APP_ERROR
    assert MARKER not in ar.get_message()


def run_powershell_helpers(tmp_path, names, body):
    script = tmp_path / 'helpers.ps1'
    script.write_text('''
param($Runbook)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Runbook, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0] }
foreach ($name in ''' + "@(" + ','.join("'" + name + "'" for name in names) + ")" + ''') {
    $node = $ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name}, $true)
    if ($null -eq $node) { throw "Missing helper $name" }
    Invoke-Expression $node.Extent.Text
}
''' + body)
    result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-File', str(script),
                             str((Path(__file__).resolve().parents[2] / "runbook" / "runbook.ps1"))],
                            check=True, text=True, capture_output=True, timeout=30)
    return result.stdout


@pytest.mark.skipif(shutil.which('pwsh') is None, reason='PowerShell is not installed')
def test_powershell_incomplete_and_escaped_header_values(tmp_path):
    cases = MALFORMED_HEADERS + ESCAPED_HEADERS
    (tmp_path / 'headers.json').write_text(json.dumps([text for text, _ in cases]))
    output = run_powershell_helpers(tmp_path,
        ['Test-JwtCompactSerialization', 'ConvertTo-SecretRedactedText'], '''
$rows = Get-Content -Raw (Join-Path $PSScriptRoot 'headers.json') | ConvertFrom-Json
@($rows | ForEach-Object { ConvertTo-SecretRedactedText $_ }) | ConvertTo-Json -Compress
''')
    values = json.loads(output)
    assert values == [expected.replace('[REDACTED]', '[redacted]') for _, expected in cases]


@pytest.mark.skipif(shutil.which('pwsh') is None, reason='PowerShell is not installed')
@pytest.mark.parametrize('action', ['release', 'deny'])
def test_success_guard_counts_serialized_bytes_and_preserves_contract(tmp_path, action):
    required = dict(action=action, identity='identity-must-stay',
                    status='released' if action == 'release' else 'denied',
                    operation_action=action, operation_id='operation-must-stay',
                    observed_release_status='Released' if action == 'release' else 'Denied',
                    cmdlet_invocation_attempted=True, cmdlet_executed=True)
    (tmp_path / 'required.json').write_text(json.dumps(required))
    output = run_powershell_helpers(tmp_path, [
        'Write-SuccessResult', 'ConvertTo-RunbookJson', 'Add-RunbookEnvelopeMetadata',
        'Get-Utf8ByteCount', 'Test-JwtCompactSerialization', 'ConvertTo-SecretRedactedText'], '''
$ListMaxRecordBytes = 900 * 1024
$DiagnosticMaxChars = 2048
$script:RuntimeDiagnosticEvidence = @{}
$script:PassiveExchangeEvidence = @{ cmdlet_default_parameter_set = ([string][char]1 * 180000) }
$data = Get-Content -Raw (Join-Path $PSScriptRoot 'required.json') | ConvertFrom-Json -AsHashtable
$data.cmdlet_default_parameter_set = $script:PassiveExchangeEvidence.cmdlet_default_parameter_set
Write-Output ([Text.Encoding]::UTF8.GetByteCount((ConvertTo-RunbookJson -Data $data)))
Write-SuccessResult -Data $data
''')
    before, record = output.splitlines()
    assert int(before) > 1024 * 1024
    assert len(record.encode('utf-8')) <= 900 * 1024
    data = json.loads(record)
    assert {key: data[key] for key in required} == required
    assert data['cmdlet_default_parameter_set_truncated'] is True
    assert data['cmdlet_default_parameter_set_original_chars'] == 180000


@pytest.mark.skipif(shutil.which('pwsh') is None, reason='PowerShell is not installed')
@pytest.mark.parametrize('action', ['release', 'deny'])
def test_native_disposition_success_with_large_passive_metadata(tmp_path, action):
    if __package__:
        from .test_runbook_release_diagnostics import run_fixture
    else:
        from test_runbook_release_diagnostics import run_fixture
    # Fixture asserts exactly one disposition call and validates native args.
    data = run_fixture(tmp_path, action, large=False, oversized_passive_metadata=True)
    assert data['action'] == action
    assert data['identity'] == 'c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7'
    assert data['status'] == ('released' if action == 'release' else 'denied')
    assert data['observed_release_status'] == ('Released' if action == 'release' else 'Denied')
    assert data['cmdlet_invocation_attempted'] is True
    assert data['cmdlet_executed'] is True
    assert data['cmdlet_contract_id'] == ('identity_releasetoall' if action == 'release' else 'identities_actiontype_no_dummy')
    assert data['cmdlet_default_parameter_set_truncated'] is True
    assert data['cmdlet_default_parameter_set_original_chars'] == 180000
    assert len(json.dumps(data, ensure_ascii=False).encode('utf-8')) <= 900 * 1024


JSON_HEADER_CASES = [
    (json.dumps(dict([('note', 'keep'), (header, value)] if note_first else
                     [(header, value), ('note', 'keep')])),
     json.dumps(dict([('note', 'keep'), (header, '[REDACTED]')] if note_first else
                     [(header, '[REDACTED]'), ('note', 'keep')])))
    for header in ('Authorization', 'Cookie', 'Set-Cookie')
    for value in (
        'session=literal`"' + MARKER,
        'session=' + MARKER + '`',
        'session=literal\\`"' + MARKER,
        'session=literal``"' + MARKER,
    )
    for note_first in (False, True)
]
NONSENSITIVE_ESCAPE_TEXTS = [
    json.dumps({'note': 'literal`"keep', 'path': 'C:\\temp\\'}),
    'ordinary diagnostic with `" and doubled single quotes: \'\' keep',
    'first diagnostic\nsecond diagnostic remains',
]


@pytest.mark.parametrize('text,expected', JSON_HEADER_CASES)
def test_python_json_headers_keep_json_escape_semantics(text, expected):
    assert json.loads(text)['note'] == 'keep'  # fixtures must be valid JSON
    result = redact_sensitive_text(text)
    assert MARKER not in result
    assert json.loads(result) == json.loads(expected)
    assert result == expected
    assert redact_sensitive_text('prefix ' + text + ' suffix') == 'prefix ' + expected + ' suffix'


@pytest.mark.parametrize('text,expected', JSON_HEADER_CASES)
def test_connectivity_json_headers_keep_json_escape_semantics(text, expected):
    c = t.make_connector()
    ar = t.patch_ar(c)
    with t.req_mock.Mocker() as m:
        t.mock_full_flow(m, {'action': 'list', 'error': True, 'message': text})
        assert c._handle_test_connectivity({}) == t.APP_ERROR
    assert MARKER not in ar.get_message()
    assert expected in ar.get_message()


@pytest.mark.parametrize('text', NONSENSITIVE_ESCAPE_TEXTS)
def test_python_unrelated_escaped_text_is_unchanged(text):
    assert redact_sensitive_text(text) == text


@pytest.mark.skipif(shutil.which('pwsh') is None, reason='PowerShell is not installed')
def test_powershell_json_headers_keep_json_escape_semantics(tmp_path):
    cases = JSON_HEADER_CASES + [
        ('prefix ' + text + ' suffix', 'prefix ' + expected + ' suffix')
        for text, expected in JSON_HEADER_CASES
    ] + [(text, text) for text in NONSENSITIVE_ESCAPE_TEXTS]
    (tmp_path / 'headers.json').write_text(json.dumps([text for text, _ in cases]))
    output = run_powershell_helpers(tmp_path,
        ['Test-JwtCompactSerialization', 'ConvertTo-SecretRedactedText'], '''
$rows = Get-Content -Raw (Join-Path $PSScriptRoot 'headers.json') | ConvertFrom-Json
@($rows | ForEach-Object { ConvertTo-SecretRedactedText $_ }) | ConvertTo-Json -Compress
''')
    values = json.loads(output)
    assert values == [expected.replace('[REDACTED]', '[redacted]') for _, expected in cases]
    for value in values[:len(JSON_HEADER_CASES)]:
        assert json.loads(value)['note'] == 'keep'
