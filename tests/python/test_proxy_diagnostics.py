"""Read-only Exchange proxy evidence, exercised through the real diagnose path."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import test_connector as t

ROOT = Path(__file__).resolve().parents[2]
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell is not installed")
SECRET = 'PROXY_SYNTHETIC_SECRET_123'
MODULE = r'''
Remove-Item Function:\Release-QuarantineMessage
$module = New-Module -Name ProxyDiagnosticFixture -ScriptBlock {
    enum ProxyReleaseActionType { Release = 0; Deny = 2; Request = 3 }
    function Release-QuarantineMessage {
        [CmdletBinding(DefaultParameterSetName = "IdentityOnly")]
        param([string] $Identity,
            [ValidateSet("Release", "Deny", "Request")]
            [ProxyReleaseActionType] $ActionType = [ProxyReleaseActionType]::Release)
        # client_secret=PROXY_SYNTHETIC_SECRET_123
        # PADDING
        # Execute-Command forwards $PSBoundParameters including ActionType
        throw "PROXY_MUST_NOT_EXECUTE"
    }
    function Execute-Command {
        param($Parameters)
        # ConvertTo-Json transports ActionType
        throw "TRANSPORT_MUST_NOT_EXECUTE"
    }
    function CheckRetryAndHandleWaitTime {
        throw "RETRY_MUST_NOT_EXECUTE"
    }
    Export-ModuleMember -Function Release-QuarantineMessage
}
Microsoft.PowerShell.Core\Import-Module -ModuleInfo $module -Force
'''


def diagnose(tmp_path, setup=''):
    source = (ROOT / 'tests/powershell/test_runbook_diagnostics_opt_in.ps1').read_text()
    source = source.replace('Join-Path $PSScriptRoot "../../runbook/runbook.ps1"',
                            "'" + str(ROOT / 'runbook/runbook.ps1') + "'")
    source = source.replace('$request = @{', setup + '\n$request = @{')
    script = tmp_path / 'diagnose.ps1'
    script.write_text(source)
    proc = subprocess.run([PWSH, '-NoProfile', '-File', str(script)],
                          capture_output=True, text=True, check=True, timeout=30)
    result = json.loads(next(line for line in reversed(proc.stdout.splitlines()) if line.startswith('{')))
    assert result['status'] == 'inspected', result
    return result


def test_private_helpers_enum_and_source_without_execution(tmp_path):
    result = diagnose(tmp_path, MODULE)
    report = json.loads(result['cmdlet_proxy_diagnostics'])
    assert report['status'] == 'collected', report
    assert report['request_capture'] is False
    assert report['action_type']['is_enum'] is True
    assert {'name': 'Deny', 'value': '2'} in report['action_type']['enum_values']
    assert report['action_type']['validate_set'] == ['Release', 'Deny', 'Request']
    assert len(report['commands']) == 3
    for row in report['commands']:
        assert row['status'] == 'collected'
        assert row['module_name'] == 'ProxyDiagnosticFixture'
        assert len(row['source_sha256']) == 64
    assert all('source' not in row and 'forwarding_excerpts' not in row for row in report['commands'])
    assert SECRET not in result['cmdlet_proxy_diagnostics']
    c = t.make_connector()
    ar = t.patch_ar(c)
    with t.req_mock.Mocker() as m:
        t.mock_full_flow(m, result)
        assert c._handle_inspect_release_environment({'identity': result['identity']}) == t.APP_SUCCESS
    assert ar.get_data()[0]['cmdlet_proxy_diagnostics'] == result['cmdlet_proxy_diagnostics']
    assert ar.get_summary()['cmdlet_proxy_diagnostics_status'] == 'collected'


def test_large_proxy_source_is_hashed_but_not_emitted(tmp_path):
    result = diagnose(tmp_path, MODULE.replace('# PADDING', '# ' + 'x' * 40000))
    command = json.loads(result['cmdlet_proxy_diagnostics'])['commands'][0]
    assert command['source_chars'] > 32768
    assert len(command['source_sha256']) == 64
    assert 'source' not in command
    assert 'forwarding_excerpts' not in command


def test_no_module_is_explicitly_partial_and_validate_set_survives(tmp_path):
    result = diagnose(tmp_path)
    report = json.loads(result['cmdlet_proxy_diagnostics'])
    assert report['status'] == 'partial'
    assert report['action_type']['validate_set'] == ['Release', 'Deny']
    assert report['commands'][1]['status'] == 'unavailable'


def test_missing_cmdlet_is_reported_without_breaking_inspection(tmp_path):
    result = diagnose(tmp_path, 'Remove-Item Function:\\Release-QuarantineMessage')
    report = json.loads(result['cmdlet_proxy_diagnostics'])
    assert report['status'] == 'unavailable'
    assert report['error']


def test_same_named_helper_from_another_scope_is_not_collected(tmp_path):
    setup = MODULE.replace('function Execute-Command {', 'function LocalUnusedHelper {')
    setup = 'function global:Execute-Command { throw "FOREIGN_HELPER" }\n' + setup
    result = diagnose(tmp_path, setup)
    report = json.loads(result['cmdlet_proxy_diagnostics'])
    assert report['status'] == 'partial'
    helper = next(row for row in report['commands'] if row['name'] == 'Execute-Command')
    assert helper['status'] == 'unavailable'
    assert 'FOREIGN_HELPER' not in result['cmdlet_proxy_diagnostics']
