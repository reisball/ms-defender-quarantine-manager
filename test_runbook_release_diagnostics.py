"""Paired offline PowerShell runbook regressions; never connects to Exchange."""
import base64
import json
from pathlib import Path
import shutil
import subprocess

import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
PWSH = shutil.which("pwsh")

SECRET = "DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE"
MOCK_STREAMS = r"""
    $large = '界"\\' * 262144
    Write-Warning ("https://example.invalid/?token=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE " + $large)
    Write-Information ("Authorization: Bearer DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE " + $large)
    Write-Verbose ("client_secret=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE " + $large)
"""
MOCK_AUTH = r"""
        $exception = [System.UnauthorizedAccessException]::new(
            "HTTP 403 Forbidden: quarantine action is not authorized."
        )
        $exception.Data["RequestId"] = "https://example.invalid/?token=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE"
        # The closing quote lies beyond the 512-character structured bound.
        $exception.Data["CorrelationId"] = ('client_secret="DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE' + ('x' * 600) + '"')
        $exception.Data["Server-Timestamp"] = "password=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE"
        $record = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            "access_token=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE",
            [System.Management.Automation.ErrorCategory]::PermissionDenied,
            "https://example.invalid/?token=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE"
        )
        $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
            "HTTP 403 Forbidden; client_secret=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE"
        )
        $PSCmdlet.ThrowTerminatingError($record)
"""

MOCK_LARGE_FAILURE = r"""
        $large = '界"\\' * 262144
        $inner = [System.Exception]::new(
            'client_secret="DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE' + ('x' * 3000) + '" ' + $large + ' INNER_END'
        )
        $exception = [System.Exception]::new(
            'Authorization: Bearer DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE ' + $large + ' ERROR_END',
            $inner
        )
        $record = [System.Management.Automation.ErrorRecord]::new(
            $exception, "synthetic_failure",
            [System.Management.Automation.ErrorCategory]::NotSpecified, "mock target"
        )
        $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
            'https://example.invalid/?token=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE ' + $large + ' DETAILS_END'
        )
        $PSCmdlet.ThrowTerminatingError($record)
"""


def run_fixture(tmp_path, action, authorization=False, large=True,
                large_failure=False, terminal_override=None, metadata_error=None,
                oversized_passive_metadata=False):
    shutil.copyfile(ROOT / "runbook.ps1", tmp_path / "runbook.ps1")
    harness = (ROOT / "test_runbook_irreversible_action.ps1").read_text()
    if oversized_passive_metadata:
        # Change only the passive Get-Command result after the native call.
        harness = harness.replace(
            "    return Microsoft.PowerShell.Core\\Get-Command `",
            r"""    if ($Name -eq "Release-QuarantineMessage" -and $global:IrreversibleTestCmdletCalls -eq 1) {
        $metadata = Microsoft.PowerShell.Core\Get-Command -Name $Name | Select-Object *
        $metadata | Add-Member -Force -NotePropertyName DefaultParameterSet -NotePropertyValue ([string][char]1 * 180000)
        return $metadata
    }
    return Microsoft.PowerShell.Core\Get-Command `"""
        )
    if metadata_error is not None:
        harness = harness.replace('throw "mock metadata lookup failure"', 'throw (' + metadata_error + ')')
    if large:
        harness = harness.replace('    Write-Warning "mock warning"', MOCK_STREAMS)
    harness = harness.replace(
        '        throw [System.UnauthorizedAccessException]::new(\n'
        '            "HTTP 403 Forbidden: quarantine action is not authorized."\n'
        '        )', MOCK_AUTH
    )
    if large_failure:
        start = harness.index('        $exception = [System.Exception]::new("mock cmdlet failure")')
        end = harness.index('        throw $exception', start) + len('        throw $exception')
        harness = harness[:start] + MOCK_LARGE_FAILURE + harness[end:]
    harness = harness.replace(
        '& $runbookPath -WebhookData $webhookData',
        '& $runbookPath -WebhookData $webhookData -Verbose\n'
        'Write-Output ("DISPOSITION_CALLS=" + $global:IrreversibleTestCmdletCalls)'
    )
    path = tmp_path / "fixture.ps1"
    path.write_text(harness)
    terminal = "Requested" if authorization else ("Released" if action == "release" else "Denied")
    terminal = terminal_override or terminal
    args = [PWSH, "-NoLogo", "-NoProfile", "-File", str(path),
            "-Action", action, "-StatusSequence", "Requested," + terminal]
    if metadata_error is not None:
        args += ["-MetadataFailure"]
    if large_failure:
        args += ["-CmdletFailure"]
    if authorization:
        args += ["-AuthorizationFailure"]
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    output = result.stdout + result.stderr
    assert SECRET not in output, output[:2000]
    assert "must-never-leave-runbook" not in output
    assert result.stdout.splitlines().count("DISPOSITION_CALLS=1") == 1
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert records
    assert max(len(line.encode("utf-8")) for line in output.splitlines()) < 1024 * 1024
    if records[-1].get("mode") == "error_complete":
        chunks = sorted((r for r in records if r.get("mode") == "error_chunk"),
                        key=lambda r: r["chunk_index"])
        payload = json.loads(base64.b64decode("".join(r["payload_chunk"] for r in chunks)))
        assert SECRET not in json.dumps(payload)
        return payload
    assert len(records) == 1
    return records[0]


@unittest.skipUnless(PWSH, "PowerShell is not installed")
class ReleaseDiagnosticTests(unittest.TestCase):
    def test_success_optional_streams_are_bounded_with_evidence(self):
        for action in ("release", "deny"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                data = run_fixture(Path(directory), action)
                self.assertEqual(data["status"], "released" if action == "release" else "denied")
                for stream in ("warning", "information", "verbose"):
                    key = "cmdlet_" + stream
                    self.assertLessEqual(len(data[key]), 2048)
                    self.assertIs(data[key + "_truncated"], True)
                    self.assertGreater(data[key + "_original_chars"], 1024 * 1024)
                    self.assertIn("[truncated]", data[key])
                    self.assertIn("[redacted]", data[key])

    def test_success_after_large_error_is_bounded_and_redacted(self):
        for action in ("release", "deny"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                data = run_fixture(Path(directory), action, large_failure=True)
                self.assertEqual(data["status"], "released" if action == "release" else "denied")
                self.assertEqual(data["observed_release_status"], "Released" if action == "release" else "Denied")
                self.assertIs(data["cmdlet_invocation_attempted"], True)
                for key in ("cmdlet_error", "cmdlet_error_details", "cmdlet_inner_exception"):
                    self.assertLessEqual(len(data[key]), 2048, key)
                    self.assertIs(data[key + "_truncated"], True, key)
                    self.assertGreater(data[key + "_original_chars"], 1024 * 1024, key)
                    self.assertIn("[truncated]", data[key], key)
                    self.assertIn("[redacted]", data[key], key)

    def test_unconfirmed_large_error_preserves_chunked_error_contract(self):
        for action in ("release", "deny"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                data = run_fixture(Path(directory), action, large_failure=True,
                                   terminal_override="Requested")
                self.assertIs(data["error"], True)
                self.assertEqual(data["error_code"], "postcondition_unconfirmed")
                details = data["details"]
                for key, suffix in (("cmdlet_error", "DETAILS_END"),
                                    ("cmdlet_error_details", "DETAILS_END"),
                                    ("cmdlet_inner_exception", "INNER_END")):
                    self.assertGreater(len(details[key]), 1024 * 1024, key)
                    self.assertTrue(details[key].endswith(suffix), key)
                    self.assertNotIn(key + "_truncated", details)
                    self.assertIn("[redacted]", details[key], key)

    def test_passive_metadata_failures_preserve_bounded_success(self):
        for action in ("release", "deny"):
            for payload in ("'x' * 1048576", "'界' * 524288", "('a' + [char]1 + '\"') * 524288"):
                with self.subTest(action=action, payload=payload), tempfile.TemporaryDirectory() as directory:
                    data = run_fixture(Path(directory), action, large=False,
                                       metadata_error="'client_secret=DIAGNOSTIC_SECRET_MUST_NOT_SURVIVE ' + (" + payload + ")")
                    self.assertEqual(data["status"], "released" if action == "release" else "denied")
                    self.assertEqual(data["observed_release_status"], "Released" if action == "release" else "Denied")
                    for key in ("cmdlet_metadata_error", "exchange_connection_metadata_error"):
                        self.assertLessEqual(len(data[key]), 2048)
                        self.assertLessEqual(len(json.dumps(data[key], ensure_ascii=False).encode()), 16 * 1024)
                        self.assertTrue(data[key + "_truncated"])
                        self.assertGreater(data[key + "_original_chars"], 524288 - 100)
                        self.assertIn("[truncated]", data[key])
                        self.assertIn("[redacted]", data[key])

    def test_short_optional_streams_remain_readable(self):
        for action in ("release", "deny"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                data = run_fixture(Path(directory), action, large=False)
                for stream in ("warning", "information", "verbose"):
                    key = "cmdlet_" + stream
                    self.assertEqual(data[key], "mock " + stream)
                    self.assertIs(data[key + "_truncated"], False)
                    self.assertEqual(data[key + "_original_chars"], len(data[key]))

    def test_authorization_structured_evidence_is_redacted_in_all_streams(self):
        for action in ("release", "deny"):
            for large in (False, True):
                with self.subTest(action=action, large=large), tempfile.TemporaryDirectory() as directory:
                    data = run_fixture(Path(directory), action, authorization=True, large=large)
                    self.assertIs(data["error"], True)
                    self.assertEqual(data["error_code"], "disposition_rejected")
                    data = data["details"]
                    for key in ("cmdlet_error_target_name", "cmdlet_fully_qualified_error_id",
                                "cmdlet_request_id", "cmdlet_correlation_id", "cmdlet_server_timestamp",
                                "cmdlet_error_details"):
                        self.assertIn("[redacted]", data[key], key)


if __name__ == "__main__":
    unittest.main()
