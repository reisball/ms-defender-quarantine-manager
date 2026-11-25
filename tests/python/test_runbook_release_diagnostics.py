"""Paired real PowerShell errors, delayed reads and native result transport."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest
from test_connector import IDENTITY, RunbookActionError, make_utils

ROOT = Path(__file__).resolve().parents[2]
PWSH = shutil.which("pwsh")


def run_fixture(action, statuses, *switches):
    if not PWSH:
        pytest.skip("PowerShell is not installed")
    # The shared fixture sets MaxAttempts=3 for fast unit checks. Remove that
    # override in a temporary copy so these regressions exercise the real
    # seven-check default; its zero-second test sleep stays in effect.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "runbook").mkdir()
        (root / "tests/powershell").mkdir(parents=True)
        shutil.copyfile(ROOT / "runbook/runbook.ps1", root / "runbook/runbook.ps1")
        source = (ROOT / "tests/powershell/test_runbook_irreversible_action.ps1").read_text()
        needle = 'if ($Name -eq "QuarantinePostconditionMaxAttempts") {\n        return 3'
        assert needle in source
        source = source.replace(needle, 'if ($Name -eq "QuarantinePostconditionMaxAttempts") {\n        throw "not configured"')
        fixture = root / "tests/powershell/fixture.ps1"
        fixture.write_text(source)
        proc = subprocess.run([
            PWSH, "-NoLogo", "-NoProfile", "-File", str(fixture),
            "-Action", action, "-StatusSequence", statuses, "-ReportCalls", *switches,
        ], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "must-never-leave-runbook" not in proc.stdout + proc.stderr
    return json.loads(next(line for line in reversed(proc.stdout.splitlines()) if line.startswith("{")))


@pytest.mark.parametrize("action,terminal", [("release", "Released"), ("deny", "Denied")])
@pytest.mark.parametrize("delay", [1, 4, 7])
def test_delayed_exchange_status_is_verified_after_one_write(action, terminal, delay):
    report = run_fixture(action, ",".join(["Requested"] * delay + [terminal]))
    assert report["writes"] == 1
    assert report["reads"] == delay + 1
    assert report["disconnects"] == 1
    data = report["result"]
    assert data["status"] == terminal.lower()
    make_utils()._validate_runbook_result(data, action, IDENTITY)


@pytest.mark.parametrize("action", ["release", "deny"])
@pytest.mark.parametrize("failure", ["-CmdletFailure", "-AuthorizationFailure", "-TransportFailure",
                                      "-NonTerminatingError", "-MisleadingServerFailure",
                                      "-MisleadingThrottleFailure", "-StructuredForbiddenFailure"])
def test_native_errors_are_not_reclassified_by_later_terminal_status(action, failure):
    terminal = "Released" if action == "release" else "Denied"
    report = run_fixture(action, "Requested," + terminal, failure)
    assert report["writes"] == 1
    assert report["reads"] == 1  # no error-to-success reconstruction
    assert report["disconnects"] == 1
    data = report["result"]
    assert data["error"] is True
    assert data["message"]
    assert data["error_code"]
    assert data["error_context"] == "Release-QuarantineMessage"
    with pytest.raises(RunbookActionError) as exc:
        make_utils()._raise_for_runbook_error(data, action, IDENTITY)
    assert str(exc.value) == data["message"]
    assert exc.value.result is data


@pytest.mark.parametrize("action", ["release", "deny"])
def test_unconfirmed_status_is_bounded_and_never_rewrites(action):
    report = run_fixture(action, "Requested")
    assert report["writes"] == 1
    assert report["reads"] == 8  # initial read plus seven post-command checks
    assert report["result"]["error"] is True
    assert report["result"]["error_code"] == "postcondition_unconfirmed"
    with pytest.raises(RunbookActionError):
        make_utils()._raise_for_runbook_error(report["result"], action, IDENTITY)


@pytest.mark.parametrize("action,terminal", [("release", "Released"), ("deny", "Denied")])
@pytest.mark.parametrize("switch", ["-MetadataFailure", "-AliasCommand", "-StreamSecrets"])
def test_optional_diagnostics_do_not_gate_success(action, terminal, switch):
    report = run_fixture(action, "Requested," + terminal, switch)
    assert report["writes"] == 1
    assert report["result"]["status"] == terminal.lower()
    make_utils()._validate_runbook_result(report["result"], action, IDENTITY)


@pytest.mark.parametrize("action,statuses,expected_writes", [
    ("release", "Requested,PreparingToRelease", 1),
    ("release", "PreparingToRelease", 0),
    ("deny", "PreparingToRelease", 0),
    ("deny", "Requested,PreparingToRelease", 1),
])
def test_preparing_to_release_is_reported_as_pending_without_rewrite(
    action, statuses, expected_writes,
):
    report = run_fixture(action, statuses)
    assert report["writes"] == expected_writes
    assert report["reads"] == (8 if expected_writes else 1)
    data = report["result"]
    assert data["error"] is True
    assert data["error_code"] == "release_pending"
    assert data["observed_release_status"] == "PreparingToRelease"
    with pytest.raises(RunbookActionError):
        make_utils()._raise_for_runbook_error(data, action, IDENTITY)
