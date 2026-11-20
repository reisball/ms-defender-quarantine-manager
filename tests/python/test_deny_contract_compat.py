"""Paired real PowerShell producer/Python consumer; Exchange is mocked."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from test_connector import IDENTITY, make_utils

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("action,terminal", [("release", "Released"), ("deny", "Denied")])
@pytest.mark.parametrize("observed_sets", [False, True])
def test_paired_runbook_output_and_actual_single_identity_binding(action, terminal, observed_sets):
    if not shutil.which("pwsh"):
        pytest.skip("PowerShell is not installed")
    args = ["pwsh", "-NoProfile", "-File",
            str(ROOT / "tests/powershell/test_runbook_irreversible_action.ps1"),
            "-Action", action, "-StatusSequence", f"Requested,{terminal}", "-ReportCalls"]
    if observed_sets:
        args.append("-ObservedExchangeParameterSets")
    process = subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)
    report = json.loads(next(line for line in reversed(process.stdout.splitlines())
                             if line.startswith("{")))
    data = report["result"]
    # The harness checks real bound Identity/ReleaseToAll/ActionType parameters.
    assert report["writes"] == 1
    assert report["reads"] == 2
    assert data["status"] == terminal.lower()
    assert data["observed_release_status"] == terminal
    assert data["identity"] == IDENTITY
    assert data["observed_identity"] == IDENTITY
    make_utils()._validate_runbook_result(data, action, IDENTITY)
    make_utils()._raise_for_runbook_error(data, action, IDENTITY)
    assert "cmdlet_contract_id" not in data
    assert "operation_id" not in data
