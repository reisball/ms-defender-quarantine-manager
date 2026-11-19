"""Offline business contracts: real runbook with synthetic Exchange cmdlets.

No Azure/SOAR service is contacted. Called by both CI workflows instead of
maintaining a second mandatory diagnostic-proof protocol in inline assertions.
"""
import argparse
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def invoke(script, *arguments):
    proc = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-File", str(HERE / script), *arguments],
        check=True, capture_output=True, text=True, timeout=45,
    )
    rows = [json.loads(line) for line in proc.stdout.splitlines()
            if line.strip().startswith("{")]
    assert len(rows) == 1, proc.stdout
    return rows[0]


def connection():
    count = 0
    for action in ("list", "release", "deny"):
        for source in ("webhook", "variable"):
            body = {"action": action, "identity": "__IDENTITY__"}
            args = ["-AuthMethodVariable", "Credential", "-EnableVerbose"]
            if source == "webhook":
                body.update(auth_method="ManagedIdentity", organization="test.onmicrosoft.com")
            else:
                args += ["-OrganizationVariable", "test.onmicrosoft.com"]
            out = invoke("test_runbook_connection_contract.ps1",
                         "-RequestJson", json.dumps(body), *args)
            assert not out["result"].get("error"), out
            assert not out["leaked_secret_any_stream"], out
            assert not out["credential_reads"], out
            assert "ExchangeAuthMethod" not in out["variable_reads"], out
            assert len(out["connect_calls"]) == 1, out
            call = out["connect_calls"][0]
            assert call["managed_identity"] is True and not call["credential_bound"], out
            assert call["organization"] == "test.onmicrosoft.com", out
            assert out["release_calls"] == (0 if action == "list" else 1), out
            assert out["disconnect_calls"] == 1, out
            count += 1

    for fault, message in (("-ImportFailure", "import"), ("-ConnectFailure", "connect")):
        out = invoke("test_runbook_connection_contract.ps1", "-RequestJson",
                     json.dumps({"action": "deny", "identity": "__IDENTITY__",
                                 "organization": "test.onmicrosoft.com"}),
                     fault, "-EnableVerbose")
        assert out["result"]["error"] is True, out
        assert message in out["result"]["message"].lower(), out
        assert out["release_calls"] == 0, out
        assert not out["leaked_secret_any_stream"], out
        count += 1
    return count


def disposition():
    count = 0
    for action, terminal in (("release", "Released"), ("deny", "Denied")):
        for sequence in (f"Requested,{terminal}", f"Requested,Requested,{terminal}"):
            out = invoke("test_runbook_irreversible_action.ps1", "-Action", action,
                         "-StatusSequence", sequence, "-ReportCalls",
                         "-ObservedExchangeParameterSets")
            result = out["result"]
            assert not result.get("error"), out
            assert result["status"] == ("released" if action == "release" else "denied"), out
            assert result["observed_release_status"] == terminal, out
            assert out["writes"] == 1, out
            assert out["reads"] >= len(sequence.split(",")), out
            assert out["disconnects"] == 1 and not out["leaked_secret"], out
            count += 1
        # Even a hypothetical later terminal state must not reclassify the error.
        out = invoke("test_runbook_irreversible_action.ps1", "-Action", action,
                     "-StatusSequence", f"Requested,{terminal}", "-CmdletFailure",
                     "-ReportCalls")
        assert out["result"]["error"] is True, out
        assert out["writes"] == 1 and out["reads"] == 1, out
        assert out["disconnects"] == 1, out
        count += 1

        out = invoke("test_runbook_irreversible_action.ps1", "-Action", action,
                     "-StatusSequence", "Requested", "-ReportCalls")
        assert out["result"]["error"] is True, out
        assert out["result"]["error_code"] == "postcondition_unconfirmed", out
        assert out["writes"] == 1 and out["reads"] > 1, out
        count += 1

        out = invoke("test_runbook_irreversible_action.ps1", "-Action", action,
                     "-StatusSequence", "NotReleased", "-ForbidCmdlet", "-ReportCalls")
        assert out["result"]["error"] is True and out["writes"] == 0, out
        count += 1

        out = invoke("test_runbook_irreversible_action.ps1", "-Action", action,
                     "-StatusSequence", terminal, "-ForbidCmdlet", "-ReportCalls")
        assert not out["result"].get("error"), out
        assert out["result"]["status"] == ("already_released" if action == "release" else "already_denied"), out
        assert out["writes"] == 0 and out["reads"] == 1, out
        count += 1
    # Active-window status observation must stay read-only.
    out = invoke("test_runbook_irreversible_action.ps1", "-Action", "reconcile",
                 "-StatusSequence", "Denied", "-ForbidCmdlet", "-ReportCalls")
    assert out["writes"] == 0 and out["reads"] == 1, out
    assert out["result"]["observed_release_status"] == "Denied", out
    assert "operation_action" not in out["result"], out
    count += 1
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=("connection", "disposition"))
    args = parser.parse_args()
    completed = globals()[args.group]()
    print(json.dumps({"group": args.group, "cases_passed": completed}))
