"""Offline producer/consumer regression for the single-identity Deny candidate."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

from ms_quarantine_for_splunk_soar_utils import (
    AutomationError, MSQuarantineForSplunkSOARUtils as Utils,
)

ROOT = Path(__file__).resolve().parents[2]
NEW_CONTRACT = "identity_releasetoall_actiontype_deny"
SINGLE_CONTRACT = "identity_actiontype_deny"
PLACEHOLDER_CONTRACT = "identities_actiontype_identity_placeholder"
OLD_CONTRACT = "identities_actiontype_no_dummy"


class DenyContractCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = {}
        for action, terminal in (("deny", "Denied"), ("release", "Released")):
            proc = subprocess.run([
                "pwsh", "-NoProfile", "-File",
                str(ROOT / "tests/powershell/test_runbook_irreversible_action.ps1"),
                "-Action", action, "-StatusSequence", f"Requested,{terminal}",
            ], capture_output=True, text=True, check=True, timeout=30)
            cls.outputs[action] = json.loads(next(
                line for line in reversed(proc.stdout.splitlines()) if line.startswith("{")
            ))

    def validate(self, data, action="deny"):
        Utils._validate_irreversible_diagnostics(data, "test", action)

    def test_new_runbook_deny_output_is_accepted(self):
        data = self.outputs["deny"]
        self.assertEqual(data["status"], "denied")
        self.assertEqual(data["cmdlet_error"], "")
        self.assertEqual(data["cmdlet_contract_id"], NEW_CONTRACT)
        self.validate(data)

    def test_single_identity_deny_without_switch_remains_accepted(self):
        data = copy.deepcopy(self.outputs["deny"])
        data["cmdlet_contract_id"] = SINGLE_CONTRACT
        data["cmdlet_expected_argument_names"] = "Identity,ActionType"
        data["cmdlet_parameter_names"] = "Identity,ActionType,Confirm,ErrorAction"
        data["cmdlet_invocation_form"] = "Release-QuarantineMessage -Identity <identity> -ActionType Deny -Confirm:$false -ErrorAction Stop"
        self.validate(data)

    def test_new_contract_requires_release_to_all_parameter(self):
        data = copy.deepcopy(self.outputs["deny"])
        data["cmdlet_parameter_names"] = "Identity,ActionType,Confirm,ErrorAction"
        with self.assertRaisesRegex(AutomationError, "required effective parameter"):
            self.validate(data)

    def test_observed_exchange_sets_bind_deny_to_release_to_all_set(self):
        proc = subprocess.run([
            "pwsh", "-NoProfile", "-File",
            str(ROOT / "tests/powershell/test_runbook_irreversible_action.ps1"),
            "-Action", "deny", "-StatusSequence", "Requested,Denied",
            "-ObservedExchangeParameterSets",
        ], capture_output=True, text=True, check=True, timeout=30)
        data = json.loads(next(line for line in reversed(proc.stdout.splitlines()) if line.startswith("{")))
        self.assertEqual(data["status"], "denied")
        self.assertTrue(data["cmdlet_executed"])
        self.validate(data)

    def test_legacy_deny_evidence_remains_accepted(self):
        data = copy.deepcopy(self.outputs["deny"])
        data["cmdlet_contract_id"] = OLD_CONTRACT
        data["cmdlet_expected_argument_names"] = "Identities,ActionType"
        data["cmdlet_parameter_names"] = "Identities,ActionType,Confirm,ErrorAction"
        data["cmdlet_invocation_form"] = "Release-QuarantineMessage -Identities <identity> -ActionType Deny -Confirm:$false -ErrorAction Stop"
        self.validate(data)

    def test_placeholder_deny_evidence_remains_accepted(self):
        data = copy.deepcopy(self.outputs["deny"])
        data["cmdlet_contract_id"] = PLACEHOLDER_CONTRACT
        data["cmdlet_expected_argument_names"] = "Identity,Identities,ActionType"
        data["cmdlet_parameter_names"] = "Identity,Identities,ActionType,Confirm,ErrorAction"
        data["cmdlet_invocation_form"] = "Release-QuarantineMessage -Identity 000 -Identities <identity> -ActionType Deny -Confirm:$false -ErrorAction Stop"
        self.validate(data)

    def test_release_output_is_unchanged_and_accepted(self):
        data = self.outputs["release"]
        self.assertEqual(data["status"], "released")
        self.assertEqual(data["cmdlet_contract_id"], "identity_releasetoall")
        self.assertNotIn("000", data["cmdlet_invocation_form"])
        self.validate(data, "release")

    def test_unknown_contract_is_rejected(self):
        data = copy.deepcopy(self.outputs["deny"])
        data["cmdlet_contract_id"] = "unknown"
        with self.assertRaisesRegex(AutomationError, "unexpected cmdlet_contract_id"):
            self.validate(data)

    def test_argument_contracts_cannot_be_mixed(self):
        for contract, arguments in (
            (NEW_CONTRACT, "Identities,ActionType"),
            (NEW_CONTRACT, "Identity,ActionType"),
            (SINGLE_CONTRACT, "Identity,ReleaseToAll,ActionType"),
            (OLD_CONTRACT, "Identity,ActionType"),
            (PLACEHOLDER_CONTRACT, "Identity,ActionType"),
            (NEW_CONTRACT, "Identity,Identities,ActionType"),
        ):
            with self.subTest(contract=contract):
                data = copy.deepcopy(self.outputs["deny"])
                data["cmdlet_contract_id"] = contract
                data["cmdlet_expected_argument_names"] = arguments
                with self.assertRaisesRegex(AutomationError, "unexpected disposition argument"):
                    self.validate(data)

    def test_new_contract_requires_effective_identity_parameter(self):
        data = copy.deepcopy(self.outputs["deny"])
        data["cmdlet_parameter_names"] = "Identities,ActionType,Confirm,ErrorAction"
        with self.assertRaisesRegex(AutomationError, "required effective parameter"):
            self.validate(data)

    def test_deny_contract_cannot_validate_release(self):
        with self.assertRaisesRegex(AutomationError, "unexpected cmdlet_contract_id"):
            self.validate(self.outputs["deny"], "release")
