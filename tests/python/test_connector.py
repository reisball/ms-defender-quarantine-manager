# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
#
# Tests – MS Quarantine for Splunk SOAR (Azure Automation)
# =================================================
# All HTTP calls mocked via requests-mock.
# No Azure, no SOAR runtime, no Exchange Online needed.

import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import types

import pytest
import requests
import requests_mock as req_mock


# ---------------------------------------------------------------------------
# SOAR SDK stubs
# ---------------------------------------------------------------------------

class _ActionResult:
    def __init__(self, param=None):
        self._data    = []
        self._summary = {}
        self._status  = None
        self._message = ""
        self.param    = param or {}

    def add_data(self, d):       self._data.append(d); return self
    def update_summary(self, s): self._summary.update(s)
    def set_status(self, s, m=""): self._status, self._message = s, m; return s
    def get_status(self):  return self._status
    def get_message(self): return self._message
    def get_data(self):    return self._data
    def get_summary(self): return self._summary


class _AppSuccess:
    def __bool__(self): return True
    def __eq__(self, o): return isinstance(o, _AppSuccess)

class _AppError:
    def __bool__(self): return False
    def __eq__(self, o): return isinstance(o, _AppError)


phantom_stub             = types.ModuleType("phantom")
phantom_stub.APP_SUCCESS = _AppSuccess()
phantom_stub.APP_ERROR   = _AppError()
phantom_stub.is_fail     = lambda status: not bool(status)
sys.modules["phantom"]   = phantom_stub
sys.modules["phantom.app"] = phantom_stub

ar_mod = types.ModuleType("phantom.action_result")
ar_mod.ActionResult = _ActionResult
sys.modules["phantom.action_result"] = ar_mod


class _BaseConnector:
    def __init__(self):
        self._config         = {}
        self._action_results = []
        self._action_id      = ""
        self._container_id   = 1
        self._asset_id       = 8
        self._is_poll_now    = False
        self._saved_containers = []
        self._save_container_error = ""
        self._next_container_id = 100
        self._state_file_path = str(
            Path(tempfile.mkdtemp(prefix="ms_quarantine_for_splunk_soar-state-")) / "1_state.json"
        )

    def get_config(self):            return self._config
    def get_action_identifier(self): return self._action_id
    def get_container_id(self):      return self._container_id
    def get_asset_id(self):          return self._asset_id
    def is_poll_now(self):           return self._is_poll_now
    def get_state_file_path(self):   return self._state_file_path
    def get_app_json(self):          return {"app_version": json.loads((Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text())["app_version"]}
    def save_progress(self, msg):    pass
    def set_status(self, s, m=""):   return s
    def add_action_result(self, ar): self._action_results.append(ar); return ar
    def get_action_results(self):    return json.dumps([])
    def finalize(self):              return phantom_stub.APP_SUCCESS
    def save_container(self, container):
        if self._save_container_error:
            return (
                phantom_stub.APP_ERROR,
                self._save_container_error,
                None,
            )
        source_id = container.get("source_data_identifier")
        for item in self._saved_containers:
            if item["container"].get("source_data_identifier") == source_id:
                return (
                    phantom_stub.APP_SUCCESS,
                    "Duplicate container found",
                    item["id"],
                )
        container_id = self._next_container_id
        self._next_container_id += 1
        self._saved_containers.append({
            "id": container_id,
            "container": json.loads(json.dumps(container)),
        })
        return phantom_stub.APP_SUCCESS, "Container saved", container_id
    def load_state(self):
        path = Path(self._state_file_path)
        if not path.exists():
            return {}
        return json.loads(path.read_text())
    def save_state(self, state):
        path = Path(self._state_file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state))
        temporary.replace(path)
        return phantom_stub.APP_SUCCESS


bc_mod = types.ModuleType("phantom.base_connector")
bc_mod.BaseConnector = _BaseConnector
sys.modules["phantom.base_connector"] = bc_mod

# Vault mock
VAULT_ADDS = []
ARTIFACT_ADDS = []

class _VaultStub:
    @staticmethod
    def get_vault_tmp_dir():
        import tempfile
        return tempfile.gettempdir()

def _vault_add_mock(container, file_location, file_name, metadata=None):
    with open(file_location, "rb") as f:
        content = f.read()
    vault_id = hashlib.sha1(content).hexdigest()
    VAULT_ADDS.append({
        "container": container, "file_name": file_name,
        "content": content, "vault_id": vault_id, "metadata": metadata,
    })
    return True, "Success", vault_id

def _artifact_add_mock(**kwargs):
    artifact_id = len(ARTIFACT_ADDS) + 1000
    ARTIFACT_ADDS.append({**kwargs, "artifact_id": artifact_id})
    return True, "Success", artifact_id

phrules_stub        = types.ModuleType("phantom.rules")
phrules_stub.vault_add = _vault_add_mock
phrules_stub.add_artifact = _artifact_add_mock
phrules_stub.Vault  = _VaultStub
sys.modules["phantom.rules"] = phrules_stub

# Import under test
import ms_quarantine_for_splunk_soar_utils as automation_utils  # noqa: E402
from ms_quarantine_for_splunk_soar_utils import (  # noqa: E402
    MSQuarantineForSplunkSOARUtils, AutomationError,
    TokenError, WebhookError, JobTimeoutError, JobFailedError,
    RunbookActionError, OversizedExportError,
    AAD_TOKEN_URL, MGMT_BASE, MGMT_API_VERSION,
    AZURE_STREAM_LIMIT_MESSAGE, MAX_DECODED_EML_BYTES,
    LIST_CHUNK_MODE, LIST_COMPLETE_MODE, MAX_LIST_RESULT_COUNT,
    ERROR_CHUNK_MODE, ERROR_COMPLETE_MODE,
    MAX_DIAGNOSTIC_TRACE_RECORDS, MAX_RBAC_ROLE_GROUP_INSPECTIONS,
)
from ms_quarantine_for_splunk_soar_connector import (  # noqa: E402
    MSQuarantineForSplunkSOARConnector, EXPORT_VAULT, EXPORT_INLINE,
    ARTIFACT_LAYOUT_COMBINED, ARTIFACT_LAYOUT_SEPARATE,
    ARTIFACT_FIELD_ORDER, ARTIFACT_FIELD_CONFIG_KEYS,
    DEFAULT_ARTIFACT_FIELDS,
    MAX_OPERATION_RECORDS, OPERATION_STATE_KEY,
    ON_POLL_CANDIDATE_PAGE_SIZE,
    LIST_DEFAULT_PAGE_SIZE,
    ON_POLL_MAX_CONTAINERS,
    WORKER_STATE_KEY,
    _run_cli,
    normalize_recipient_address, parse_artifact_asset_config,
    parse_artifact_fields,
)

APP_SUCCESS = phantom_stub.APP_SUCCESS
APP_ERROR   = phantom_stub.APP_ERROR


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

TENANT_ID   = "11111111-1111-1111-1111-111111111111"
CLIENT_ID   = "22222222-2222-2222-2222-222222222222"
CLIENT_SECRET = "test-secret"
SUB_ID      = "33333333-3333-3333-3333-333333333333"
RG          = "rg-automation"
AA          = "contoso-automation"
WEBHOOK_URL = "https://s1events.azure-automation.net/webhooks?token=abc123"
JOB_ID      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

IDENTITY     = r"c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
EML_RAW      = b"From: attacker@evil.com\r\nSubject: Test\r\n\r\nBody"
EML_B64      = base64.b64encode(EML_RAW).decode()
ARTIFACT_EML_RAW = (
    b"Received: from edge.example.net (192.0.2.10) by "
    b"mail.protection.outlook.com; Tue, 28 Jul 2026 14:35:10 +0200\r\n"
    b"Received: from sender.example.net by edge.example.net; "
    b"Tue, 28 Jul 2026 14:34:58 +0200\r\n"
    b"Date: Tue, 28 Jul 2026 14:34:56 +0200\r\n"
    b"From: Alice Example <alice@example.com>\r\n"
    b"Sender: sender@example.com\r\n"
    b"To: Bob Example <bob@example.com>, Carol <carol@example.com>\r\n"
    b"Cc: Security <security@example.com>\r\n"
    b"Reply-To: replies@example.com\r\n"
    b"X-Original-To: envelope@example.com\r\n"
    b"Message-ID: <message-123@example.com>\r\n"
    b"Subject: =?utf-8?q?Pr=C3=BCfung?=\r\n"
    b"\r\n"
    b"Body"
)
ARTIFACT_EML_B64 = base64.b64encode(ARTIFACT_EML_RAW).decode()
MOCK_TOKEN   = "eyJmYWtldG9rZW4iOiJ0cnVlIn0="
RUNBOOK_VERSION = "3.4.2"
RUNBOOK_SOURCE_REVISION = (
    "sha256:5b3b3fc64451329d96e088d1113418ef"
    "f09f84f6e7abc6b10bf71871cc61759e"
)
RUNBOOK_BUILD_ID = (
    "ms-quarantine-for-splunk-soar-runbook-3.4.2+sha256."
    "5b3b3fc64451329d96e088d1113418ef"
    "f09f84f6e7abc6b10bf71871cc61759e"
)
RELEASE_CONTRACT = "identity_releasetoall"
DENY_CONTRACT = "identities_actiontype_no_dummy"

PRECONDITION_TRACE = json.dumps(
    [{
        "attempt": 1,
        "timestamp_utc": "2026-07-30T08:00:00.0000000Z",
        "result_count": 1,
        "observed_identity": IDENTITY,
        "observed_release_status": "Requested",
        "exact_identity_match": True,
        "error": "",
    }],
    separators=(",", ":"),
)
POSTCONDITION_TRACE = json.dumps(
    [{
        "attempt": 1,
        "timestamp_utc": "2026-07-30T08:00:01.0000000Z",
        "result_count": 1,
        "observed_identity": IDENTITY,
        "observed_release_status": "Released",
        "exact_identity_match": True,
        "error": "",
    }],
    separators=(",", ":"),
)
REJECTED_POSTCONDITION_TRACE = json.dumps(
    [
        {
            "attempt": attempt,
            "timestamp_utc": f"2026-07-30T08:00:0{attempt}.0000000Z",
            "result_count": 1,
            "observed_identity": IDENTITY,
            "observed_release_status": "Requested",
            "exact_identity_match": True,
            "error": "",
        }
        for attempt in range(1, 4)
    ],
    separators=(",", ":"),
)


ORG = "contoso.onmicrosoft.com"


def connection_evidence(
    method="ManagedIdentity",
    organization=ORG,
    method_source="webhook",
    organization_source="webhook",
):
    """Runbook 3.4.2 reports Managed Identity only, never credential fields."""
    return {
        "exchange_auth_method": method,
        "exchange_auth_method_source": method_source,
        "exchange_organization": organization,
        "exchange_organization_source": organization_source,
        "exchange_connection_metadata": "",
        "exchange_connection_metadata_error": "",
    }


def build_metadata():
    return {
        "runbook_version": RUNBOOK_VERSION,
        "runbook_source_revision": RUNBOOK_SOURCE_REVISION,
        "runbook_build_id": RUNBOOK_BUILD_ID,
    }


def static_diagnostics(action="release"):
    is_release = action == "release"
    return {
        "runbook_version": RUNBOOK_VERSION,
        "runbook_source_revision": RUNBOOK_SOURCE_REVISION,
        "runbook_build_id": RUNBOOK_BUILD_ID,
        "powershell_version": "7.4.6",
        "powershell_edition": "Core",
        "powershell_platform": "Unix",
        "powershell_os": "Ubuntu 22.04",
        **connection_evidence(),
        "exchange_online_management_version": "3.5.0",
        "exchange_online_management_path": (
            "/modules/ExchangeOnlineManagement.psd1"
        ),
        "cmdlet_name": "Release-QuarantineMessage",
        "cmdlet_command_type": "Function",
        "cmdlet_module_name": "ExchangeOnlineManagement",
        "cmdlet_module_version": "3.5.0",
        "cmdlet_default_parameter_set": "Identitities",
        "cmdlet_parameter_sets": (
            "Identity[Identity=required,ReleaseToAll=optional] | "
            "Identities[Identity=optional,Identities=required,"
            "ActionType=optional]"
        ),
        "cmdlet_metadata_error": "",
        "cmdlet_contract_id": (
            RELEASE_CONTRACT if is_release else DENY_CONTRACT
        ),
        "cmdlet_expected_argument_names": (
            "Identity,ReleaseToAll"
            if is_release
            else "Identities,ActionType"
        ),
        "cmdlet_parameter_names": (
            (
                "Identity,ReleaseToAll,ErrorVariable,WarningAction,"
                "InformationAction,Verbose,ErrorAction"
            )
            if is_release
            else (
                "Identities,ActionType,ErrorVariable,WarningAction,"
                "InformationAction,Verbose,ErrorAction"
            )
        ),
    }


def disposition_diagnostics(
    *,
    action="release",
    executed=True,
    cmdlet_error="",
):
    result = {
        **static_diagnostics(action),
        "cmdlet_executed": executed,
        "exchange_disconnect_status": "completed",
        "exchange_disconnect_error": "",
        "cmdlet_invocation_attempted": executed,
        "cmdlet_invocation_form": (
            "Release-QuarantineMessage -Identity <identity> -ReleaseToAll "
            "-Confirm:$false -ErrorAction Stop"
        ),
        "cmdlet_error_position": "",
        "cmdlet_script_stack_trace": "",
        "cmdlet_duration_ms": 125 if executed else 0,
        "cmdlet_started_at_utc": (
            "2026-07-30T08:00:00.0000000Z" if executed else ""
        ),
        "cmdlet_completed_at_utc": (
            "2026-07-30T08:00:00.1250000Z" if executed else ""
        ),
        "cmdlet_warning": "",
        "cmdlet_information": "",
        "cmdlet_verbose": "",
        "cmdlet_error": cmdlet_error,
        "cmdlet_fully_qualified_error_id": (
            "Mock.ExchangeError" if cmdlet_error else ""
        ),
        "cmdlet_error_category": (
            "NotSpecified" if cmdlet_error else ""
        ),
        "cmdlet_error_reason": (
            "Exception" if cmdlet_error else ""
        ),
        "cmdlet_error_target_name": "",
        "cmdlet_error_target_type": "",
        "cmdlet_exception_type": (
            "System.Exception" if cmdlet_error else ""
        ),
        "cmdlet_exception_hresult": (
            "0x80131500" if cmdlet_error else ""
        ),
        "cmdlet_http_status_code": "",
        "cmdlet_error_details": cmdlet_error,
        "cmdlet_inner_exception": "",
        "cmdlet_request_id": (
            "11111111-aaaa-bbbb-cccc-222222222222"
            if cmdlet_error else ""
        ),
        "cmdlet_correlation_id": (
            "33333333-aaaa-bbbb-cccc-444444444444"
            if cmdlet_error else ""
        ),
        "cmdlet_server_timestamp": (
            "2026-07-30T08:00:00Z" if cmdlet_error else ""
        ),
    }
    return result


def diagnostic_success_output():
    return {
        "action": "diagnose",
        "identity": IDENTITY,
        "include_rbac": True,
        "status": "inspected",
        "inspected_at_utc": "2026-07-30T08:00:00.0000000Z",
        "result_count": 1,
        "observed_identity": IDENTITY,
        "observed_release_status": "Requested",
        "inspection_error": "",
        "handling": "read_only",
        **build_metadata(),
        **static_diagnostics(),
        **rbac_diagnostics(),
    }


def diagnostic_identity_only_output():
    result = diagnostic_success_output()
    result.update({
        "include_rbac": False,
        "rbac_included": False,
        "rbac_diagnostics_status": "not_requested",
        "rbac_diagnostics_reason": "tenant_rbac_opt_in_required",
        "rbac_empty_contracts": [],
        "read_roles": "",
        "export_roles": "",
        "release_to_all_roles": "",
        "release_deny_roles": "",
        "quarantine_role_present": None,
        "quarantine_role_groups": "",
        "matched_quarantine_role_groups": "",
        "quarantine_role_group_total_count": 0,
        "quarantine_role_group_inspected_count": 0,
        "quarantine_role_group_inspection_truncated": False,
        "service_principal_registered": None,
        "registered_service_principal_identity": "",
        "registered_service_principal_app_id": "",
        "registered_service_principal_object_id": "",
        "role_group_membership_evaluated": None,
        "quarantine_group_membership_confirmed": None,
        "quarantine_administrator_membership_confirmed": None,
        "role_assignment_matches_identity": None,
        "permission_query_error_count": 0,
        "permission_query_error_retained_count": 0,
        "permission_query_error_dropped_count": 0,
        "permission_query_errors_truncated": False,
        "permission_query_errors": [],
    })
    result.pop("managed_identity_claims_status", None)
    result.pop("managed_identity_app_id", None)
    result.pop("managed_identity_object_id", None)
    return result


def rbac_diagnostics(
    status="complete",
    error_records=None,
    membership_confirmed=True,
):
    if error_records is None:
        error_records = []
    return {
        "permission_queries_read_only": True,
        "rbac_included": True,
        "rbac_diagnostics_status": status,
        "rbac_diagnostics_reason": (
            "" if status == "complete"
            else "one_or_more_permission_queries_failed"
        ),
        "rbac_empty_contracts": [],
        "rbac_required_cmdlets": [
            "Get-ManagementRole",
            "Get-ManagementRoleEntry",
            "Get-ServicePrincipal",
            "Get-ManagementRoleAssignment",
            "Get-RoleGroupMember",
        ],
        "rbac_available_cmdlets": [
            "Get-ManagementRole",
            "Get-ManagementRoleEntry",
            "Get-ServicePrincipal",
            "Get-ManagementRoleAssignment",
            "Get-RoleGroupMember",
        ],
        "missing_cmdlets": [],
        "missing_cmdlet_count": 0,
        "read_roles": "Quarantine",
        "export_roles": "Quarantine",
        "release_to_all_roles": "Quarantine",
        "release_deny_roles": "Quarantine",
        "quarantine_role_present": True,
        "quarantine_role_groups": (
            "Quarantine Administrator" if membership_confirmed else ""
        ),
        "matched_quarantine_role_groups": (
            "Quarantine Administrator" if membership_confirmed else ""
        ),
        "quarantine_role_group_total_count": 1,
        "quarantine_role_group_inspected_count": 1,
        "quarantine_role_group_inspection_truncated": False,
        "managed_identity_claims_status": "resolved",
        "managed_identity_app_id": (
            "11111111-2222-3333-4444-555555555555"
        ),
        "managed_identity_object_id": (
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        ),
        "service_principal_registered": True,
        "registered_service_principal_identity": "service-principal-ms_quarantine_for_splunk_soar",
        "registered_service_principal_app_id": (
            "11111111-2222-3333-4444-555555555555"
        ),
        "registered_service_principal_object_id": (
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        ),
        "role_group_membership_evaluated": True,
        "quarantine_group_membership_confirmed": membership_confirmed,
        "quarantine_administrator_membership_confirmed": (
            membership_confirmed
        ),
        "role_assignment_matches_identity": membership_confirmed,
        "permission_query_error_count": len(error_records),
        "permission_query_error_retained_count": len(error_records),
        "permission_query_error_dropped_count": 0,
        "permission_query_errors_truncated": False,
        "permission_query_errors": error_records,
    }


def static_diagnostics_with_metadata_error():
    diagnostics = static_diagnostics()
    diagnostics.update({
        "cmdlet_command_type": "",
        "cmdlet_module_name": "",
        "cmdlet_module_version": "",
        "cmdlet_default_parameter_set": "",
        "cmdlet_parameter_sets": "",
        "cmdlet_metadata_error": (
            "Release-QuarantineMessage was not available after connection."
        ),
    })
    return diagnostics

TOKEN_URL    = AAD_TOKEN_URL.format(tenant_id=TENANT_ID)

def job_url(job_id=JOB_ID):
    return (
        f"{MGMT_BASE}/subscriptions/{SUB_ID}/resourceGroups/{RG}"
        f"/providers/Microsoft.Automation/automationAccounts/{AA}"
        f"/jobs/{job_id}?api-version={MGMT_API_VERSION}"
    )

def job_output_url(job_id=JOB_ID):
    return job_url(job_id).replace(
        f"?api-version={MGMT_API_VERSION}",
        f"/output?api-version={MGMT_API_VERSION}"
    )

MOCK_MESSAGES = [{
    "Identity": IDENTITY, "SenderAddress": "a@evil.com",
    "RecipientAddress": "u@contoso.com", "Subject": "Invoice",
    "Type": "HighConfPhish", "ReceivedTime": "2024-01-15T10:23:00.0000000Z",
    "Expires": "2024-01-30T10:23:00.0000000Z",
    "ReleaseStatus": "REQUESTED", "PolicyName": "Default",
}]


def make_utils(**kwargs):
    defaults = dict(
        webhook_url=WEBHOOK_URL, tenant_id=TENANT_ID,
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
        subscription_id=SUB_ID, resource_group=RG,
        automation_account=AA, poll_interval=0, poll_timeout=30,
    )
    defaults.update(kwargs)
    return MSQuarantineForSplunkSOARUtils(**defaults)


def base_asset_config(export_mode=EXPORT_VAULT):
    return {
        "webhook_url":              WEBHOOK_URL,
        "azure_tenant_id":          TENANT_ID,
        "azure_client_id":          CLIENT_ID,
        "azure_client_secret":      CLIENT_SECRET,
        "azure_subscription_id":    SUB_ID,
        "azure_resource_group":     RG,
        "azure_automation_account": AA,
        "poll_interval_seconds":    5,
        "poll_timeout_seconds":     600,
        "export_mode":              export_mode,
    }


def make_connector(export_mode=EXPORT_VAULT, poll_interval=0,
                   poll_timeout=30, state_path=None,
                   config_overrides=None):
    c = MSQuarantineForSplunkSOARConnector()
    if state_path is not None:
        c._state_file_path = str(state_path)
    c._config = base_asset_config(export_mode=export_mode)
    c._config["poll_interval_seconds"] = max(poll_interval, 1)
    c._config["poll_timeout_seconds"] = max(poll_timeout, 600)
    c._config.update(config_overrides or {})
    assert c.initialize() == APP_SUCCESS
    # Unit tests use zero-second polling to avoid sleeping. Configuration
    # validation remains production-realistic; only the constructed test
    # utility is shortened after successful initialization.
    c._utils._poll_interval = poll_interval
    c._utils._poll_timeout = poll_timeout
    return c


def artifact_asset_config(
    enabled=True,
    layout=ARTIFACT_LAYOUT_COMBINED,
    fields=None,
):
    config = {
        "create_email_artifacts": enabled,
        "artifact_layout": layout,
    }
    if fields is not None:
        selected = set(fields)
        config.update({
            config_key: field in selected
            for field, config_key in ARTIFACT_FIELD_CONFIG_KEYS.items()
        })
    return config


def patch_ar(connector):
    ar = _ActionResult()
    connector.add_action_result = lambda x: ar
    return ar


def manifest_action_paths(identifier):
    manifest = json.loads(
        (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
    )
    action = next(
        item for item in manifest["actions"]
        if item["identifier"] == identifier
    )
    return {item["data_path"] for item in action["output"]}


def action_result_paths(action_result):
    paths = set()
    for row in action_result.get_data():
        for key, value in row.items():
            base = f"action_result.data.*.{key}"
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        paths.update(f"{base}.*.{field}" for field in item)
                    else:
                        paths.add(f"{base}.*")
            else:
                paths.add(base)
    for key, value in action_result.get_summary().items():
        base = f"action_result.summary.{key}"
        if isinstance(value, list):
            if value:
                paths.add(f"{base}.*")
        else:
            paths.add(base)
    return paths


class TestTlsPolicy:

    def test_all_http_paths_force_tls_verification(self, monkeypatch):
        """Token, webhook, status, and output calls must always verify TLS."""
        utils = make_utils()
        verify_values = []

        def response(payload):
            return types.SimpleNamespace(
                ok=True,
                status_code=200,
                headers={},
                text=json.dumps(payload),
                json=lambda: payload,
            )

        def post(url, **kwargs):
            verify_values.append(kwargs["verify"])
            if url == TOKEN_URL:
                return response({"access_token": MOCK_TOKEN})
            return response({"JobIds": [JOB_ID]})

        def get(url, **kwargs):
            verify_values.append(kwargs["verify"])
            if url == job_url():
                return response({"properties": {"status": "Completed"}})
            return response({"action": "list", "count": 0, "messages": []})

        monkeypatch.setattr(utils._session, "post", post)
        monkeypatch.setattr(utils._session, "get", get)

        utils.get_mgmt_token()
        utils.fire_webhook("list")
        utils.poll_job(JOB_ID)
        utils.get_job_output(JOB_ID)

        assert verify_values == [True, True, True, True]


def mock_full_flow(
    m,
    output_json: dict,
    job_id=JOB_ID,
    status="Completed",
    include_version=True,
    include_postcondition=True,
):
    """Register all three mock endpoints for a complete action flow."""
    output_json = dict(output_json)
    if include_version:
        for field, value in build_metadata().items():
            output_json.setdefault(field, value)
    if (
        include_postcondition
        and output_json.get("action") in {"release", "deny"}
        and output_json.get("error") is not True
    ):
        expected_release_status = (
            "Released"
            if output_json["action"] == "release"
            else "Denied"
        )
        output_json.setdefault(
            "verification_method", "Get-QuarantineMessage"
        )
        output_json.setdefault(
            "expected_release_status", expected_release_status
        )
        output_json.setdefault(
            "observed_release_status", expected_release_status
        )
        output_json.setdefault("observed_identity", IDENTITY)
        output_json.setdefault(
            "observed_release_status_history",
            expected_release_status,
        )
        output_json.setdefault("verification_attempts", 1)
        output_json.setdefault("last_verification_error", "")
        output_json.setdefault("precondition_trace", PRECONDITION_TRACE)
        output_json.setdefault("postcondition_trace", POSTCONDITION_TRACE)
        for field, value in disposition_diagnostics(
            action=output_json["action"],
        ).items():
            output_json.setdefault(field, value)
    # Token
    m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN, "expires_in": 3600})
    irreversible = output_json.get("action") in {"release", "deny"}
    state = {"action": output_json.get("action"), "body": {}}

    def webhook(request, context):
        state["body"] = request.json()
        state["action"] = state["body"].get("action")
        context.status_code = 200
        return {"JobIds": [job_id]}

    def job_output(request, context):
        if irreversible and state["action"] == "config_check":
            return json.dumps(config_check_for_request(state["body"]))
        return json.dumps(output_json)

    # Webhook
    m.post(WEBHOOK_URL, json=webhook)
    # Job status
    m.get(job_url(job_id), json={"properties": {"status": status}})
    # Job output
    m.get(job_output_url(job_id), text=job_output)


PREFLIGHT_JOB_ID = "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"


def mock_preflight_then_unfinished_operation(m, connector, webhook_calls):
    """Preflight completes; the irreversible webhook is accepted but its job
    is not polled to completion (the polling budget ends right after it)."""
    m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})

    def webhook_cb(request, context):
        body = request.json()
        webhook_calls.append(body)
        context.status_code = 200
        if body["action"] == "config_check":
            return {"JobIds": [PREFLIGHT_JOB_ID]}
        connector._utils._poll_timeout = 0
        return {"JobIds": [JOB_ID]}

    m.post(WEBHOOK_URL, json=webhook_cb)
    m.get(
        job_url(PREFLIGHT_JOB_ID),
        json={"properties": {"status": "Completed"}},
    )
    m.get(
        job_output_url(PREFLIGHT_JOB_ID),
        text=json.dumps(config_check_for_request({})),
    )


def irreversible_webhook_bodies(m):
    """Webhook bodies of release/deny only (the preflight is read-only)."""
    return [
        request.json()
        for request in m.request_history
        if request.url == WEBHOOK_URL
        and request.json()["action"] in {"release", "deny"}
    ]


def preflight_webhook_bodies(m):
    return [
        request.json()
        for request in m.request_history
        if request.url == WEBHOOK_URL
        and request.json()["action"] == "config_check"
    ]


def mock_full_flow_text(m, output_text: str, job_id=JOB_ID, status="Completed"):
    """Register all endpoints for a complete flow with raw job output text."""
    m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN, "expires_in": 3600})
    m.post(WEBHOOK_URL, json={"JobIds": [job_id]})
    m.get(job_url(job_id), json={"properties": {"status": status}})
    m.get(job_output_url(job_id), text=output_text)


def postcondition_error_output(
    action="release",
    observed_status="Requested",
    attempts=3,
    cmdlet_error="",
):
    expected_status = "Released" if action == "release" else "Denied"
    details = {
        "identity": IDENTITY,
        "expected_release_status": expected_status,
        "observed_release_status": observed_status,
        "observed_identity": IDENTITY,
        "observed_release_status_history": observed_status,
        "verification_attempts": attempts,
        "verification_method": "Get-QuarantineMessage",
        "last_verification_error": "",
        "precondition_trace": PRECONDITION_TRACE,
        "postcondition_trace": POSTCONDITION_TRACE,
        "handling": "reconcile_before_retry",
        **disposition_diagnostics(
            action=action,
            executed=True,
            cmdlet_error=cmdlet_error,
        ),
    }
    return {
        "action": action,
        "error": True,
        "error_code": "postcondition_unconfirmed",
        "message": cmdlet_error or (
            f"Exchange did not confirm ReleaseStatus={expected_status}."
        ),
        "details": details,
        **build_metadata(),
    }


def disposition_rejected_output(action="release"):
    expected_status = "Released" if action == "release" else "Denied"
    diagnostics = disposition_diagnostics(
        action=action,
        executed=True,
        cmdlet_error="HTTP 403 Forbidden: quarantine action is not authorized.",
    )
    diagnostics.update({
        "cmdlet_fully_qualified_error_id": "Exchange.HttpResponseException",
        "cmdlet_error_category": "PermissionDenied",
        "cmdlet_error_reason": "UnauthorizedAccessException",
        "cmdlet_exception_type": "System.UnauthorizedAccessException",
        "cmdlet_http_status_code": "403",
        "cmdlet_error_details": "HTTP 403 Forbidden",
    })
    return {
        "action": action,
        "error": True,
        "error_code": "disposition_rejected",
        "message": diagnostics["cmdlet_error"],
        "details": {
            "identity": IDENTITY,
            "expected_release_status": expected_status,
            "observed_release_status": "Requested",
            "observed_identity": IDENTITY,
            "observed_release_status_history": "Requested",
            "verification_attempts": 3,
            "verification_method": "Get-QuarantineMessage",
            "last_verification_error": "",
            "precondition_trace": PRECONDITION_TRACE,
            "postcondition_trace": REJECTED_POSTCONDITION_TRACE,
            "handling": "manual_review",
            **diagnostics,
        },
        **build_metadata(),
    }


def precondition_error_output(
    observed_status="Approved",
    action="release",
):
    details = {
        "identity": IDENTITY,
        "expected_release_status": "Requested",
        "observed_release_status": observed_status,
        "observed_identity": IDENTITY,
        "observed_release_status_history": observed_status,
        "verification_attempts": 1,
        "verification_method": "Get-QuarantineMessage",
        "last_verification_error": "",
        "precondition_trace": PRECONDITION_TRACE,
        "postcondition_trace": "",
        "handling": "manual_review",
        **disposition_diagnostics(
            action=action,
            executed=False,
        ),
    }
    return {
        "action": action,
        "error": True,
        "error_code": "precondition_unconfirmed",
        "message": (
            "Exchange did not confirm ReleaseStatus=Requested for the exact "
            f"identity. The {action} cmdlet was not executed."
        ),
        "details": details,
        **build_metadata(),
    }


def disposition_capability_error_output(action="release"):
    output = precondition_error_output(action=action)
    details = output["details"]
    details.update({
        "cmdlet_capability_status": "unconfirmed",
        "cmdlet_capability_parameter_set": "",
        "cmdlet_capability_error": (
            "No loaded Release-QuarantineMessage parameter set accepts the "
            f"exact named {action.title()} arguments without additional "
            "mandatory parameters."
        ),
        "last_verification_error": (
            "Disposition command parameter contract was not confirmed."
        ),
    })
    output.update({
        "error_code": "disposition_capability_unconfirmed",
        "message": details["cmdlet_capability_error"],
    })
    return output


def cmdlet_failure_output(action="release"):
    details = {
        "identity": IDENTITY,
        "handling": "retry_requires_new_operation",
        **disposition_diagnostics(
            action=action,
            executed=True,
            cmdlet_error="mock cmdlet failure",
        ),
    }
    details.update({
        "cmdlet_warning": "mock warning",
        "cmdlet_information": "mock information",
        "cmdlet_verbose": "mock verbose",
    })
    return {
        "action": action,
        "error": True,
        "error_code": "exchange_cmdlet_failed",
        "message": details["cmdlet_error"],
        "details": details,
        **build_metadata(),
    }


def chunked_export_output(
    raw=EML_RAW,
    identity=IDENTITY,
    chunk_size=8,
    order=None,
    sha256=None,
    length=None,
    decoded_size=None,
    runbook_version=RUNBOOK_VERSION,
):
    eml_base64 = base64.b64encode(raw).decode()
    chunks = [
        eml_base64[i:i + chunk_size]
        for i in range(0, len(eml_base64), chunk_size)
    ]
    records = []
    for idx, chunk in enumerate(chunks):
        records.append({
            "action": "export",
            "mode": "chunked",
            "identity": identity,
            "encoding": "base64",
            "chunk_index": idx,
            "chunk_count": len(chunks),
            "eml_chunk": chunk,
            "runbook_version": runbook_version,
            "runbook_source_revision": RUNBOOK_SOURCE_REVISION,
            "runbook_build_id": RUNBOOK_BUILD_ID,
        })
    trailer = {
        "action": "export",
        "mode": "chunked_complete",
        "identity": identity,
        "chunk_count": len(chunks),
        "eml_base64_length": len(eml_base64) if length is None else length,
        "decoded_size": len(raw) if decoded_size is None else decoded_size,
        "sha256": sha256 or hashlib.sha256(raw).hexdigest(),
        "runbook_version": runbook_version,
        "runbook_source_revision": RUNBOOK_SOURCE_REVISION,
        "runbook_build_id": RUNBOOK_BUILD_ID,
    }
    records.append(trailer)
    if order is not None:
        records = [records[i] for i in order]
    return "\n".join(json.dumps(record) for record in records)


def chunked_error_output(error_result, chunk_size=64, mutate=None):
    payload = json.dumps(
        error_result,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.b64encode(payload).decode("ascii")
    chunks = [
        encoded[offset:offset + chunk_size]
        for offset in range(0, len(encoded), chunk_size)
    ]
    records = [
        {
            "action": error_result["action"],
            "error": True,
            "mode": ERROR_CHUNK_MODE,
            "encoding": "base64",
            "chunk_index": idx,
            "chunk_count": len(chunks),
            "payload_chunk": chunk,
            **build_metadata(),
        }
        for idx, chunk in enumerate(chunks)
    ]
    records.append({
        "action": error_result["action"],
        "error": True,
        "mode": ERROR_COMPLETE_MODE,
        "encoding": "base64",
        "chunk_count": len(chunks),
        "payload_base64_length": len(encoded),
        "payload_utf8_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        **build_metadata(),
    })
    if mutate is not None:
        mutate(records)
    return "\n".join(
        json.dumps(record, separators=(",", ":"))
        for record in records
    )


def chunked_list_output(
    messages=None,
    groups=None,
    order=None,
    count=None,
    runbook_version=RUNBOOK_VERSION,
):
    messages = list(MOCK_MESSAGES if messages is None else messages)
    if groups is None:
        groups = [[message] for message in messages]
    records = []
    for idx, group in enumerate(groups):
        records.append({
            "action": "list",
            "mode": LIST_CHUNK_MODE,
            "chunk_index": idx,
            "messages": group,
            "runbook_version": runbook_version,
            "runbook_source_revision": RUNBOOK_SOURCE_REVISION,
            "runbook_build_id": RUNBOOK_BUILD_ID,
        })
    records.append({
        "action": "list",
        "mode": LIST_COMPLETE_MODE,
        "chunk_count": len(groups),
        "count": len(messages) if count is None else count,
        "runbook_version": runbook_version,
        "runbook_source_revision": RUNBOOK_SOURCE_REVISION,
        "runbook_build_id": RUNBOOK_BUILD_ID,
    })
    if order is not None:
        records = [records[idx] for idx in order]
    return "\n".join(json.dumps(record) for record in records)


@pytest.fixture(autouse=True)
def reset_vault():
    VAULT_ADDS.clear()
    ARTIFACT_ADDS.clear()
    yield


# ---------------------------------------------------------------------------
# TestInitialize
# ---------------------------------------------------------------------------

class TestInitialize:

    def test_valid_config(self):
        c = make_connector()
        assert c._utils is not None

    def test_cli_uses_base_connector_entrypoint(self, monkeypatch, tmp_path):
        calls = []

        def base_entrypoint(connector, payload, context):
            in_json = json.loads(payload)
            calls.append((in_json, context))
            connector._action_id = in_json["action_identifier"]
            return APP_SUCCESS

        monkeypatch.setattr(
            _BaseConnector,
            "_handle_action",
            base_entrypoint,
            raising=False,
        )
        input_path = tmp_path / "input.json"
        input_path.write_text(json.dumps({
            "action_identifier": "on_poll",
            "parameters": {},
        }))

        assert _run_cli(["connector.py", str(input_path)]) == 0
        assert calls == [({
            "action_identifier": "on_poll",
            "parameters": {},
        }, None)]

    def test_cli_rejects_invalid_json_without_dispatch(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ):
        dispatched = False

        def base_entrypoint(_connector, _payload, _context):
            nonlocal dispatched
            dispatched = True
            return APP_SUCCESS

        monkeypatch.setattr(
            _BaseConnector,
            "_handle_action",
            base_entrypoint,
            raising=False,
        )
        input_path = tmp_path / "invalid.json"
        input_path.write_text("{not-json")

        assert _run_cli(["connector.py", str(input_path)]) == 2
        error = json.loads(capsys.readouterr().err)
        assert error == {
            "error": "Invalid CLI input",
            "exception_type": "JSONDecodeError",
        }
        assert dispatched is False

    def test_manifest_declares_python_39_and_313_explicitly(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        assert manifest["python_version"] == "3.9, 3.13"
        assert manifest["python_version"] != "3"

    def test_default_poll_timeout_is_600_seconds(self):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            "webhook_url": WEBHOOK_URL,
            "azure_tenant_id": TENANT_ID,
            "azure_client_id": CLIENT_ID,
            "azure_client_secret": CLIENT_SECRET,
            "azure_subscription_id": SUB_ID,
            "azure_resource_group": RG,
            "azure_automation_account": AA,
        }
        assert c.initialize() == APP_SUCCESS
        assert c._utils._poll_timeout == 600

    @pytest.mark.parametrize("field,value", [
        ("poll_interval_seconds", 0),
        ("poll_interval_seconds", 61),
        ("poll_interval_seconds", "invalid"),
        ("poll_timeout_seconds", 59),
        ("poll_timeout_seconds", 120),
        ("poll_timeout_seconds", 599),
        ("poll_timeout_seconds", 3601),
        ("poll_timeout_seconds", "invalid"),
    ])
    def test_invalid_poll_configuration_is_rejected(self, field, value):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            "webhook_url": WEBHOOK_URL,
            "azure_tenant_id": TENANT_ID,
            "azure_client_id": CLIENT_ID,
            "azure_client_secret": CLIENT_SECRET,
            "azure_subscription_id": SUB_ID,
            "azure_resource_group": RG,
            "azure_automation_account": AA,
            "poll_interval_seconds": 5,
            "poll_timeout_seconds": 600,
            field: value,
        }
        assert c.initialize() == APP_ERROR

    def test_minimum_poll_timeout_600_is_accepted(self):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            "webhook_url": WEBHOOK_URL,
            "azure_tenant_id": TENANT_ID,
            "azure_client_id": CLIENT_ID,
            "azure_client_secret": CLIENT_SECRET,
            "azure_subscription_id": SUB_ID,
            "azure_resource_group": RG,
            "azure_automation_account": AA,
            "poll_interval_seconds": 60,
            "poll_timeout_seconds": 600,
        }
        assert c.initialize() == APP_SUCCESS

    def test_missing_webhook_url(self):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            "webhook_url": "",
            "azure_tenant_id": TENANT_ID,
            "azure_client_id": CLIENT_ID,
            "azure_client_secret": CLIENT_SECRET,
            "azure_subscription_id": SUB_ID,
            "azure_resource_group": RG,
            "azure_automation_account": AA,
        }
        assert c.initialize() == APP_ERROR

    def test_missing_tenant_id(self):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            "webhook_url": WEBHOOK_URL,
            "azure_tenant_id": "",
            "azure_client_id": CLIENT_ID,
            "azure_client_secret": CLIENT_SECRET,
            "azure_subscription_id": SUB_ID,
            "azure_resource_group": RG,
            "azure_automation_account": AA,
        }
        assert c.initialize() == APP_ERROR

    def test_hidden_invalid_export_mode_falls_back_to_vault(self):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            "webhook_url": WEBHOOK_URL,
            "azure_tenant_id": TENANT_ID,
            "azure_client_id": CLIENT_ID,
            "azure_client_secret": CLIENT_SECRET,
            "azure_subscription_id": SUB_ID,
            "azure_resource_group": RG,
            "azure_automation_account": AA,
            "export_mode": "nonsense",
        }
        assert c.initialize() == APP_SUCCESS
        assert c._export_mode == EXPORT_VAULT
        assert c._config["export_mode"] == "nonsense"

    def test_default_export_mode_is_vault(self):
        c = make_connector()
        assert c._export_mode == EXPORT_VAULT

    def test_default_asset_artifact_policy_is_disabled_with_legacy_defaults(self):
        c = make_connector()
        assert c._asset_artifact_options == {
            "enabled": False,
            "layout": ARTIFACT_LAYOUT_COMBINED,
            "fields": DEFAULT_ARTIFACT_FIELDS,
        }

    def test_verbose_action_diagnostics_default_is_false(self):
        c = make_connector()
        assert c._include_verbose_action_diagnostics is False

    @pytest.mark.parametrize("value", [True, 1, "true", "yes", "on"])
    def test_verbose_action_diagnostics_accepts_true_values(self, value):
        c = make_connector(config_overrides={
            "include_verbose_action_diagnostics": value,
        })
        assert c._include_verbose_action_diagnostics is True

    @pytest.mark.parametrize("value", [False, 0, "false", "no", "off", ""])
    def test_verbose_action_diagnostics_accepts_false_values(self, value):
        c = make_connector(config_overrides={
            "include_verbose_action_diagnostics": value,
        })
        assert c._include_verbose_action_diagnostics is False

    @pytest.mark.parametrize("value", [2, "sometimes", [], {}])
    def test_verbose_action_diagnostics_rejects_invalid_values(self, value):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = base_asset_config()
        c._config["include_verbose_action_diagnostics"] = value
        assert c.initialize() == APP_ERROR

    def test_on_poll_active_limit_defaults_to_ten(self):
        c = make_connector()
        assert c._on_poll_max_containers == 10

    @pytest.mark.parametrize("value", [1, 3, 50, "7"])
    def test_on_poll_max_containers_accepts_supported_range(self, value):
        c = make_connector(config_overrides={
            "on_poll_max_containers": value,
        })
        assert c._on_poll_max_containers == int(value)

    @pytest.mark.parametrize("value", [None, ""])
    def test_on_poll_max_containers_defaults_for_upgraded_assets(self, value):
        c = make_connector(config_overrides={
            "on_poll_max_containers": value,
        })
        assert c._on_poll_max_containers == 10

    @pytest.mark.parametrize("value", [0, 51, -1, "many"])
    def test_on_poll_max_containers_rejects_invalid_values(self, value):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = base_asset_config()
        c._config["on_poll_max_containers"] = value
        assert c.initialize() == APP_ERROR

    @pytest.mark.parametrize("value", [1, 30, 365, "90"])
    def test_worker_terminal_retention_accepts_supported_days(self, value):
        c = make_connector(config_overrides={
            "worker_terminal_retention_days": value,
        })
        assert c._worker_terminal_retention_days == int(value)

    @pytest.mark.parametrize("value", [0, 366, -1, "forever"])
    def test_worker_terminal_retention_rejects_invalid_days(self, value):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = base_asset_config()
        c._config["worker_terminal_retention_days"] = value
        assert c.initialize() == APP_ERROR

    def test_manifest_exposes_asset_dropdown_and_field_checkboxes(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        config = manifest["configuration"]
        assert "export_mode" not in config
        assert "create_email_artifacts" not in config
        assert config["artifact_layout"]["value_list"] == ["combined", "separate"]
        assert all(key in config for key in ARTIFACT_FIELD_CONFIG_KEYS.values())

    def test_manifest_groups_target_then_api_login_then_exchange(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        config = manifest["configuration"]
        ordered = [
            key for key, _ in sorted(
                config.items(), key=lambda item: item[1]["order"]
            )
        ]
        assert ordered[:8] == [
            "webhook_url",
            "azure_subscription_id",
            "azure_resource_group",
            "azure_automation_account",
            "azure_tenant_id",
            "azure_client_id",
            "azure_client_secret",
            "exchange_organization",
        ]
        assert sorted(item["order"] for item in config.values()) == list(
            range(len(config))
        )
        prefixes = [config[key]["description"].split(": ", 1)[0] for key in ordered]
        blocks = [value for index, value in enumerate(prefixes)
                  if index == 0 or value != prefixes[index - 1]]
        assert blocks == ["Connection", "Email import", "Mail fields", "Advanced"]
        for key in (
            "azure_tenant_id", "azure_client_id", "azure_client_secret"
        ):
            assert config[key]["required"] is True
            assert "not Exchange" in config[key]["description"]
        assert config["azure_client_secret"]["data_type"] == "password"
        assert "VALUE" in config["azure_client_secret"]["description"]
        assert config["exchange_organization"]["required"] is False

    def test_manifest_has_no_exchange_credential_or_method_fields(self):
        raw = (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        manifest = json.loads(raw)
        config = manifest["configuration"]
        assert not [key for key in config if key.startswith("exchange_")
                    and key != "exchange_organization"]
        assert "exchange_credential" not in raw
        assert "exchange_auth_method\"," not in raw.split('"actions"')[0]
        for action in manifest["actions"]:
            for item in action.get("output", []):
                assert "exchange_credential" not in item["data_path"]

    def test_manifest_declares_optional_on_poll_configuration(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        config = manifest["configuration"]
        assert "enable_on_poll_ingestion" not in config
        assert config["on_poll_max_containers"]["default"] == 10
        assert config["worker_terminal_retention_days"]["default"] == 30
        action = next(
            item for item in manifest["actions"]
            if item["identifier"] == "on_poll"
        )
        assert action["action"] == "on poll"
        assert action["type"] == "ingest"
        assert action["read_only"] is True
        assert "container_count" in action["parameters"]
        assert config["artifact_layout"]["data_type"] == "string"
        assert config["artifact_layout"]["default"] == "combined"
        assert config["include_verbose_action_diagnostics"] == {
            "description": "Advanced: Verbose diagnostics for successful actions",
            "data_type": "boolean",
            "required": False,
            "default": False,
            "order": 27,
        }
        assert config["webhook_url"]["description"] == (
            "Connection: HTTPS webhook URL with token; no redirects"
        )
        assert config["azure_tenant_id"]["description"] == (
            "Connection: Azure API tenant ID (not Exchange)"
        )
        assert config["poll_interval_seconds"]["description"] == (
            "Advanced: Job status check (whole seconds, 1-60; default 5)"
        )
        assert config["poll_timeout_seconds"]["description"] == (
            "Advanced: Job timeout (whole seconds, 600-3600; default 600)"
        )
        assert config["artifact_field_from"]["description"] == "Mail fields: From"
        assert all(
            len(field["description"]) <= 64
            for field in config.values()
        )
        assert config["artifact_layout"]["value_list"] == [
            "combined",
            "separate",
        ]

        for field, config_key in ARTIFACT_FIELD_CONFIG_KEYS.items():
            assert config[config_key]["data_type"] == "boolean"
            assert config[config_key]["default"] is (
                field in DEFAULT_ARTIFACT_FIELDS
            )

        assert all(item["identifier"] != "get_quarantine_message" for item in manifest["actions"])

    def test_manifest_declares_validated_offline_runtime_contract(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        assert manifest["min_phantom_version"] == "8.5.0"
        assert manifest["python_version"] == "3.9, 3.13"
        assert "pip3_dependencies" not in manifest
        assert manifest["appid"] == "2e21b2c5-a6a6-4fb4-8df7-9dd1135ab08e"

        inspect_action = next(
            item for item in manifest["actions"]
            if item["identifier"] == "inspect_release_environment"
        )
        assert inspect_action["parameters"]["include_rbac"]["default"] is False
        inspect_paths = {
            item["data_path"] for item in inspect_action["output"]
        }
        for path in (
            "action_result.parameter.include_rbac",
            "action_result.data.*.rbac_included",
            "action_result.data.*.rbac_empty_contracts.*",
            "action_result.data.*.permission_query_error_retained_count",
            "action_result.data.*.permission_query_error_dropped_count",
            "action_result.data.*.permission_query_errors_truncated",
        ):
            assert path in inspect_paths
        assert all(
            "managed_identity_resource_id" not in path
            for path in inspect_paths
        )

        action = next(
            item for item in manifest["actions"]
            if item["identifier"] == "reconcile_quarantine_operation"
        )
        assert action["read_only"] is True
        assert action["parameters"]["refresh_exchange_status"] == {
            "description": action["parameters"][
                "refresh_exchange_status"
            ]["description"],
            "data_type": "boolean",
            "required": False,
            "default": False,
            "order": 4,
        }
        for identifier in (
            "release_quarantine_message",
            "deny_quarantine_release",
            "reconcile_quarantine_operation",
        ):
            paths = manifest_action_paths(identifier)
            assert "action_result.data.*.idempotent" in paths

    def test_removed_legacy_action_cannot_dispatch_or_mutate_state(self, monkeypatch):
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        assert {item["identifier"] for item in manifest["actions"]} == {
            "test_connectivity", "on_poll", "on_es_poll",
            "recover_quarantine_ingestion", "inspect_release_environment",
            "release_quarantine_message", "deny_quarantine_release",
            "reconcile_quarantine_operation",
        }
        c = make_connector()
        c.save_state({"legacy_marker": {"state": "prompt_pending"}})
        before = Path(c.get_state_file_path()).read_bytes()
        def forbidden(*args, **kwargs):
            raise AssertionError("Removed legacy action was dispatched")
        monkeypatch.setattr(c, "_transition_worker_item", forbidden)
        for identifier in (
            "update_quarantine_work_item", "list_quarantine_requests",
            "get_quarantine_message",
        ):
            c._action_id = identifier
            assert c.handle_action({"identity": IDENTITY}) == APP_ERROR
        assert Path(c.get_state_file_path()).read_bytes() == before

    def test_asset_artifact_policy_normalizes_selected_fields(self):
        options = parse_artifact_asset_config(artifact_asset_config(
            enabled=True,
            layout=" SEPARATE ",
            fields={"subject", "from", "received_date"},
        ))
        assert options == {
            "enabled": True,
            "layout": ARTIFACT_LAYOUT_SEPARATE,
            "fields": ("from", "subject", "received_date"),
        }

    def test_missing_or_empty_new_asset_fields_use_documented_defaults(self):
        options = parse_artifact_asset_config({
            "artifact_layout": "",
            "artifact_field_from": None,
            "artifact_field_subject": "",
        })
        assert options == {
            "enabled": False,
            "layout": ARTIFACT_LAYOUT_COMBINED,
            "fields": DEFAULT_ARTIFACT_FIELDS,
        }

    @pytest.mark.parametrize(
        "config",
        [
            artifact_asset_config(enabled="maybe"),
            artifact_asset_config(enabled=True, layout="invalid"),
            artifact_asset_config(enabled=True, fields=set()),
            {"artifact_field_from": "maybe"},
        ],
    )
    def test_invalid_asset_artifact_policy_is_rejected(self, config):
        with pytest.raises(ValueError):
            parse_artifact_asset_config(config)

    def test_legacy_enable_value_does_not_require_optional_mail_fields(self):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = base_asset_config()
        c._config.update(artifact_asset_config(
            enabled=True,
            fields=set(),
        ))
        assert c.initialize() == APP_SUCCESS
        assert c._asset_artifact_options["fields"] == ()
        assert c._config["create_email_artifacts"] is True


# ---------------------------------------------------------------------------
# TestTokenAcquisition
# ---------------------------------------------------------------------------

class TestTokenAcquisition:

    def test_token_acquired_successfully(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            token = utils.get_mgmt_token()
        assert token == MOCK_TOKEN

    def test_token_cached(self):
        utils = make_utils()
        call_count = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                call_count.append(1)
                ctx.status_code = 200
                return {"access_token": MOCK_TOKEN}
            m.post(TOKEN_URL, json=cb)
            utils.get_mgmt_token()
            utils.get_mgmt_token()
        assert len(call_count) == 1

    def test_token_failure_raises(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, status_code=401,
                   json={"error_description": "bad credentials"})
            with pytest.raises(TokenError):
                utils.get_mgmt_token()

    def test_token_connection_error(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, exc=requests.exceptions.ConnectionError())
            with pytest.raises(TokenError):
                utils.get_mgmt_token()

    def test_token_error_redacts_client_secret_and_jwt(self):
        utils = make_utils()
        jwt = (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIn0."
            "signaturesignature"
        )
        with req_mock.Mocker() as m:
            m.post(
                TOKEN_URL,
                status_code=401,
                json={
                    "error_description": (
                        f"client_secret={CLIENT_SECRET}; token={jwt}"
                    )
                },
            )
            with pytest.raises(TokenError) as exc:
                utils.get_mgmt_token()
        message = str(exc.value)
        assert CLIENT_SECRET not in message
        assert jwt not in message

    @pytest.mark.parametrize(
        "text",
        [
            (
                "The mailbox is on server "
                "nam02-am6-obe.outbound.protection.outlook.com and failed."
            ),
            "Module Microsoft.Exchange.Management.RestApiClient.dll failed.",
            "Identifier abcdefgh.ijklmnop.qrstuvwx is not a JWT.",
        ],
    )
    def test_redaction_preserves_non_jwt_dotted_text(self, text):
        assert automation_utils.redact_sensitive_text(text) == text

    def test_redaction_uses_last_three_segments_of_dotted_chain(self):
        jwt = (
            "eyJhbGciOiJSUzI1NiJ9."
            "payloadxx."
            "signature"
        )
        candidate = f"login.microsoftonline.{jwt}"
        assert automation_utils.redact_sensitive_text(candidate) == (
            "login.microsoftonline.[REDACTED-JWT]"
        )

    def test_redaction_fails_closed_for_oversized_jwt_header(
        self,
        monkeypatch,
    ):
        nested_json = "[" * 10000 + "0" + "]" * 10000
        header_segment = base64.urlsafe_b64encode(
            nested_json.encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        assert len(header_segment) > automation_utils.MAX_JWT_HEADER_SEGMENT_CHARS
        candidate = f"{header_segment}.payloadxx.signature"

        def unexpected_decode(_value):
            raise AssertionError("oversized JWT header was decoded")

        monkeypatch.setattr(
            automation_utils.base64,
            "urlsafe_b64decode",
            unexpected_decode,
        )
        assert (
            automation_utils.redact_sensitive_text(candidate, max_chars=None)
            == "[REDACTED-JWT]"
        )

    def test_redaction_preserves_candidate_when_json_parser_recurses(
        self,
        monkeypatch,
    ):
        candidate = "eyJhbGciOiJSUzI1NiJ9.payloadxx.signature"

        def recursive_json(_value):
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(automation_utils.json, "loads", recursive_json)
        assert automation_utils.redact_sensitive_text(candidate) == candidate

    @pytest.mark.parametrize(
        ("text", "secret"),
        [
            ("Cookie: session=abc123; csrf=def456", "abc123"),
            ("Set-Cookie: session=abc123; HttpOnly; Secure", "abc123"),
            ('{"refresh_token":"rotate-me"}', "rotate-me"),
            ("client_assertion='signed-assertion'", "signed-assertion"),
            ("password=hunter2", "hunter2"),
            ("pwd:secret-value", "secret-value"),
            ("https://example.invalid/?refresh_token=query-secret", "query-secret"),
        ],
    )
    def test_redaction_covers_extended_credential_forms(self, text, secret):
        redacted = automation_utils.redact_sensitive_text(
            text,
            max_chars=None,
        )
        assert secret not in redacted
        assert "[REDACTED]" in redacted


# ---------------------------------------------------------------------------
# TestWebhook
# ---------------------------------------------------------------------------

class TestWebhook:

    def test_webhook_returns_job_id(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            job_id = utils.fire_webhook("list")
        assert job_id == JOB_ID

    def test_webhook_sends_action(self):
        utils = make_utils()
        bodies = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                bodies.append(req.json())
                ctx.status_code = 200
                return {"JobIds": [JOB_ID]}
            m.post(WEBHOOK_URL, json=cb)
            utils.fire_webhook("list")
        assert bodies[0]["action"] == "list"

    def test_webhook_sends_identity(self):
        utils = make_utils()
        bodies = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                bodies.append(req.json())
                ctx.status_code = 200
                return {"JobIds": [JOB_ID]}
            m.post(WEBHOOK_URL, json=cb)
            utils.fire_webhook("export", identity=IDENTITY)
        assert bodies[0]["identity"] == IDENTITY

    def test_webhook_sends_read_only_operation_action(self):
        utils = make_utils()
        bodies = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                bodies.append(req.json())
                ctx.status_code = 200
                return {"JobIds": [JOB_ID]}
            m.post(WEBHOOK_URL, json=cb)
            utils.fire_webhook(
                "reconcile",
                identity=IDENTITY,
                operation_action="release",
            )
        assert bodies == [{
            "action": "reconcile",
            "auth_method": "ManagedIdentity",
            "identity": IDENTITY,
            "operation_action": "release",
        }]

    @pytest.mark.parametrize("include_rbac", [False, True])
    def test_webhook_sends_explicit_rbac_opt_in(self, include_rbac):
        utils = make_utils()
        bodies = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                bodies.append(req.json())
                ctx.status_code = 200
                return {"JobIds": [JOB_ID]}
            m.post(WEBHOOK_URL, json=cb)
            utils.fire_webhook(
                "diagnose",
                identity=IDENTITY,
                include_rbac=include_rbac,
            )
        assert bodies == [{
            "action": "diagnose",
            "auth_method": "ManagedIdentity",
            "identity": IDENTITY,
            "include_rbac": include_rbac,
        }]

    def test_webhook_no_identity_for_list(self):
        utils = make_utils()
        bodies = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                bodies.append(req.json())
                ctx.status_code = 200
                return {"JobIds": [JOB_ID]}
            m.post(WEBHOOK_URL, json=cb)
            utils.fire_webhook("list")
        assert "identity" not in bodies[0]

    def test_webhook_404_raises(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(WEBHOOK_URL, status_code=404)
            with pytest.raises(WebhookError) as exc:
                utils.fire_webhook("list")
        assert "expired" in str(exc.value).lower() or "404" in str(exc.value)

    def test_webhook_empty_job_ids_raises(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(WEBHOOK_URL, json={"JobIds": []})
            with pytest.raises(WebhookError):
                utils.fire_webhook("list")

    def test_webhook_transport_exception_never_persists_url_token(self):
        utils = make_utils()
        leaked = (
            "HTTPSConnectionPool failed with url: "
            "/webhooks?token=abc123 and " + WEBHOOK_URL
        )
        with req_mock.Mocker() as m:
            m.post(
                WEBHOOK_URL,
                exc=requests.exceptions.ConnectionError(leaked),
            )
            with pytest.raises(WebhookError) as exc:
                utils.fire_webhook("list")
        message = str(exc.value)
        assert "abc123" not in message
        assert WEBHOOK_URL not in message

        connector = make_connector()
        mapped = connector._map_error(WebhookError(leaked), "release")
        assert "abc123" not in mapped
        assert WEBHOOK_URL not in mapped

    def test_validated_runbook_message_is_not_normalised_by_connector(self):
        connector = make_connector()
        message = (
            "Microsoft Exchange failure\r\n"
            "ErrorAccessDenied – request-id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
        exc = RunbookActionError(
            message,
            result={"error": True, "message": message},
        )
        assert connector._map_error(exc, "release") == message


# ---------------------------------------------------------------------------
# TestPolling
# ---------------------------------------------------------------------------

class TestPolling:

    def test_completed_job_succeeds(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            status = utils.poll_job(JOB_ID)
        assert status == "Completed"

    def test_failed_job_raises(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Failed"}})
            with pytest.raises(JobFailedError):
                utils.poll_job(JOB_ID)

    def test_suspended_job_raises(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Suspended"}})
            with pytest.raises(JobFailedError):
                utils.poll_job(JOB_ID)

    def test_running_then_completed(self):
        utils = make_utils(poll_interval=0)
        responses = [
            {"properties": {"status": "Running"}},
            {"properties": {"status": "Running"}},
            {"properties": {"status": "Completed"}},
        ]
        call = [0]
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            def cb(req, ctx):
                ctx.status_code = 200
                r = responses[min(call[0], len(responses)-1)]
                call[0] += 1
                return r
            m.get(job_url(), json=cb)
            status = utils.poll_job(JOB_ID)
        assert status == "Completed"

    def test_timeout_raises(self):
        utils = make_utils(poll_interval=0, poll_timeout=0)
        with pytest.raises(JobTimeoutError) as exc_info:
            utils.poll_job(JOB_ID)
        assert exc_info.value.job_id == JOB_ID
        assert exc_info.value.phase == "status"

    def test_timeout_preserves_last_observed_status(self, monkeypatch):
        utils = make_utils(poll_interval=0, poll_timeout=1)
        clock = iter([0.0, 0.0, 0.0, 2.0])
        fake_time = types.SimpleNamespace(
            time=lambda: next(clock),
            sleep=lambda seconds: None,
        )
        monkeypatch.setattr(automation_utils, "time", fake_time)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Running"}})
            with pytest.raises(JobTimeoutError) as exc_info:
                utils.poll_job(JOB_ID)
        assert exc_info.value.job_id == JOB_ID
        assert exc_info.value.last_status == "Running"
        assert exc_info.value.phase == "status"

    def test_403_gives_role_hint(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), status_code=403,
                  json={"error": {"code": "AuthorizationFailed"}})
            with pytest.raises(AutomationError) as exc:
                utils.poll_job(JOB_ID)
        assert "Automation Job Operator" in str(exc.value)

    def test_404_gives_config_hint(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), status_code=404)
            with pytest.raises(AutomationError) as exc:
                utils.poll_job(JOB_ID)
        assert "azure_subscription_id" in str(exc.value) or "automation_account" in str(exc.value)

    def test_failed_job_includes_exception_detail(self):
        """Job failure should surface properties.exception from Azure."""
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {
                "status": "Failed",
                "exception": "Connect-ExchangeOnline: UnAuthorized"
            }})
            with pytest.raises(JobFailedError) as exc:
                utils.poll_job(JOB_ID)
        assert "Connect-ExchangeOnline" in str(exc.value)

    def test_transient_network_error_retried(self):
        """A single network blip mid-poll must not kill the action."""
        utils = make_utils(poll_interval=0, poll_timeout=30)
        calls = [0]
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            def cb(req, ctx):
                calls[0] += 1
                if calls[0] == 1:
                    raise requests.exceptions.ConnectionError("blip")
                ctx.status_code = 200
                return {"properties": {"status": "Completed"}}
            m.get(job_url(), json=cb)
            status = utils.poll_job(JOB_ID)
        assert status == "Completed"
        assert calls[0] == 2

    def test_401_mid_poll_refreshes_token_once(self):
        """Expired token mid-poll triggers exactly one token refresh."""
        utils = make_utils(poll_interval=0, poll_timeout=30)
        token_calls = [0]
        poll_calls = [0]
        with req_mock.Mocker() as m:
            def token_cb(req, ctx):
                token_calls[0] += 1
                ctx.status_code = 200
                return {"access_token": MOCK_TOKEN}
            m.post(TOKEN_URL, json=token_cb)
            def poll_cb(req, ctx):
                poll_calls[0] += 1
                if poll_calls[0] == 1:
                    ctx.status_code = 401
                    return {"error": "token expired"}
                ctx.status_code = 200
                return {"properties": {"status": "Completed"}}
            m.get(job_url(), json=poll_cb)
            status = utils.poll_job(JOB_ID)
        assert status == "Completed"
        assert token_calls[0] == 2  # initial + refresh

    def test_429_mid_poll_retries_with_backoff(self, monkeypatch):
        """Azure Management API throttling should be retried inside the action."""
        utils = make_utils(poll_interval=1, poll_timeout=30)
        sleeps = []
        poll_calls = [0]
        monkeypatch.setattr(time, "sleep", lambda seconds: sleeps.append(seconds))

        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})

            def poll_cb(req, ctx):
                poll_calls[0] += 1
                if poll_calls[0] == 1:
                    ctx.status_code = 429
                    ctx.headers["Retry-After"] = "2"
                    return {
                        "code": 429,
                        "message": "The request rate is currently too large."
                    }
                ctx.status_code = 200
                return {"properties": {"status": "Completed"}}

            m.get(job_url(), json=poll_cb)
            status = utils.poll_job(JOB_ID)

        assert status == "Completed"
        assert poll_calls[0] == 2
        assert sleeps == [2.0]

    def test_status_and_output_share_one_absolute_deadline(self):
        utils = make_utils()
        calls = []
        utils.new_poll_deadline = lambda: 123.0
        utils.poll_job = lambda job_id, deadline=None: calls.append(
            ("status", job_id, deadline)
        ) or "Completed"
        utils.get_job_output = (
            lambda job_id, action=None, deadline=None: calls.append(
                ("output", job_id, deadline)
            ) or {
                "action": "list",
                "count": 0,
                "messages": [],
                **build_metadata(),
            }
        )
        assert utils.wait_for_action_result(JOB_ID, "list")["count"] == 0
        assert calls == [
            ("status", JOB_ID, 123.0),
            ("output", JOB_ID, 123.0),
        ]

    def test_output_throttling_cannot_restart_consumed_status_budget(
        self,
        monkeypatch,
    ):
        utils = make_utils(poll_interval=1, poll_timeout=10)
        utils._mgmt_token = MOCK_TOKEN
        now = [0.0]
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        fake_time = types.SimpleNamespace(time=lambda: now[0], sleep=sleep)
        monkeypatch.setattr(automation_utils, "time", fake_time)

        with req_mock.Mocker() as m:
            def status_cb(_request, context):
                now[0] = 9.0
                context.status_code = 200
                return {"properties": {"status": "Completed"}}

            m.get(job_url(), json=status_cb)
            m.get(
                job_output_url(),
                status_code=429,
                headers={"Retry-After": "30"},
                json={"code": 429},
            )
            with pytest.raises(JobTimeoutError) as exc_info:
                utils.wait_for_action_result(JOB_ID, "list")

        assert exc_info.value.phase == "output"
        assert exc_info.value.last_status == "Completed"
        assert now[0] == 10.0
        assert sleeps == [1.0]

    def test_output_available_just_before_shared_deadline_succeeds(
        self,
        monkeypatch,
    ):
        utils = make_utils(poll_interval=1, poll_timeout=10)
        utils._mgmt_token = MOCK_TOKEN
        now = [0.0]
        output_calls = [0]

        def sleep(seconds):
            now[0] += seconds

        fake_time = types.SimpleNamespace(time=lambda: now[0], sleep=sleep)
        monkeypatch.setattr(automation_utils, "time", fake_time)

        with req_mock.Mocker() as m:
            def status_cb(_request, context):
                now[0] = 9.0
                context.status_code = 200
                return {"properties": {"status": "Completed"}}

            def output_cb(_request, context):
                output_calls[0] += 1
                if output_calls[0] == 1:
                    context.status_code = 429
                    context.headers["Retry-After"] = "0.5"
                    return {"code": 429}
                context.status_code = 200
                return {
                    "action": "list",
                    "count": 0,
                    "messages": [],
                    **build_metadata(),
                }

            m.get(job_url(), json=status_cb)
            m.get(job_output_url(), json=output_cb)
            result = utils.wait_for_action_result(JOB_ID, "list")

        assert result["count"] == 0
        assert now[0] == 9.5
        assert output_calls[0] == 2


# ---------------------------------------------------------------------------
# TestJobOutput
# ---------------------------------------------------------------------------

class TestJobOutput:

    def test_output_parsed_as_json(self):
        utils = make_utils()
        payload = {"action": "list", "count": 1, "messages": []}
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=json.dumps(payload))
            result = utils.get_job_output(JOB_ID)
        assert result["count"] == 1

    def test_output_429_retries_with_backoff(self, monkeypatch):
        """Azure throttling on the job output endpoint should be retried too."""
        utils = make_utils(poll_interval=1, poll_timeout=30)
        payload = {"action": "list", "count": 1, "messages": []}
        sleeps = []
        calls = [0]
        monkeypatch.setattr(time, "sleep", lambda seconds: sleeps.append(seconds))

        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})

            def output_cb(req, ctx):
                calls[0] += 1
                if calls[0] == 1:
                    ctx.status_code = 429
                    ctx.headers["Retry-After"] = "3"
                    return {
                        "code": 429,
                        "message": "The request rate is currently too large."
                    }
                ctx.status_code = 200
                return payload

            m.get(job_output_url(), json=output_cb)
            result = utils.get_job_output(JOB_ID)

        assert result["count"] == 1
        assert calls[0] == 2
        assert sleeps == [3.0]

    def test_empty_output_raises(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text="")
            with pytest.raises(AutomationError):
                utils.get_job_output(JOB_ID)

    def test_non_json_output_raises(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text="not json at all")
            with pytest.raises(AutomationError):
                utils.get_job_output(JOB_ID)

    def test_last_json_line_used(self):
        """Verbose output before Write-Output should be ignored."""
        utils = make_utils()
        verbose = "VERBOSE: Connecting...\n" + json.dumps({"action": "list", "count": 0, "messages": []})
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=verbose)
            result = utils.get_job_output(JOB_ID)
        assert result["action"] == "list"

    def test_chunked_list_output_reassembled_in_index_order(self):
        utils = make_utils()
        second = dict(MOCK_MESSAGES[0], Subject="Second")
        output = chunked_list_output(
            messages=[MOCK_MESSAGES[0], second],
            groups=[[MOCK_MESSAGES[0]], [second]],
            order=[1, 0, 2],
        )
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            result = utils.get_job_output(JOB_ID, action="list")
        assert result["action"] == "list"
        assert result["count"] == 2
        assert [item["Subject"] for item in result["messages"]] == [
            "Invoice", "Second"
        ]

    def test_chunked_list_without_trailer_is_rejected(self):
        utils = make_utils()
        output = "\n".join(chunked_list_output().splitlines()[:-1])
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        assert "missing" in str(exc_info.value).lower()
        assert "list_complete" in str(exc_info.value)

    def test_chunked_list_duplicate_index_is_rejected(self):
        utils = make_utils()
        second = dict(MOCK_MESSAGES[0], Subject="Second")
        records = [
            json.loads(line) for line in chunked_list_output(
                messages=[MOCK_MESSAGES[0], second],
                groups=[[MOCK_MESSAGES[0]], [second]],
            ).splitlines()
        ]
        records[1]["chunk_index"] = 0
        output = "\n".join(json.dumps(record) for record in records)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        assert "duplicate chunk_index" in str(exc_info.value)

    def test_chunked_list_count_mismatch_is_rejected(self):
        utils = make_utils()
        output = chunked_list_output(count=2)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        assert "count mismatch" in str(exc_info.value).lower()

    def test_chunked_list_count_limit_is_enforced(self):
        utils = make_utils()
        records = [
            json.loads(line) for line in chunked_list_output().splitlines()
        ]
        records[-1]["count"] = MAX_LIST_RESULT_COUNT + 1
        output = "\n".join(json.dumps(record) for record in records)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        assert "count must be between" in str(exc_info.value)

    @pytest.mark.parametrize("messages", [None, ["not-an-object"]])
    def test_chunked_list_messages_must_be_nonempty_object_array(self, messages):
        utils = make_utils()
        record_messages = [] if messages is None else messages
        output = "\n".join([
            json.dumps({
                "action": "list",
                "mode": LIST_CHUNK_MODE,
                "chunk_index": 0,
                "messages": record_messages,
                "runbook_version": RUNBOOK_VERSION,
            }),
            json.dumps({
                "action": "list",
                "mode": LIST_COMPLETE_MODE,
                "chunk_count": 1,
                "count": 1,
                "runbook_version": RUNBOOK_VERSION,
            }),
        ])
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError):
                utils.get_job_output(JOB_ID, action="list")

    def test_chunked_list_record_version_must_match_trailer(self):
        utils = make_utils()
        records = [
            json.loads(line) for line in chunked_list_output().splitlines()
        ]
        records[0]["runbook_version"] = "3.4.0"
        output = "\n".join(json.dumps(record) for record in records)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        assert "runbook_version mismatch" in str(exc_info.value)

    def test_runbook_error_flag_raises(self):
        utils = make_utils()
        error_output = {
            "action": "list",
            "error": True,
            "message": "Connect-ExchangeOnline failed",
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(job_output_url(), text=json.dumps(error_output))
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("list")
        assert "Connect-ExchangeOnline" in str(exc_info.value)

    def test_validated_runbook_error_has_no_connector_prefix(self):
        utils = make_utils()
        message = (
            "Microsoft native failure\r\n"
            "ErrorAccessDenied; RequestId=12345678-1234-1234-1234-123456789abc"
        )
        error_output = {
            "action": "list",
            "error": True,
            "message": message,
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, error_output)
            with pytest.raises(RunbookActionError) as exc_info:
                utils.run_action("list")
        assert str(exc_info.value) == message

    def test_chunked_error_restores_exact_unicode_and_line_breaks(self):
        utils = make_utils()
        message = (
            "Microsoft Exchange Online returned:\r\n"
            "Fehler: Zugriff verweigert – Ω\n"
            "RequestId: 12345678-1234-1234-1234-123456789abc\n"
            "Mailbox: analyst+quarantine@example.com"
        )
        error_result = {
            "action": "list",
            "error": True,
            "error_code": "fixture_native_error",
            "message": message,
            **build_metadata(),
        }
        output = chunked_error_output(error_result)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            restored = utils.get_job_output(JOB_ID, action="list")
        assert restored == error_result
        assert restored["message"] == message

    @pytest.mark.parametrize(
        "mutation,expected",
        [
            (
                lambda records: records.__setitem__(
                    -1,
                    {**records[-1], "payload_sha256": "0" * 64},
                ),
                "sha256 mismatch",
            ),
            (
                lambda records: records.pop(0),
                "expected",
            ),
            (
                lambda records: records.__setitem__(
                    0,
                    {**records[0], "chunk_index": 1},
                ),
                "duplicate chunk_index",
            ),
        ],
    )
    def test_chunked_error_rejects_corruption(self, mutation, expected):
        utils = make_utils()
        error_result = {
            "action": "list",
            "error": True,
            "message": "native error " * 100,
            **build_metadata(),
        }
        output = chunked_error_output(error_result, mutate=mutation)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        assert expected in str(exc_info.value).lower()

    def test_chunked_error_without_trailer_is_rejected(self):
        utils = make_utils()
        error_result = {
            "action": "list",
            "error": True,
            "message": "native error " * 100,
            **build_metadata(),
        }
        output = "\n".join(
            chunked_error_output(error_result).splitlines()[:-1]
        )
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        assert "error_complete" in str(exc_info.value)

    def test_chunked_export_output_reassembled(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=chunked_export_output())
            result = utils.get_job_output(JOB_ID)
        assert result["action"] == "export"
        assert result["mode"] == "chunked"
        assert result["identity"] == IDENTITY
        assert result["eml"] == EML_B64
        assert result["sha256"] == hashlib.sha256(EML_RAW).hexdigest()

    def test_chunked_export_vault_path_skips_full_base64_join(self):
        utils = make_utils(retain_chunked_base64=False)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=chunked_export_output())
            result = utils.get_job_output(JOB_ID)
        assert "eml" not in result
        assert result["_eml_bytes"] == EML_RAW

    def test_chunked_export_inline_cap_rejected_before_join(self, monkeypatch):
        import ms_quarantine_for_splunk_soar_utils as utils_mod

        monkeypatch.setattr(
            utils_mod, "MAX_INLINE_DECODED_EML_BYTES", len(EML_RAW) - 1
        )
        utils = make_utils(retain_chunked_base64=True)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=chunked_export_output())
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "export_mode=vault" in str(exc_info.value)

    def test_chunked_export_ignores_output_order(self):
        utils = make_utils()
        lines = chunked_export_output().splitlines()
        output = "\n".join(list(reversed(lines[:-1])) + [lines[-1]])
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            result = utils.get_job_output(JOB_ID)
        assert result["eml"] == EML_B64

    def test_chunked_export_missing_complete_raises(self):
        utils = make_utils()
        output = "\n".join(chunked_export_output().splitlines()[:-1])
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "chunked_complete" in str(exc_info.value)

    def test_chunked_export_missing_chunk_raises(self):
        utils = make_utils()
        lines = chunked_export_output().splitlines()
        output = "\n".join(lines[:1] + lines[2:])
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "expected" in str(exc_info.value).lower()

    def test_chunked_export_duplicate_chunk_raises(self):
        utils = make_utils()
        lines = chunked_export_output().splitlines()
        lines[1] = lines[0]
        output = "\n".join(lines)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "duplicate" in str(exc_info.value).lower()

    def test_chunked_export_identity_mismatch_raises(self):
        utils = make_utils()
        lines = chunked_export_output().splitlines()
        bad = json.loads(lines[0])
        bad["identity"] = (
            r"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            r"\bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        )
        lines[0] = json.dumps(bad)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text="\n".join(lines))
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "identity mismatch" in str(exc_info.value).lower()

    def test_chunked_export_length_mismatch_raises(self):
        utils = make_utils()
        output = chunked_export_output(length=len(EML_B64) + 1)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "length mismatch" in str(exc_info.value).lower()

    def test_chunked_export_sha256_mismatch_raises(self):
        utils = make_utils()
        output = chunked_export_output(sha256="0" * 64)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "sha256 mismatch" in str(exc_info.value).lower()

    def test_chunked_export_decoded_size_mismatch_raises(self):
        utils = make_utils()
        output = chunked_export_output(decoded_size=len(EML_RAW) + 1)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "decoded_size mismatch" in str(exc_info.value).lower()

    def test_chunked_export_old_runbook_version_rejected(self):
        utils = make_utils()
        lines = chunked_export_output().splitlines()
        trailer = json.loads(lines[-1])
        trailer["runbook_version"] = "3.1.1"
        lines[-1] = json.dumps(trailer)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text="\n".join(lines))
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "deploy the app and runbook together" in str(exc_info.value).lower()

    def test_chunked_export_error_record_raises_from_run_action(self):
        utils = make_utils()
        error_record = {
            "action": "export",
            "error": True,
            "message": "boom",
            **build_metadata(),
        }
        output = chunked_export_output() + "\n" + json.dumps(error_record)
        with req_mock.Mocker() as m:
            mock_full_flow_text(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("export", identity=IDENTITY)
        assert "boom" in str(exc_info.value)

    def test_oversized_export_raises_structured_error(self):
        utils = make_utils()
        output = {
            "action": "export",
            "error": True,
            "error_code": "export_oversized",
            "message": "Decoded EML exceeds the safety cap.",
            "details": {
                "identity": IDENTITY,
                "decoded_size": MAX_DECODED_EML_BYTES + 1,
                "max_decoded_size": MAX_DECODED_EML_BYTES,
                "handling": "fail_closed",
            },
            "runbook_version": RUNBOOK_VERSION,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(OversizedExportError) as exc_info:
                utils.run_action("export", identity=IDENTITY)
        assert exc_info.value.identity == IDENTITY
        assert exc_info.value.decoded_size == MAX_DECODED_EML_BYTES + 1
        assert exc_info.value.max_decoded_size == MAX_DECODED_EML_BYTES

    def test_failed_job_with_oversized_output_raises_structured_error(self):
        utils = make_utils()
        output = {
            "action": "export",
            "error": True,
            "error_code": "export_oversized",
            "message": "Decoded EML exceeds the safety cap.",
            "details": {
                "identity": IDENTITY,
                "decoded_size": MAX_DECODED_EML_BYTES + 1,
                "max_decoded_size": MAX_DECODED_EML_BYTES,
                "handling": "fail_closed",
            },
            "runbook_version": RUNBOOK_VERSION,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output, status="Failed")
            with pytest.raises(OversizedExportError) as exc_info:
                utils.run_action("export", identity=IDENTITY)
        assert exc_info.value.identity == IDENTITY
        assert exc_info.value.decoded_size == MAX_DECODED_EML_BYTES + 1

    def test_failed_job_without_structured_output_stays_job_failure(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            mock_full_flow_text(m, "PowerShell crashed", status="Failed")
            with pytest.raises(JobFailedError) as exc_info:
                utils.run_action("export", identity=IDENTITY)
        assert "structured job output was unavailable" in str(exc_info.value)

    def test_failed_job_with_success_output_stays_job_failure(self):
        utils = make_utils()
        output = {
            "action": "export",
            "identity": IDENTITY,
            "eml": EML_B64,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output, status="Failed")
            with pytest.raises(JobFailedError):
                utils.run_action("export", identity=IDENTITY)

    @pytest.mark.parametrize("field,value", [
        ("identity", "00000000-0000-0000-0000-000000000000\\"
                     "00000000-0000-0000-0000-000000000000"),
        ("handling", "retry"),
        ("decoded_size", MAX_DECODED_EML_BYTES),
        ("max_decoded_size", MAX_DECODED_EML_BYTES + 2),
    ])
    def test_oversized_error_metadata_is_validated(self, field, value):
        utils = make_utils()
        details = {
            "identity": IDENTITY,
            "decoded_size": MAX_DECODED_EML_BYTES + 1,
            "max_decoded_size": MAX_DECODED_EML_BYTES,
            "handling": "fail_closed",
        }
        details[field] = value
        output = {
            "action": "export",
            "error": True,
            "error_code": "export_oversized",
            "message": "Decoded EML exceeds the safety cap.",
            "details": details,
            "runbook_version": RUNBOOK_VERSION,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output, status="Failed")
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("export", identity=IDENTITY)
        assert "protocol error" in str(exc_info.value).lower()

    def test_structured_error_action_must_match_request(self):
        utils = make_utils()
        output = {
            "action": "list",
            "error": True,
            "message": "wrong action",
            "runbook_version": RUNBOOK_VERSION,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output, status="Failed")
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("export", identity=IDENTITY)
        assert "does not match requested action" in str(exc_info.value)

    def test_structured_error_flag_must_be_boolean(self):
        utils = make_utils()
        output = {
            "action": "export",
            "error": "true",
            "message": "wrong type",
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("export", identity=IDENTITY)
        assert "must be a boolean" in str(exc_info.value)

    def test_chunked_export_noise_ignored(self):
        utils = make_utils()
        output = (
            "VERBOSE: connecting\n"
            "{not really json\n"
            + chunked_export_output()
        )
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=output)
            result = utils.get_job_output(JOB_ID)
        assert result["eml"] == EML_B64

    def test_chunked_export_size_cap_raises(self, monkeypatch):
        import ms_quarantine_for_splunk_soar_utils as utils_mod

        monkeypatch.setattr(
            utils_mod, "MAX_DECODED_EML_BYTES", len(EML_RAW) - 1
        )
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=chunked_export_output())
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "maximum" in str(exc_info.value).lower()

    def test_azure_stream_limit_message_has_actionable_error(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=AZURE_STREAM_LIMIT_MESSAGE)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "3.3.4 runbook" in str(exc_info.value)

    def test_list_stream_limit_message_is_action_specific(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=AZURE_STREAM_LIMIT_MESSAGE)
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID, action="list")
        message = str(exc_info.value)
        assert "list output record" in message
        assert "export chunking does not repair list output" in message

    def test_json_array_output_rejected(self):
        utils = make_utils()
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_output_url(), text=json.dumps([{"action": "list"}]))
            with pytest.raises(AutomationError) as exc_info:
                utils.get_job_output(JOB_ID)
        assert "must be an object" in str(exc_info.value)

    @pytest.mark.parametrize("action,identity,output", [
        ("list", None, {
            "action": "list", "count": 0, "messages": [],
        }),
        ("export", IDENTITY, {
            "action": "export", "identity": IDENTITY, "eml": EML_B64,
        }),
        ("release", IDENTITY, {
            "action": "release", "identity": IDENTITY, "status": "released",
        }),
        ("deny", IDENTITY, {
            "action": "deny", "identity": IDENTITY, "status": "denied",
        }),
    ])
    def test_current_version_is_required_for_every_action(
        self, action, identity, output
    ):
        utils = make_utils()
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            result = utils.run_action(action, identity=identity)
        assert result["runbook_version"] == RUNBOOK_VERSION

    @pytest.mark.parametrize(
        "action,business_status",
        [("release", "released"), ("deny", "denied")],
    )
    def test_irreversible_success_requires_exchange_postcondition(
        self, action, business_status
    ):
        utils = make_utils()
        output = {
            "action": action,
            "identity": IDENTITY,
            "status": business_status,
            **disposition_diagnostics(action=action),
        }
        with req_mock.Mocker() as m:
            mock_full_flow(
                m,
                output,
                include_postcondition=False,
            )
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action(action, identity=IDENTITY)
        assert "verification_method" in str(exc_info.value)

    def test_confirmed_release_accepts_cmdlet_metadata_error_fallback(self):
        utils = make_utils()
        output = {
            "action": "release",
            "identity": IDENTITY,
            "status": "released",
            "verification_method": "Get-QuarantineMessage",
            "expected_release_status": "Released",
            "observed_release_status": "Released",
            "observed_identity": IDENTITY,
            "observed_release_status_history": "Requested -> Released",
            "verification_attempts": 1,
            "last_verification_error": "",
            "precondition_trace": PRECONDITION_TRACE,
            "postcondition_trace": POSTCONDITION_TRACE,
            **disposition_diagnostics(),
        }
        output.update(static_diagnostics_with_metadata_error())
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            result = utils.run_action("release", identity=IDENTITY)
        assert result["status"] == "released"
        assert result["cmdlet_command_type"] == ""
        assert result["cmdlet_metadata_error"]

    def test_generic_diagnose_failure_surfaces_original_message(self):
        utils = make_utils()
        output = {
            "action": "diagnose",
            "error": True,
            "message": (
                "Failed to connect to Exchange Online: AADSTS700016"
            ),
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(RunbookActionError) as exc_info:
                utils.run_action("diagnose", identity=IDENTITY)
        message = str(exc_info.value)
        assert "AADSTS700016" in message
        assert "protocol error" not in message.lower()

    @pytest.mark.parametrize(
        "field,value,expected_message",
        [
            ("expected_release_status", "Denied", "expected Exchange"),
            ("observed_release_status", "Requested", "postcondition"),
            ("observed_identity", IDENTITY + "0", "observed_identity"),
            (
                "observed_release_status_history",
                "Requested",
                "status history",
            ),
            ("verification_attempts", 0, "positive verification_attempts"),
            ("verification_method", "assumed", "verification_method"),
            (
                "last_verification_error",
                None,
                "last_verification_error",
            ),
            (
                "exchange_online_management_version",
                "",
                "exchange_online_management_version",
            ),
            ("cmdlet_warning", None, "cmdlet_warning"),
        ],
    )
    def test_release_success_rejects_invalid_postcondition_evidence(
        self, field, value, expected_message
    ):
        utils = make_utils()
        output = {
            "action": "release",
            "identity": IDENTITY,
            "status": "released",
            "verification_method": "Get-QuarantineMessage",
            "expected_release_status": "Released",
            "observed_release_status": "Released",
            "observed_identity": IDENTITY,
            "observed_release_status_history": "Released",
            "verification_attempts": 1,
            "last_verification_error": "",
            "exchange_online_management_version": "3.5.0",
            "cmdlet_warning": "",
            "cmdlet_information": "",
            "cmdlet_verbose": "",
            "cmdlet_error": "",
        }
        output[field] = value
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("release", identity=IDENTITY)
        assert expected_message in str(exc_info.value)

    def test_release_success_preserves_long_cmdlet_warning(self):
        utils = make_utils()
        native_warning = "x" * 4096
        output = {
            "action": "release",
            "identity": IDENTITY,
            "status": "released",
            "verification_method": "Get-QuarantineMessage",
            "expected_release_status": "Released",
            "observed_release_status": "Released",
            "observed_identity": IDENTITY,
            "observed_release_status_history": "Released",
            "verification_attempts": 1,
            "last_verification_error": "",
            "exchange_online_management_version": "3.5.0",
            "cmdlet_warning": native_warning,
            "cmdlet_information": "",
            "cmdlet_verbose": "",
            "cmdlet_error": "",
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            result = utils.run_action("release", identity=IDENTITY)
        assert result["cmdlet_warning"] == native_warning

    def test_postcondition_unconfirmed_is_a_validated_action_error(self):
        utils = make_utils()
        output = postcondition_error_output()
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(RunbookActionError) as exc_info:
                utils.run_action("release", identity=IDENTITY)
        assert exc_info.value.result["error_code"] == (
            "postcondition_unconfirmed"
        )

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_disposition_rejected_is_a_validated_action_error(self, action):
        utils = make_utils()
        output = disposition_rejected_output(action)
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(RunbookActionError) as exc_info:
                utils.run_action(action, identity=IDENTITY)
        assert exc_info.value.result["error_code"] == "disposition_rejected"

    @pytest.mark.parametrize(
        "field,value,expected_message",
        [
            ("observed_release_status", "Approved", "exact unchanged"),
            ("observed_identity", IDENTITY + "0", "exact observed_identity"),
            ("verification_attempts", 2, "between three and twenty"),
            ("verification_method", "assumed", "verification_method"),
            ("handling", "reconcile_before_retry", "manual_review"),
            ("last_verification_error", "timeout", "read error"),
            ("observed_release_status_history", "Requested -> Approved", "history"),
            ("cmdlet_error", "", "rejection evidence"),
        ],
    )
    def test_disposition_rejected_rejects_malformed_details(
        self,
        field,
        value,
        expected_message,
    ):
        utils = make_utils()
        output = disposition_rejected_output()
        if field == "cmdlet_error":
            for evidence_field in (
                "cmdlet_error",
                "cmdlet_fully_qualified_error_id",
                "cmdlet_error_category",
                "cmdlet_error_details",
            ):
                output["details"][evidence_field] = ""
        else:
            output["details"][field] = value
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("release", identity=IDENTITY)
        assert expected_message in str(exc_info.value)

    def test_disposition_rejected_rejects_intermediate_read_error(self):
        utils = make_utils()
        output = disposition_rejected_output()
        trace = json.loads(output["details"]["postcondition_trace"])
        trace[1].update({
            "result_count": 0,
            "observed_identity": "",
            "observed_release_status": "",
            "exact_identity_match": False,
            "error": "Transient Exchange read error.",
        })
        output["details"]["postcondition_trace"] = json.dumps(
            trace,
            separators=(",", ":"),
        )
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("release", identity=IDENTITY)
        assert "declared number of exact, error-free Requested" in str(
            exc_info.value
        )

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_precondition_unconfirmed_is_a_validated_disposition_error(
        self, action
    ):
        utils = make_utils()
        output = precondition_error_output(action=action)
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(RunbookActionError) as exc_info:
                utils.run_action(action, identity=IDENTITY)
        assert exc_info.value.result["error_code"] == (
            "precondition_unconfirmed"
        )

    @pytest.mark.parametrize(
        "field,value,expected_message",
        [
            ("expected_release_status", "Released", "Requested"),
            ("observed_release_status", None, "observed_release_status"),
            ("observed_identity", None, "observed_identity"),
            (
                "observed_release_status_history",
                None,
                "observed_release_status_history",
            ),
            ("verification_attempts", 2, "exactly one"),
            ("verification_method", "assumed", "verification_method"),
            ("last_verification_error", None, "last_verification_error"),
            ("handling", "retry", "manual_review"),
            (
                "exchange_online_management_version",
                "",
                "exchange_online_management_version",
            ),
        ],
    )
    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_precondition_unconfirmed_rejects_malformed_details(
        self, action, field, value, expected_message
    ):
        utils = make_utils()
        output = precondition_error_output(action=action)
        output["details"][field] = value
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action(action, identity=IDENTITY)
        assert expected_message in str(exc_info.value)

    @pytest.mark.parametrize(
        "field,value,expected_message",
        [
            ("expected_release_status", "Denied", "expected Exchange"),
            ("observed_release_status", None, "observed_release_status"),
            ("observed_identity", None, "observed_identity"),
            (
                "observed_release_status_history",
                None,
                "observed_release_status_history",
            ),
            ("verification_attempts", 0, "positive verification_attempts"),
            ("verification_method", "assumed", "verification_method"),
            (
                "last_verification_error",
                None,
                "last_verification_error",
            ),
            (
                "exchange_online_management_version",
                "",
                "exchange_online_management_version",
            ),
            ("cmdlet_verbose", None, "cmdlet_verbose"),
            ("handling", "retry", "reconcile_before_retry"),
        ],
    )
    def test_postcondition_unconfirmed_rejects_malformed_details(
        self, field, value, expected_message
    ):
        utils = make_utils()
        output = postcondition_error_output()
        output["details"][field] = value
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("release", identity=IDENTITY)
        assert expected_message in str(exc_info.value)

    @pytest.mark.parametrize("action,identity,output", [
        ("list", None, {
            "action": "list", "count": 0, "messages": [],
        }),
        ("export", IDENTITY, {
            "action": "export", "identity": IDENTITY, "eml": EML_B64,
        }),
        ("release", IDENTITY, {
            "action": "release", "identity": IDENTITY, "status": "released",
        }),
        ("deny", IDENTITY, {
            "action": "deny", "identity": IDENTITY, "status": "denied",
        }),
    ])
    def test_old_version_is_rejected_for_every_action(
        self, action, identity, output
    ):
        utils = make_utils()
        output = dict(output, runbook_version="3.3.2")
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action(action, identity=identity)
        message = str(exc_info.value)
        assert "requires runbook 3.3.4 or newer" in message
        assert "received 3.3.2" in message

    def test_missing_version_is_rejected(self):
        utils = make_utils()
        output = {"action": "list", "count": 0, "messages": []}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output, include_version=False)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("list")
        assert "missing required field 'runbook_version'" in str(exc_info.value)

    @pytest.mark.parametrize("version", ["3.1", "v3.3.4", "3.3.4.0", "x"])
    def test_malformed_version_is_rejected(self, version):
        utils = make_utils()
        output = {
            "action": "list",
            "count": 0,
            "messages": [],
            "runbook_version": version,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("list")
        assert "must use semantic versioning" in str(exc_info.value)

    def test_higher_version_is_accepted(self):
        utils = make_utils()
        output = {
            "action": "list",
            "count": 0,
            "messages": [],
            "runbook_version": "3.3.4",
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            result = utils.run_action("list")
        assert result["runbook_version"] == "3.3.4"

    def test_success_action_must_match_request(self):
        utils = make_utils()
        output = {"action": "deny", "identity": IDENTITY, "status": "denied"}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("release", identity=IDENTITY)
        assert "does not match requested action" in str(exc_info.value)

    @pytest.mark.parametrize("action,status", [
        ("export", None),
        ("release", "released"),
        ("deny", "denied"),
    ])
    def test_success_identity_must_match_request(self, action, status):
        utils = make_utils()
        output = {
            "action": action,
            "identity": (
                "00000000-0000-0000-0000-000000000000\\"
                "11111111-1111-1111-1111-111111111111"
            ),
        }
        if action == "export":
            output["eml"] = EML_B64
        else:
            output["status"] = status
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action(action, identity=IDENTITY)
        assert "identity does not match" in str(exc_info.value)

    def test_structured_error_requires_current_version(self):
        utils = make_utils()
        output = {
            "action": "list",
            "error": True,
            "message": "application error",
            "runbook_version": "3.3.1",
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output, status="Failed")
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("list")
        assert "requires runbook 3.3.4 or newer" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestConnectivity
# ---------------------------------------------------------------------------

class TestConnectivity:

    def test_connectivity_success(self):
        c = make_connector()
        output = {"action": "list", "count": 0, "messages": []}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_test_connectivity({}) == APP_SUCCESS

    def test_connectivity_token_failure(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, status_code=401, json={"error_description": "bad"})
            assert c._handle_test_connectivity({}) == APP_ERROR
        assert "token" in ar.get_message().lower() or "401" in ar.get_message()

    def test_connectivity_webhook_failure(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.post(WEBHOOK_URL, status_code=404)
            assert c._handle_test_connectivity({}) == APP_ERROR

    def test_connectivity_detects_runbook_error(self):
        """Job completes but runbook reports error:true (e.g. missing EXO role)."""
        c = make_connector()
        ar = patch_ar(c)
        error_output = {
            "action": "list", "error": True,
            "message": "Failed to connect to Exchange Online: Unauthorized"
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, error_output)
            assert c._handle_test_connectivity({}) == APP_ERROR
        # Should distinguish connectivity permission from operational RBAC.
        assert "Exchange.ManageAsApp" in ar.get_message()
        assert "operational" in ar.get_message()

    def test_connectivity_success_clears_error_check(self):
        """Valid empty list output passes connectivity."""
        c = make_connector()
        ar = patch_ar(c)
        good_output = {"action": "list", "count": 0, "messages": []}
        with req_mock.Mocker() as m:
            mock_full_flow(m, good_output)
            assert c._handle_test_connectivity({}) == APP_SUCCESS

    def test_connectivity_403_job_poll_hint(self):
        """403 on job poll gives Automation Job Operator role hint."""
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            m.get(job_url(), status_code=403,
                  json={"error": {"code": "AuthorizationFailed"}})
            assert c._handle_test_connectivity({}) == APP_ERROR
        assert "Automation Job Operator" in ar.get_message()

    def test_connectivity_unexpected_output_format(self):
        """Empty dict output is caught as malformed."""
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, {})
            assert c._handle_test_connectivity({}) == APP_ERROR
        assert "unexpected output" in ar.get_message().lower()


# ---------------------------------------------------------------------------
# TestList
# ---------------------------------------------------------------------------

class TestList:

    @pytest.mark.parametrize(("value", "expected"), [
        ("user@contoso.com", "user@contoso.com"),
        ("  user@contoso.com  ", "user@contoso.com"),
        (["user@contoso.com"], "user@contoso.com"),
        (
            ["first@contoso.com", " second@contoso.com "],
            "first@contoso.com, second@contoso.com",
        ),
        ([], ""),
        ([None, "", "  "], ""),
        (None, ""),
    ])
    def test_normalize_recipient_address(self, value, expected):
        assert normalize_recipient_address(value) == expected

    @pytest.mark.parametrize("value", [
        {"address": "user@contoso.com"},
        7,
        ["user@contoso.com", {"address": "other@contoso.com"}],
    ])
    def test_normalize_recipient_address_rejects_structured_values(self, value):
        with pytest.raises(ValueError):
            normalize_recipient_address(value)

    def test_list_success(self):
        c = make_connector()
        output = {"action": "list", "count": 1, "messages": MOCK_MESSAGES}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_SUCCESS

    def test_list_data_added(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 1, "messages": MOCK_MESSAGES}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_list_quarantine_requests({})
        assert len(ar.get_data()) == 1

    def test_list_chunked_output_reaches_same_action_result_shape(self):
        c = make_connector()
        ar = patch_ar(c)
        second = dict(MOCK_MESSAGES[0], Subject="Second")
        output = chunked_list_output(
            messages=[MOCK_MESSAGES[0], second],
            groups=[[MOCK_MESSAGES[0]], [second]],
        )
        with req_mock.Mocker() as m:
            mock_full_flow_text(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_SUCCESS
        assert [item["Subject"] for item in ar.get_data()] == [
            "Invoice", "Second"
        ]
        assert ar.get_summary()["total_found"] == 2

    def test_list_required_fields(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 1, "messages": MOCK_MESSAGES}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_list_quarantine_requests({})
        row = ar.get_data()[0]
        for f in ["Identity", "SenderAddress", "RecipientAddress",
                  "Subject", "Type", "ReleaseStatus"]:
            assert f in row

    @pytest.mark.parametrize(("recipient_address", "expected"), [
        ("user@contoso.com", "user@contoso.com"),
        (["user@contoso.com"], "user@contoso.com"),
        (
            ["first@contoso.com", "second@contoso.com"],
            "first@contoso.com, second@contoso.com",
        ),
        ([], ""),
        (None, ""),
    ])
    def test_list_recipient_address_matches_manifest_string(
        self, recipient_address, expected
    ):
        c = make_connector()
        ar = patch_ar(c)
        message = dict(
            MOCK_MESSAGES[0],
            RecipientAddress=recipient_address,
        )
        output = {"action": "list", "count": 1, "messages": [message]}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_SUCCESS
        assert ar.get_data()[0]["RecipientAddress"] == expected
        assert isinstance(ar.get_data()[0]["RecipientAddress"], str)

    def test_list_invalid_recipient_address_fails_without_partial_data(self):
        c = make_connector()
        ar = patch_ar(c)
        valid = dict(MOCK_MESSAGES[0])
        invalid = dict(
            MOCK_MESSAGES[0],
            Identity=IDENTITY.replace("c14401cf", "d14401cf"),
            RecipientAddress={"address": "user@contoso.com"},
        )
        output = {
            "action": "list",
            "count": 2,
            "messages": [valid, invalid],
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert "RecipientAddress must be a string" in ar.get_message()
        assert ar.get_data() == []

    def test_list_summary_total(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 1, "messages": MOCK_MESSAGES}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_list_quarantine_requests({})
        assert ar.get_summary()["total_found"] == 1
        assert ar.get_summary()["max_results"] == LIST_DEFAULT_PAGE_SIZE
        assert ar.get_summary()["results_may_be_truncated"] is False

    def test_list_exact_limit_warns_about_possible_truncation(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 1, "messages": MOCK_MESSAGES}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests(
                {"max_results": 1}
            ) == APP_SUCCESS
        assert ar.get_summary() == {
            "total_found": 1,
            "max_results": 1,
            "results_may_be_truncated": True,
        }
        assert "results may be truncated at max_results=1" in ar.get_message()

    def test_list_empty(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 0, "messages": []}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_SUCCESS
        assert ar.get_summary()["total_found"] == 0

    def test_list_null_messages_is_empty(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 0, "messages": None}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_SUCCESS
        assert ar.get_summary()["total_found"] == 0

    def test_list_legacy_single_object_is_preserved(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 9, "messages": MOCK_MESSAGES[0]}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_SUCCESS
        assert len(ar.get_data()) == 1
        assert ar.get_summary()["total_found"] == 1
        assert ar.get_data()[0]["Identity"] == IDENTITY

    def test_list_scalar_messages_is_protocol_error(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 1, "messages": "not-an-array"}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert "'messages' must be an array" in ar.get_message()

    def test_list_non_object_item_is_protocol_error(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 1, "messages": ["not-an-object"]}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert "every 'messages' item must be an object" in ar.get_message()

    def test_list_count_mismatch_is_protocol_error(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": 2, "messages": MOCK_MESSAGES}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert "'count' does not match" in ar.get_message()

    def test_list_non_numeric_count_is_protocol_error(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "list", "count": "many", "messages": MOCK_MESSAGES}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_list_quarantine_requests({}) == APP_ERROR
        assert "'count' must be an integer" in ar.get_message()

    def test_list_job_failed(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            m.get(job_url(), json={"properties": {"status": "Failed"}})
            m.get(job_output_url(), text="PowerShell crashed")
            assert c._handle_list_quarantine_requests({}) == APP_ERROR

    @pytest.mark.parametrize("max_results", [1, 2, 25, 1000])
    def test_list_max_results_passed_to_webhook(self, max_results):
        """max_results must be forwarded as page_size in the webhook body."""
        c = make_connector()
        patch_ar(c)
        bodies = []
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            def webhook_cb(req, ctx):
                bodies.append(req.json())
                ctx.status_code = 200
                return {"JobIds": [JOB_ID]}
            m.post(WEBHOOK_URL, json=webhook_cb)
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(job_output_url(),
                  text=json.dumps({
                      "action": "list",
                      "count": 0,
                      "messages": [],
                      "runbook_version": RUNBOOK_VERSION,
                  }))
            c._handle_list_quarantine_requests({
                "max_results": max_results,
            })
        assert bodies[0]["page_size"] == max_results

    def test_list_max_results_too_high_rejected(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_list_quarantine_requests(
                {"max_results": 5000}) == APP_ERROR
        assert "1000" in ar.get_message()

    def test_list_max_results_zero_rejected(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_list_quarantine_requests(
                {"max_results": 0}) == APP_ERROR

    def test_list_max_results_non_numeric_rejected(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_list_quarantine_requests(
                {"max_results": "abc"}) == APP_ERROR

    @pytest.mark.parametrize("param", [{}, {"max_results": None}])
    def test_list_without_max_results_works(self, param):
        """The app sends its default even without SOAR manifest injection."""
        c = make_connector()
        ar = patch_ar(c)
        bodies = []
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            def webhook_cb(req, ctx):
                bodies.append(req.json())
                ctx.status_code = 200
                return {"JobIds": [JOB_ID]}
            m.post(WEBHOOK_URL, json=webhook_cb)
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(job_output_url(), text=json.dumps({
                "action": "list",
                "count": 0,
                "messages": [],
                **build_metadata(),
            }))
            assert c._handle_list_quarantine_requests(param) == APP_SUCCESS
        assert bodies[0]["page_size"] == 2
        assert ar.get_summary()["max_results"] == 2
        manifest = json.loads((Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text())
        assert all(item["identifier"] != "list_quarantine_requests" for item in manifest["actions"])


# ---------------------------------------------------------------------------
# TestOnPoll
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# TestExportVaultMode
# ---------------------------------------------------------------------------

class TestExportVaultMode:

    def test_oversized_export_fails_closed_without_vault_import(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {
            "action": "export",
            "error": True,
            "error_code": "export_oversized",
            "message": "Decoded EML exceeds the safety cap.",
            "details": {
                "identity": IDENTITY,
                "decoded_size": MAX_DECODED_EML_BYTES + 1,
                "max_decoded_size": MAX_DECODED_EML_BYTES,
                "handling": "fail_closed",
            },
            "runbook_version": RUNBOOK_VERSION,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}
            ) == APP_ERROR
        assert VAULT_ADDS == []
        assert ar.get_data() == [{
            "status": "oversized",
            "handling": "fail_closed",
            "identity": IDENTITY,
            "decoded_size": MAX_DECODED_EML_BYTES + 1,
            "max_decoded_size": MAX_DECODED_EML_BYTES,
        }]
        assert ar.get_summary()["status"] == "oversized"
        assert ar.get_summary()["handling"] == "fail_closed"
        assert "remains quarantined" in ar.get_message()

    def test_vault_success(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_vault_id_returned(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0].get("vault_id")

    def test_vault_hashes_correct(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        d = ar.get_data()[0]
        assert d["sha256"] == hashlib.sha256(EML_RAW).hexdigest()
        assert d["sha1"]   == hashlib.sha1(EML_RAW).hexdigest()
        assert d["md5"]    == hashlib.md5(EML_RAW).hexdigest()

    def test_legacy_hashes_are_explicitly_nonsecurity_for_fips(
        self,
        monkeypatch,
    ):
        calls = []
        original_md5 = hashlib.md5
        original_sha1 = hashlib.sha1

        def md5(data, **kwargs):
            calls.append(("md5", kwargs))
            return original_md5(data)

        def sha1(data, **kwargs):
            calls.append(("sha1", kwargs))
            return original_sha1(data)

        monkeypatch.setattr(hashlib, "md5", md5)
        monkeypatch.setattr(hashlib, "sha1", sha1)
        hashes = make_connector()._calculate_hashes(EML_RAW)
        assert hashes["sha256"] == hashlib.sha256(EML_RAW).hexdigest()
        assert calls == [
            ("md5", {"usedforsecurity": False}),
            ("sha1", {"usedforsecurity": False}),
        ]

    def test_vault_size_correct(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0]["size"] == len(EML_RAW)

    def test_vault_no_eml_in_data(self):
        """Vault mode must NOT include the raw base64 in action_result."""
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert "eml" not in ar.get_data()[0]

    def test_vault_called_once(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert len(VAULT_ADDS) == 1

    def test_vault_correct_bytes_stored(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert VAULT_ADDS[0]["content"] == EML_RAW

    def test_vault_metadata_identity(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert VAULT_ADDS[0]["metadata"]["identity"] == IDENTITY

    def test_vault_pascalcase_eml_accepted(self):
        """PowerShell returns 'Eml' not 'eml' – must be tolerated."""
        c = make_connector(export_mode=EXPORT_VAULT)
        output = {"action": "export", "identity": IDENTITY, "Eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS
        assert len(VAULT_ADDS) == 1

    def test_vault_summary_mode(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_summary()["export_mode"] == EXPORT_VAULT

    def test_vault_chunked_export_success(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow_text(m, chunked_export_output())
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS
        assert ar.get_data()[0]["sha256"] == hashlib.sha256(EML_RAW).hexdigest()
        assert VAULT_ADDS[0]["content"] == EML_RAW

    def test_vault_invalid_base64_rejected(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": "not-base64!"}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_ERROR
        assert "invalid base64" in ar.get_message().lower()

    def test_vault_base64_whitespace_tolerated(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        spaced = EML_B64[:8] + "\n" + EML_B64[8:]
        output = {"action": "export", "identity": IDENTITY, "eml": spaced}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS
        assert VAULT_ADDS[0]["content"] == EML_RAW

    def test_vault_decoded_size_cap_rejected(self, monkeypatch):
        import ms_quarantine_for_splunk_soar_connector as connector_mod

        monkeypatch.setattr(
            connector_mod, "MAX_DECODED_EML_BYTES", len(EML_RAW) - 1
        )
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_ERROR
        assert "supported maximum" in ar.get_message().lower()


# ---------------------------------------------------------------------------
# TestExportInlineMode
# ---------------------------------------------------------------------------

class TestExportInlineMode:

    def test_inline_success(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_inline_eml_returned(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0]["eml"] == EML_B64

    def test_inline_no_vault_call(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert len(VAULT_ADDS) == 0

    def test_inline_hashes_present(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        d = ar.get_data()[0]
        assert d.get("sha256") == hashlib.sha256(EML_RAW).hexdigest()

    def test_inline_summary_mode(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": EML_B64}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_summary()["export_mode"] == EXPORT_INLINE


# ---------------------------------------------------------------------------
# TestEmailArtifactCreation
# ---------------------------------------------------------------------------

class TestEmailArtifactCreation:

    @staticmethod
    def _run(
        params=None,
        export_mode=EXPORT_VAULT,
        eml_b64=ARTIFACT_EML_B64,
        config_overrides=None,
    ):
        c = make_connector(
            export_mode=export_mode,
            config_overrides=config_overrides,
        )
        ar = patch_ar(c)
        action_params = {"identity": IDENTITY}
        action_params.update(params or {})
        output = {
            "action": "export",
            "identity": IDENTITY,
            "eml": eml_b64,
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            status = c._handle_get_quarantine_message(action_params)
        return c, ar, status

    def test_artifacts_are_disabled_by_default(self):
        _c, ar, status = self._run()
        assert status == APP_SUCCESS
        assert ARTIFACT_ADDS == []
        assert "artifact_created" not in ar.get_data()[0]

    def test_asset_policy_creates_default_combined_artifact(self):
        _c, ar, status = self._run(
            config_overrides=artifact_asset_config(enabled=True),
        )
        assert status == APP_SUCCESS
        assert len(ARTIFACT_ADDS) == 1
        assert ar.get_data()[0]["artifact_layout"] == (
            ARTIFACT_LAYOUT_COMBINED
        )
        assert ar.get_data()[0]["artifact_fields"] == ",".join(
            DEFAULT_ARTIFACT_FIELDS
        )

    def test_asset_policy_selects_fields_and_separate_layout(self):
        _c, ar, status = self._run(
            config_overrides=artifact_asset_config(
                enabled=True,
                layout=ARTIFACT_LAYOUT_SEPARATE,
                fields={"to", "subject"},
            ),
        )
        assert status == APP_SUCCESS
        assert len(ARTIFACT_ADDS) == 3
        assert ar.get_data()[0]["artifact_layout"] == (
            ARTIFACT_LAYOUT_SEPARATE
        )
        assert ar.get_data()[0]["artifact_fields"] == "to,subject"

    def test_explicit_legacy_false_overrides_enabled_asset_policy(self):
        _c, ar, status = self._run(
            params={"create_email_artifacts": False},
            config_overrides=artifact_asset_config(enabled=True),
        )
        assert status == APP_SUCCESS
        assert ARTIFACT_ADDS == []
        assert "artifact_created" not in ar.get_data()[0]

    def test_legacy_action_policy_overrides_disabled_asset_policy(self):
        _c, ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_layout": "separate",
            "artifact_fields": "to,subject",
        })
        assert status == APP_SUCCESS
        assert len(ARTIFACT_ADDS) == 3
        assert ar.get_data()[0]["artifact_layout"] == (
            ARTIFACT_LAYOUT_SEPARATE
        )
        assert ar.get_data()[0]["artifact_fields"] == "to,subject"

    def test_legacy_layout_without_enable_preserves_disabled_behavior(self):
        _c, ar, status = self._run(
            params={"artifact_layout": "separate"},
            config_overrides=artifact_asset_config(enabled=True),
        )
        assert status == APP_SUCCESS
        assert ARTIFACT_ADDS == []
        assert "artifact_created" not in ar.get_data()[0]

    def test_explicit_false_preserves_legacy_output_and_ignores_other_options(self):
        _c, ar, status = self._run({
            "create_email_artifacts": False,
            "artifact_layout": "invalid",
            "artifact_fields": "not_a_field",
        })
        assert status == APP_SUCCESS
        assert ARTIFACT_ADDS == []
        assert set(ar.get_data()[0]) == {
            "vault_id",
            "file_name",
            "size",
            "md5",
            "sha1",
            "sha256",
        }

    def test_combined_default_fields_create_one_artifact(self):
        _c, ar, status = self._run({
            "create_email_artifacts": True,
        })
        assert status == APP_SUCCESS
        assert len(ARTIFACT_ADDS) == 1
        artifact = ARTIFACT_ADDS[0]
        assert artifact["container"] == 1
        assert artifact["label"] == "email"
        assert artifact["artifact_type"] == "email"
        assert artifact["severity"] == "low"
        assert artifact["run_automation"] is False
        assert artifact["cef_data"]["fromEmail"] == "alice@example.com"
        assert artifact["cef_data"]["toEmail"] == [
            "bob@example.com",
            "carol@example.com",
        ]
        assert artifact["cef_data"]["emailSubject"] == "Prüfung"
        assert (
            artifact["cef_data"]["emailMessageId"]
            == "<message-123@example.com>"
        )
        assert (
            artifact["cef_data"]["emailDateRaw"]
            == "Tue, 28 Jul 2026 14:34:56 +0200"
        )
        assert (
            artifact["cef_data"]["emailDate"]
            == "2026-07-28T14:34:56+02:00"
        )
        row = ar.get_data()[0]
        assert row["artifact_created"] is True
        assert row["artifact_count"] == 1
        assert row["artifact_layout"] == ARTIFACT_LAYOUT_COMBINED
        assert row["artifact_fields"] == ",".join(DEFAULT_ARTIFACT_FIELDS)
        assert row["missing_artifact_fields"] == ""
        assert ar.get_summary()["artifact_count"] == 1

    def test_combined_artifact_keeps_correlation_in_raw_data(self):
        _c, _ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_fields": "subject",
        })
        assert status == APP_SUCCESS
        raw = ARTIFACT_ADDS[0]["raw_data"]
        assert raw["quarantine_identity"] == IDENTITY
        assert raw["container_id"] == 1
        assert raw["vault_id"] == VAULT_ADDS[0]["vault_id"]
        assert raw["eml_sha256"] == hashlib.sha256(
            ARTIFACT_EML_RAW
        ).hexdigest()

    def test_separate_layout_creates_one_artifact_per_value(self):
        _c, ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_layout": "separate",
            "artifact_fields": "to,subject,email_date",
        })
        assert status == APP_SUCCESS
        assert len(ARTIFACT_ADDS) == 4
        cef_rows = [artifact["cef_data"] for artifact in ARTIFACT_ADDS]
        assert {"toEmail": "bob@example.com"} in cef_rows
        assert {"toEmail": "carol@example.com"} in cef_rows
        assert {"emailSubject": "Prüfung"} in cef_rows
        assert {
            "emailDateRaw": "Tue, 28 Jul 2026 14:34:56 +0200",
            "emailDate": "2026-07-28T14:34:56+02:00",
        } in cef_rows
        assert ar.get_data()[0]["artifact_count"] == 4
        assert (
            ar.get_data()[0]["artifact_layout"]
            == ARTIFACT_LAYOUT_SEPARATE
        )

    def test_all_fields_include_topmost_received_date(self):
        _c, ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_fields": "all",
        })
        assert status == APP_SUCCESS
        cef = ARTIFACT_ADDS[0]["cef_data"]
        assert cef["senderAddress"] == "sender@example.com"
        assert cef["recipientAddress"] == "envelope@example.com"
        assert cef["replyToEmail"] == "replies@example.com"
        assert cef["ccEmail"] == "security@example.com"
        assert (
            cef["receivedDateRaw"]
            == "Tue, 28 Jul 2026 14:35:10 +0200"
        )
        assert cef["receivedDate"] == "2026-07-28T14:35:10+02:00"
        assert ar.get_data()[0]["artifact_fields"] == ",".join(
            ARTIFACT_FIELD_ORDER
        )

    def test_missing_selected_headers_are_reported_without_failure(self):
        minimal = base64.b64encode(
            b"From: sender@example.com\r\n\r\nBody"
        ).decode()
        _c, ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_fields": "from,to,cc,email_date",
        }, eml_b64=minimal)
        assert status == APP_SUCCESS
        assert len(ARTIFACT_ADDS) == 1
        assert ar.get_data()[0]["missing_artifact_fields"] == (
            "to,cc,email_date"
        )

    def test_date_without_timezone_keeps_raw_and_warns(self):
        no_timezone = base64.b64encode(
            b"Date: Tue, 28 Jul 2026 14:34:56\r\n"
            b"Subject: Test\r\n\r\nBody"
        ).decode()
        _c, ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_fields": "email_date",
        }, eml_b64=no_timezone)
        assert status == APP_SUCCESS
        cef = ARTIFACT_ADDS[0]["cef_data"]
        assert cef["emailDateRaw"] == "Tue, 28 Jul 2026 14:34:56"
        assert "emailDate" not in cef
        assert "no timezone" in ar.get_data()[0]["artifact_warnings"]

    @pytest.mark.parametrize(
        "params,expected",
        [
            (
                {
                    "create_email_artifacts": True,
                    "artifact_layout": "invalid",
                },
                "artifact_layout",
            ),
            (
                {
                    "create_email_artifacts": True,
                    "artifact_fields": "subject,unknown",
                },
                "unknown artifact field",
            ),
            (
                {
                    "create_email_artifacts": True,
                    "artifact_fields": "all,subject",
                },
                "all",
            ),
            (
                {"create_email_artifacts": "maybe"},
                "must be a boolean",
            ),
        ],
    )
    def test_invalid_artifact_options_fail_before_webhook(
        self, params, expected
    ):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_get_quarantine_message({
                "identity": IDENTITY,
                **params,
            }) == APP_ERROR
            assert m.request_history == []
        assert expected in ar.get_message().lower()
        assert ARTIFACT_ADDS == []

    def test_inline_mode_can_create_artifacts_without_vault(self):
        _c, ar, status = self._run(
            {
                "create_email_artifacts": True,
                "artifact_fields": "subject,vault_id",
            },
            export_mode=EXPORT_INLINE,
        )
        assert status == APP_SUCCESS
        assert VAULT_ADDS == []
        assert len(ARTIFACT_ADDS) == 1
        assert "vault_id" in ar.get_data()[0]["missing_artifact_fields"]
        assert "vault_id" not in ARTIFACT_ADDS[0]["raw_data"]

    def test_artifact_api_failure_fails_action_but_preserves_vault_evidence(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            phrules_stub,
            "add_artifact",
            lambda **_kwargs: (False, "database unavailable", None),
        )
        _c, ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_fields": "subject",
        })
        assert status == APP_ERROR
        assert len(VAULT_ADDS) == 1
        row = ar.get_data()[0]
        assert row["vault_id"] == VAULT_ADDS[0]["vault_id"]
        assert row["artifact_created"] is False
        assert "database unavailable" in row["artifact_error"]
        assert "stored in the Vault" in ar.get_message()

    def test_duplicate_artifact_with_existing_id_is_not_an_error(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            phrules_stub,
            "add_artifact",
            lambda **_kwargs: (False, "already exists", 777),
        )
        _c, ar, status = self._run({
            "create_email_artifacts": True,
            "artifact_fields": "subject",
        })
        assert status == APP_SUCCESS
        row = ar.get_data()[0]
        assert row["artifact_created"] is False
        assert row["artifact_count"] == 1
        assert row["artifact_ids"] == "777"

    def test_identifiers_are_deterministic_across_retries(self):
        params = {
            "create_email_artifacts": True,
            "artifact_layout": "separate",
            "artifact_fields": "to,subject",
        }
        self._run(params)
        first_identifiers = [
            artifact["identifier"] for artifact in ARTIFACT_ADDS
        ]
        ARTIFACT_ADDS.clear()
        self._run(params)
        second_identifiers = [
            artifact["identifier"] for artifact in ARTIFACT_ADDS
        ]
        assert first_identifiers == second_identifiers

    def test_field_parser_canonicalizes_order_and_duplicates(self):
        assert parse_artifact_fields("subject,from,subject,to") == (
            "from",
            "to",
            "subject",
        )


# ---------------------------------------------------------------------------
# TestInspectReleaseEnvironment
# ---------------------------------------------------------------------------

class TestInspectReleaseEnvironment:

    def test_default_inspection_skips_tenant_rbac_and_preserves_opt_in(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, diagnostic_identity_only_output())
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
            }) == APP_SUCCESS
            webhook_body = next(
                request.json()
                for request in m.request_history
                if request.url == WEBHOOK_URL
            )

        assert webhook_body["include_rbac"] is False
        assert ar.get_data()[0]["rbac_included"] is False
        assert ar.get_summary()["rbac_diagnostics_status"] == "not_requested"
        assert "managed_identity_resource_id" not in ar.get_data()[0]

    def test_full_inspection_sends_explicit_rbac_opt_in(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            mock_full_flow(m, diagnostic_success_output())
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
                "include_rbac": True,
            }) == APP_SUCCESS
            webhook_body = next(
                request.json()
                for request in m.request_history
                if request.url == WEBHOOK_URL
            )
        assert webhook_body["include_rbac"] is True

    def test_inspection_accepts_guid_case_variant_as_same_identity(self):
        c = make_connector()
        output = diagnostic_identity_only_output()
        output["observed_identity"] = IDENTITY.upper()
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
            }) == APP_SUCCESS

    def test_generic_runbook_failure_surfaces_root_cause(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {
            "action": "diagnose",
            "error": True,
            "message": (
                "Failed to connect to Exchange Online: AADSTS700016"
            ),
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
            }) == APP_ERROR
        assert "AADSTS700016" in ar.get_message()
        assert "protocol error" not in ar.get_message().lower()

    def test_structured_inspection_failure_preserves_diagnostics(self):
        c = make_connector()
        ar = patch_ar(c)
        details = {
            "identity": IDENTITY,
            "status": "inspection_failed",
            "inspected_at_utc": "2026-07-30T08:00:00.0000000Z",
            "result_count": 0,
            "observed_identity": "",
            "observed_release_status": "",
            "inspection_error": "Exchange read failed.",
            "handling": "read_only",
            "include_rbac": True,
            **static_diagnostics(),
            **rbac_diagnostics(),
        }
        output = {
            "action": "diagnose",
            "error": True,
            "error_code": "diagnostic_inspection_failed",
            "message": details["inspection_error"],
            "details": details,
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
                "include_rbac": True,
            }) == APP_ERROR
        assert ar.get_data()[0]["inspection_error"] == "Exchange read failed."
        assert ar.get_message() == details["inspection_error"]

    def test_success_exposes_compact_rbac_summary(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, diagnostic_success_output())
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
                "include_rbac": True,
            }) == APP_SUCCESS

        row = ar.get_data()[0]
        summary = ar.get_summary()
        assert row["permission_queries_read_only"] is True
        assert row["release_to_all_roles"] == "Quarantine"
        assert row["release_deny_roles"] == "Quarantine"
        assert row["service_principal_registered"] is True
        assert row["role_assignment_matches_identity"] is True
        assert summary["rbac_diagnostics_status"] == "complete"
        assert summary["quarantine_role_present"] is True
        assert summary["service_principal_registered"] is True
        assert summary["role_assignment_matches_identity"] is True
        assert summary["permission_query_error_count"] == 0
        assert "rbac=complete" in ar.get_message()

    def test_partial_rbac_diagnostics_are_preserved(self):
        c = make_connector()
        ar = patch_ar(c)
        record = diagnostic_success_output()
        record.update(rbac_diagnostics(
            status="partial",
            error_records=[{
                "query": "quarantine_role_assignments",
                "error": "The cmdlet is not available.",
                "exception_type": "CommandNotFoundException",
            }],
            membership_confirmed=False,
        ))
        record["service_principal_registered"] = False
        record["registered_service_principal_identity"] = ""
        record["registered_service_principal_app_id"] = ""
        record["registered_service_principal_object_id"] = ""

        output = {
            "action": "diagnose",
            "error": True,
            "error_code": "diagnostic_rbac_partial",
            "message": "The cmdlet is not available.",
            "details": record,
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
                "include_rbac": True,
            }) == APP_ERROR

        assert ar.get_summary()["rbac_diagnostics_status"] == "partial"
        assert ar.get_summary()["permission_query_error_count"] == 1
        assert ar.get_message() == "The cmdlet is not available."

    def test_truthful_bounded_permission_error_counts_are_accepted(self):
        record = diagnostic_success_output()
        retained = [
            {
                "query": f"query-{index}",
                "error": f"bounded error {index}",
                "exception_type": "RuntimeException",
            }
            for index in range(2)
        ]
        record.update({
            "rbac_diagnostics_status": "partial",
            "rbac_diagnostics_reason": (
                "one_or_more_permission_queries_failed"
            ),
            "permission_query_error_count": 5,
            "permission_query_error_retained_count": 2,
            "permission_query_error_dropped_count": 3,
            "permission_query_errors_truncated": True,
            "permission_query_errors": retained,
        })

        MSQuarantineForSplunkSOARUtils._validate_rbac_diagnostics(
            record,
            "bounded permission evidence",
        )

    def test_truncated_role_group_inspection_is_partial_and_unknown(self):
        record = diagnostic_success_output()
        record.update({
            "rbac_diagnostics_status": "partial",
            "rbac_diagnostics_reason": "role_group_inspection_truncated",
            "quarantine_role_groups": "",
            "matched_quarantine_role_groups": "",
            "quarantine_role_group_total_count": 25,
            "quarantine_role_group_inspected_count": 20,
            "quarantine_role_group_inspection_truncated": True,
            "quarantine_group_membership_confirmed": None,
            "quarantine_administrator_membership_confirmed": None,
            "role_assignment_matches_identity": None,
        })

        MSQuarantineForSplunkSOARUtils._validate_rbac_diagnostics(
            record,
            "truncated role-group evidence",
        )

    @pytest.mark.parametrize(
        "mutation,expected",
        [
            (
                lambda record: record.update(
                    quarantine_role_group_inspected_count=21,
                ),
                "invalid role-group inspection counts",
            ),
            (
                lambda record: record.update(
                    quarantine_group_membership_confirmed=False,
                ),
                "definitive negative RBAC evidence",
            ),
        ],
    )
    def test_malformed_truncated_role_group_evidence_is_rejected(
        self,
        mutation,
        expected,
    ):
        record = diagnostic_success_output()
        record.update({
            "rbac_diagnostics_status": "partial",
            "rbac_diagnostics_reason": "role_group_inspection_truncated",
            "quarantine_role_groups": "",
            "matched_quarantine_role_groups": "",
            "quarantine_role_group_total_count": 25,
            "quarantine_role_group_inspected_count": 20,
            "quarantine_role_group_inspection_truncated": True,
            "quarantine_group_membership_confirmed": None,
            "quarantine_administrator_membership_confirmed": None,
            "role_assignment_matches_identity": None,
        })
        mutation(record)

        with pytest.raises(AutomationError) as exc_info:
            MSQuarantineForSplunkSOARUtils._validate_rbac_diagnostics(
                record,
                "malformed truncated role-group evidence",
            )
        assert expected in str(exc_info.value)

    @pytest.mark.parametrize(
        "group_membership,direct_assignment,service_principal_registered",
        [
            (True, True, False),
            (False, True, True),
        ],
    )
    def test_valid_group_or_direct_assignment_evidence_is_accepted(
        self,
        group_membership,
        direct_assignment,
        service_principal_registered,
    ):
        utils = make_utils()
        output = diagnostic_success_output()
        output.update({
            "rbac_diagnostics_status": "partial",
            "quarantine_group_membership_confirmed": group_membership,
            "quarantine_administrator_membership_confirmed": (
                group_membership
            ),
            "matched_quarantine_role_groups": (
                "Quarantine Administrator" if group_membership else ""
            ),
            "quarantine_role_groups": (
                "Quarantine Administrator" if group_membership else ""
            ),
            "role_assignment_matches_identity": direct_assignment,
            "service_principal_registered": service_principal_registered,
            "registered_service_principal_identity": (
                "service-principal-ms_quarantine_for_splunk_soar"
                if service_principal_registered
                else ""
            ),
            "registered_service_principal_app_id": (
                "11111111-2222-3333-4444-555555555555"
                if service_principal_registered
                else ""
            ),
            "registered_service_principal_object_id": (
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                if service_principal_registered
                else ""
            ),
            "permission_query_error_count": 1,
            "permission_query_error_retained_count": 1,
            "permission_query_errors": [{
                "query": "exchange_service_principal",
                "error": "Lookup unavailable.",
                "exception_type": "RuntimeException",
            }],
        })
        output["rbac_diagnostics_reason"] = (
            "one_or_more_permission_queries_failed"
        )
        error_output = {
            "action": "diagnose",
            "error": True,
            "error_code": "diagnostic_rbac_partial",
            "message": "Tenant RBAC evaluation was incomplete.",
            "details": output,
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            mock_full_flow(m, error_output)
            with pytest.raises(RunbookActionError) as exc_info:
                utils.run_action(
                    "diagnose",
                    identity=IDENTITY,
                    include_rbac=True,
                )
        assert (
            exc_info.value.result["details"]["rbac_diagnostics_status"]
            == "partial"
        )

    def test_missing_rbac_cmdlets_fail_with_explicit_unknown_evidence(self):
        c = make_connector()
        ar = patch_ar(c)
        record = diagnostic_success_output()
        required = record["rbac_required_cmdlets"]
        missing_errors = [
            {
                "query": f"required_cmdlet.{cmdlet}",
                "cmdlet": cmdlet,
                "error": (
                    f"Required diagnostic cmdlet '{cmdlet}' is unavailable."
                ),
                "exception_type": (
                    "System.Management.Automation.CommandNotFoundException"
                ),
            }
            for cmdlet in required
        ]
        record.update({
            "status": "inspection_incomplete",
            "rbac_diagnostics_status": "not_evaluated",
            "rbac_diagnostics_reason": (
                "required_cmdlets_unavailable_in_current_exchange_session"
            ),
            "rbac_available_cmdlets": [],
            "missing_cmdlets": required,
            "missing_cmdlet_count": len(required),
            "quarantine_role_present": None,
            "service_principal_registered": None,
            "quarantine_role_group_total_count": 0,
            "quarantine_role_group_inspected_count": 0,
            "quarantine_role_group_inspection_truncated": False,
            "role_group_membership_evaluated": None,
            "quarantine_group_membership_confirmed": None,
            "quarantine_administrator_membership_confirmed": None,
            "role_assignment_matches_identity": None,
            "permission_query_error_count": len(missing_errors),
            "permission_query_error_retained_count": len(missing_errors),
            "permission_query_errors": missing_errors,
        })
        output = {
            "action": "diagnose",
            "error": True,
            "error_code": "diagnostic_rbac_not_evaluated",
            "message": (
                "Tenant RBAC was NOT EVALUATED. Required cmdlets missing: "
                + ", ".join(required)
            ),
            "details": record,
            **build_metadata(),
        }

        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_inspect_release_environment({
                "identity": IDENTITY,
                "include_rbac": True,
            }) == APP_ERROR

        row = ar.get_data()[0]
        summary = ar.get_summary()
        assert row["service_principal_registered"] is None
        assert row["quarantine_role_present"] is None
        assert row["role_assignment_matches_identity"] is None
        assert isinstance(row["permission_query_errors"], list)
        assert summary["rbac_diagnostics_status"] == "not_evaluated"
        assert summary["service_principal_registered_evaluation"] == (
            "not_evaluated"
        )
        assert "service_principal_registered" not in summary
        for cmdlet in required:
            assert cmdlet in ar.get_message()
        assert ar.get_message() == output["message"]

    @pytest.mark.parametrize(
        "mutation,expected",
        [
            (
                lambda record: record.update(
                    permission_query_error_count=1,
                ),
                "error count does not match",
            ),
            (
                lambda record: record.update(
                    managed_identity_app_id="not-a-guid",
                ),
                "invalid resolved identity",
            ),
            (
                lambda record: record.update(
                    quarantine_role_groups="",
                    matched_quarantine_role_groups="",
                ),
                "without supporting evidence",
            ),
            (
                lambda record: record.update(
                    quarantine_role_groups=(
                        "Quarantine Administrator | Unmatched Tenant Group"
                    ),
                ),
                "exposes unmatched role-group names",
            ),
            (
                lambda record: record.update(
                    registered_service_principal_app_id="",
                ),
                "registers a service principal without a valid",
            ),
            (
                lambda record: record.update(
                    registered_service_principal_object_id="not-a-guid",
                ),
                "registers a service principal without a valid",
            ),
        ],
    )
    def test_malformed_rbac_evidence_is_rejected(self, mutation, expected):
        utils = make_utils()
        output = diagnostic_success_output()
        mutation(output)
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            with pytest.raises(AutomationError) as exc_info:
                utils.run_action("diagnose", identity=IDENTITY)
        assert expected in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestRelease
# ---------------------------------------------------------------------------

class TestRelease:

    def test_release_success(self):
        c = make_connector()
        output = {"action": "release", "identity": IDENTITY, "status": "released",
                  "message": "Message released."}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_release_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_release_status_in_data(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "release", "identity": IDENTITY,
                  "status": "released", "message": "ok"}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_release_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0]["status"] == "released"

    def test_release_missing_identity(self):
        c = make_connector()
        patch_ar(c)
        assert c._handle_release_quarantine_message({"identity": ""}) == APP_ERROR

    def test_release_job_failed(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            m.get(job_url(), json={"properties": {"status": "Failed"}})
            m.get(job_output_url(), text="PowerShell crashed")
            assert c._handle_release_quarantine_message(
                {"identity": IDENTITY}) == APP_ERROR

    def test_release_timeout_is_unknown_outcome_without_second_webhook(self):
        c = make_connector()
        ar = patch_ar(c)
        webhook_calls = []
        with req_mock.Mocker() as m:
            mock_preflight_then_unfinished_operation(m, c, webhook_calls)
            assert c._handle_release_quarantine_message(
                {"identity": IDENTITY}
            ) == APP_ERROR

        assert [body["action"] for body in webhook_calls] == [
            "config_check", "release"
        ]
        row = ar.get_data()[0]
        assert row["status"] == "outcome_unknown"
        assert row["handling"] == "reconcile_before_retry"
        assert row["identity"] == IDENTITY
        assert row["azure_job_id"] == JOB_ID
        assert row["last_job_status"] == "unknown"
        assert ar.get_summary()["status"] == "outcome_unknown"
        assert "Do not retry blindly" in ar.get_message()


# ---------------------------------------------------------------------------
# TestDeny
# ---------------------------------------------------------------------------

class TestDeny:

    def test_deny_success(self):
        c = make_connector()
        output = {"action": "deny", "identity": IDENTITY, "status": "denied",
                  "message": "Denied."}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_deny_quarantine_release(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_deny_status_in_data(self):
        c = make_connector()
        ar = patch_ar(c)
        output = {"action": "deny", "identity": IDENTITY,
                  "status": "denied", "message": "ok"}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            c._handle_deny_quarantine_release({"identity": IDENTITY})
        assert ar.get_data()[0]["status"] == "denied"

    def test_deny_missing_identity(self):
        c = make_connector()
        patch_ar(c)
        assert c._handle_deny_quarantine_release({"identity": ""}) == APP_ERROR

    def test_deny_timeout_is_unknown_outcome_without_second_webhook(self):
        c = make_connector()
        ar = patch_ar(c)
        webhook_calls = []
        with req_mock.Mocker() as m:
            mock_preflight_then_unfinished_operation(m, c, webhook_calls)
            assert c._handle_deny_quarantine_release(
                {"identity": IDENTITY}
            ) == APP_ERROR

        assert [body["action"] for body in webhook_calls] == [
            "config_check", "deny"
        ]
        row = ar.get_data()[0]
        assert row["status"] == "outcome_unknown"
        assert row["handling"] == "reconcile_before_retry"
        assert row["identity"] == IDENTITY
        assert row["azure_job_id"] == JOB_ID
        assert row["last_job_status"] == "unknown"
        assert ar.get_summary()["status"] == "outcome_unknown"
        assert "Do not retry blindly" in ar.get_message()

    @pytest.mark.parametrize("identifier,handler_name", [
        ("release_quarantine_message", "_handle_release_quarantine_message"),
        ("deny_quarantine_release", "_handle_deny_quarantine_release"),
    ])
    def test_irreversible_timeout_datapaths_are_declared(
        self, identifier, handler_name
    ):
        c = make_connector(poll_timeout=0)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            assert getattr(c, handler_name)({"identity": IDENTITY}) == APP_ERROR

        actual_paths = action_result_paths(ar)
        declared_paths = manifest_action_paths(identifier)
        assert actual_paths <= declared_paths

    def test_runbook_uses_documented_release_and_request_deny_contracts(self):
        """Release uses Identity/ReleaseToAll; deny keeps plural ActionType."""
        from pathlib import Path

        runbook = (Path(__file__).resolve().parents[2] / "runbook" / "runbook.ps1").read_text()
        assert (
            "Release-QuarantineMessage `\n"
            "                    -Identity $Identity `\n"
            "                    -ReleaseToAll `"
        ) in runbook
        assert (
            "Release-QuarantineMessage `\n"
            "                    -Identities @($Identity) `\n"
            "                    -ActionType Deny `"
        ) in runbook
        assert '-Identity "000"' not in runbook
        # The release/deny state machine is shared; each action must still
        # bind its own Exchange ActionType and expected terminal status.
        flow = re.search(
            r"function Invoke-RequestedDisposition \{.*?"
            r"    \$precondition = Wait-QuarantinePostcondition",
            runbook,
            re.DOTALL,
        ).group(0)
        release_branch, deny_branch = flow.split("    } else {\n", 1)
        assert 'if ($Action -eq "release") {' in release_branch
        assert '$dispositionActionType = "Release"' in release_branch
        assert '$expectedStatus = "Released"' in release_branch
        assert '$completedStatus = "released"' in release_branch
        assert '$dispositionActionType = "Deny"' not in release_branch
        assert '$dispositionActionType = "Deny"' in deny_branch
        assert '$expectedStatus = "Denied"' in deny_branch
        assert '$completedStatus = "denied"' in deny_branch
        assert '$dispositionActionType = "Release"' not in deny_branch
        assert (
            "    $disposition = Invoke-QuarantineDisposition `\n"
            "        -Identity $identity `\n"
            "        -ActionType $dispositionActionType\n"
        ) in runbook
        assert (
            "    $verification = Wait-QuarantinePostcondition `\n"
            "        -Identity $identity `\n"
            "        -ExpectedStatus $expectedStatus\n"
        ) in runbook
        assert (
            '"release" {\n'
            '            Invoke-RequestedDisposition -Action "release" '
            "-Identity $identity\n"
        ) in runbook
        assert (
            '"deny" {\n'
            '            Invoke-RequestedDisposition -Action "deny" '
            "-Identity $identity\n"
        ) in runbook
        assert "$ReleaseContractId        = \"identity_releasetoall\"" in runbook
        assert (
            "$DenyContractId           = "
            "\"identities_actiontype_no_dummy\""
        ) in runbook


# ---------------------------------------------------------------------------
# TestIrreversibleOperationReconciliation
# ---------------------------------------------------------------------------

class TestIrreversibleOperationReconciliation:

    @staticmethod
    def reconcile_params(operation_id="case-42", action="release"):
        return {
            "azure_job_id": JOB_ID,
            "expected_action": action,
            "expected_identity": IDENTITY,
            "operation_id": operation_id,
        }

    @staticmethod
    def successful_result(action="release"):
        expected_release_status = (
            "Released" if action == "release" else "Denied"
        )
        return {
            "action": action,
            "identity": IDENTITY,
            "status": "released" if action == "release" else "denied",
            "message": "Confirmed.",
            **build_metadata(),
            "verification_method": "Get-QuarantineMessage",
            "expected_release_status": expected_release_status,
            "observed_release_status": expected_release_status,
            "observed_identity": IDENTITY,
            "observed_release_status_history": expected_release_status,
            "verification_attempts": 1,
            "last_verification_error": "",
            "precondition_trace": PRECONDITION_TRACE,
            "postcondition_trace": POSTCONDITION_TRACE,
            **disposition_diagnostics(action=action),
        }

    @staticmethod
    def idempotent_result(action="release"):
        expected_release_status = (
            "Released" if action == "release" else "Denied"
        )
        precondition_trace = json.dumps([{
            "attempt": 1,
            "observed_at_utc": "2026-08-02T09:00:00Z",
            "result_count": 1,
            "observed_identity": IDENTITY,
            "observed_release_status": expected_release_status,
            "exact_identity_match": True,
            "error": "",
        }], separators=(",", ":"))
        return {
            "action": action,
            "identity": IDENTITY,
            "status": (
                "already_released" if action == "release"
                else "already_denied"
            ),
            "handling": "no_retry_needed",
            "idempotent": True,
            "message": "The target state was already confirmed.",
            **build_metadata(),
            "verification_method": "Get-QuarantineMessage",
            "expected_release_status": expected_release_status,
            "observed_release_status": expected_release_status,
            "observed_identity": IDENTITY,
            "observed_release_status_history": expected_release_status,
            "verification_attempts": 1,
            "last_verification_error": "",
            "precondition_trace": precondition_trace,
            "postcondition_trace": "",
            **disposition_diagnostics(
                action=action,
                executed=False,
            ),
        }

    @staticmethod
    def read_only_refresh_result(action="release", observed_status=None):
        expected = "Released" if action == "release" else "Denied"
        observed = observed_status or expected
        if observed.lower() == expected.lower():
            state = "confirmed_success"
            handling = "no_retry_needed"
        elif observed in {"Released", "Denied"}:
            state = "confirmed_failed"
            handling = "retry_requires_new_operation"
        else:
            state = "outcome_unknown"
            handling = "reconcile_before_retry"
        trace = json.dumps([{
            "attempt": 1,
            "observed_at_utc": "2026-08-02T09:00:00Z",
            "result_count": 1,
            "observed_identity": IDENTITY,
            "observed_release_status": observed,
            "exact_identity_match": True,
            "error": "",
        }], separators=(",", ":"))
        return {
            "action": "reconcile",
            "operation_action": action,
            "identity": IDENTITY,
            "status": state,
            "handling": handling,
            **build_metadata(),
            "verification_method": "Get-QuarantineMessage",
            "expected_release_status": expected,
            "observed_release_status": observed,
            "observed_identity": IDENTITY,
            "observed_release_status_history": observed,
            "verification_attempts": 1,
            "last_verification_error": "",
            "precondition_trace": "",
            "postcondition_trace": trace,
            **disposition_diagnostics(
                action=action,
                executed=False,
            ),
        }

    @staticmethod
    def read_only_refresh_error(action="release"):
        expected = "Released" if action == "release" else "Denied"
        trace = json.dumps([{
            "attempt": 1,
            "observed_at_utc": "2026-08-02T09:00:00Z",
            "result_count": 0,
            "observed_identity": "",
            "observed_release_status": "",
            "exact_identity_match": False,
            "error": "Transient Exchange read error.",
        }], separators=(",", ":"))
        details = {
            "action": "reconcile",
            "operation_action": action,
            "identity": IDENTITY,
            "status": "outcome_unknown",
            "handling": "reconcile_before_retry",
            **build_metadata(),
            "verification_method": "Get-QuarantineMessage",
            "expected_release_status": expected,
            "observed_release_status": "",
            "observed_identity": "",
            "observed_release_status_history": "",
            "verification_attempts": 1,
            "last_verification_error": "Transient Exchange read error.",
            "precondition_trace": "",
            "postcondition_trace": trace,
            **disposition_diagnostics(
                action=action,
                executed=False,
            ),
        }
        return {
            "action": "reconcile",
            "error": True,
            "error_code": "reconciliation_inspection_unconfirmed",
            "message": "Read-only Exchange reconciliation was unconfirmed.",
            "details": details,
            **build_metadata(),
        }

    @pytest.mark.parametrize(
        "action,handler_name",
        [
            ("release", "_handle_release_quarantine_message"),
            ("deny", "_handle_deny_quarantine_release"),
        ],
    )
    def test_success_is_compact_by_default(self, action, handler_name):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, self.successful_result(action))
            assert getattr(c, handler_name)({
                "identity": IDENTITY,
                "operation_id": f"{action}-compact",
            }) == APP_SUCCESS

        row = ar.get_data()[0]
        assert set(row) == {
            "operation_id",
            "identity",
            "azure_job_id",
            "runbook_version",
            "observed_release_status",
            "exchange_auth_method",
            "exchange_auth_method_source",
            "exchange_organization",
            "exchange_organization_source",
            "status",
        }
        assert "diagnostic_bundle" not in row
        assert "cmdlet_error" not in row
        assert set(ar.get_summary()) == {
            "operation_id",
            "identity",
            "azure_job_id",
            "runbook_version",
            "observed_release_status",
            "status",
        }

    def test_success_is_verbose_when_asset_setting_is_enabled(self):
        c = make_connector(config_overrides={
            "include_verbose_action_diagnostics": True,
        })
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, self.successful_result())
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "release-verbose",
            }) == APP_SUCCESS

        row = ar.get_data()[0]
        assert row["state"] == "confirmed_success"
        assert row["cmdlet_contract_id"] == RELEASE_CONTRACT
        assert "diagnostic_bundle" in row
        assert ar.get_summary()["state"] == "confirmed_success"

    def test_release_accepts_guid_case_variant_as_same_identity(self):
        c = make_connector()
        output = self.successful_result("release")
        output["observed_identity"] = IDENTITY.upper()
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "release-guid-case-variant",
            }) == APP_SUCCESS

    @pytest.mark.parametrize(
        "action,handler_name,expected_status",
        [
            (
                "release",
                "_handle_release_quarantine_message",
                "already_released",
            ),
            (
                "deny",
                "_handle_deny_quarantine_release",
                "already_denied",
            ),
        ],
    )
    def test_already_achieved_target_is_idempotent_success_without_cmdlet(
        self,
        action,
        handler_name,
        expected_status,
    ):
        c = make_connector(config_overrides={
            "include_verbose_action_diagnostics": True,
        })
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(
                m,
                self.idempotent_result(action),
                include_postcondition=False,
            )
            assert getattr(c, handler_name)({
                "identity": IDENTITY,
                "operation_id": f"{action}-already-achieved",
            }) == APP_SUCCESS

        row = ar.get_data()[0]
        assert row["status"] == expected_status
        assert row["idempotent"] is True
        assert row["cmdlet_executed"] is False
        assert row["state"] == "confirmed_success"
        assert "no disposition cmdlet was executed" in ar.get_message()

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda result: result.update(idempotent=False),
            lambda result: result.update(cmdlet_executed=True),
            lambda result: result.update(handling="manual_review"),
            lambda result: result.update(postcondition_trace=POSTCONDITION_TRACE),
        ],
    )
    def test_malformed_idempotent_success_is_rejected(self, mutation):
        c = make_connector()
        output = self.idempotent_result("release")
        mutation(output)
        with req_mock.Mocker() as m:
            mock_full_flow(m, output, include_postcondition=False)
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "release-malformed-idempotent",
            }) == APP_ERROR

    @pytest.mark.parametrize(
        "action,handler_name",
        [
            ("release", "_handle_release_quarantine_message"),
            ("deny", "_handle_deny_quarantine_release"),
        ],
    )
    def test_unconfirmed_postcondition_is_unknown_and_blocks_retry(
        self, action, handler_name
    ):
        c = make_connector()
        ar = patch_ar(c)
        output = postcondition_error_output(action=action)
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert getattr(c, handler_name)({
                "identity": IDENTITY,
                "operation_id": f"{action}-postcondition",
            }) == APP_ERROR
            webhook_calls = irreversible_webhook_bodies(m)

        assert len(webhook_calls) == 1
        row = ar.get_data()[0]
        assert row["state"] == "outcome_unknown"
        assert row["status"] == "outcome_unknown"
        assert row["handling"] == "reconcile_before_retry"
        assert row["verification_method"] == "Get-QuarantineMessage"
        assert row["expected_release_status"] == (
            "Released" if action == "release" else "Denied"
        )
        assert row["observed_release_status"] == "Requested"
        assert row["verification_attempts"] == 3
        assert ar.get_summary()["state"] == "outcome_unknown"
        assert ar.get_message() == output["message"]
        identifier = (
            "release_quarantine_message"
            if action == "release"
            else "deny_quarantine_release"
        )
        assert action_result_paths(ar) <= manifest_action_paths(identifier)

    def test_release_precondition_failure_does_not_claim_cmdlet_success(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, precondition_error_output())
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "release-precondition",
            }) == APP_ERROR

        row = ar.get_data()[0]
        assert row["state"] == "confirmed_failed"
        assert row["handling"] == "manual_review"
        assert row["expected_release_status"] == "Requested"
        assert row["observed_release_status"] == "Approved"
        assert row["exchange_online_management_version"] == "3.5.0"
        assert ar.get_message() == precondition_error_output()["message"]
        assert action_result_paths(ar) <= manifest_action_paths(
            "release_quarantine_message"
        )

    def test_release_action_result_keeps_exact_runbook_error_message(self):
        c = make_connector()
        ar = patch_ar(c)
        message = (
            "Microsoft Exchange Online returned:\r\n"
            "ErrorAccessDenied – Ω\n"
            "RequestId: 12345678-1234-1234-1234-123456789abc"
        )
        output = precondition_error_output()
        output["message"] = message
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "release-exact-error",
            }) == APP_ERROR
        assert ar.get_message() == message

    @pytest.mark.parametrize(
        "action,handler_name",
        [
            ("release", "_handle_release_quarantine_message"),
            ("deny", "_handle_deny_quarantine_release"),
        ],
    )
    def test_unconfirmed_cmdlet_parameter_contract_fails_before_execution(
        self,
        action,
        handler_name,
    ):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, disposition_capability_error_output(action))
            assert getattr(c, handler_name)({
                "identity": IDENTITY,
                "operation_id": f"{action}-capability",
            }) == APP_ERROR

        row = ar.get_data()[0]
        assert row["state"] == "confirmed_failed"
        assert row["handling"] == "retry_requires_new_operation"
        assert row["cmdlet_executed"] is False
        assert ar.get_message() == (
            disposition_capability_error_output(action)["message"]
        )

    def test_release_cmdlet_error_with_unconfirmed_status_is_unknown(self):
        c = make_connector()
        ar = patch_ar(c)
        output = postcondition_error_output(
            action="release",
            cmdlet_error="mock server-side error",
        )
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "release-cmdlet-unknown",
            }) == APP_ERROR

        row = ar.get_data()[0]
        assert row["state"] == "outcome_unknown"
        assert row["handling"] == "reconcile_before_retry"
        assert row["exchange_online_management_version"] == "3.5.0"
        assert row["cmdlet_error"] == "mock server-side error"
        assert ar.get_message() == "mock server-side error"

    @pytest.mark.parametrize(
        "action,handler_name",
        [
            ("release", "_handle_release_quarantine_message"),
            ("deny", "_handle_deny_quarantine_release"),
        ],
    )
    def test_deterministic_rejection_is_confirmed_failed_with_full_evidence(
        self,
        action,
        handler_name,
    ):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, disposition_rejected_output(action))
            assert getattr(c, handler_name)({
                "identity": IDENTITY,
                "operation_id": f"{action}-rejected",
            }) == APP_ERROR

        row = ar.get_data()[0]
        assert row["state"] == "confirmed_failed"
        assert row["handling"] == "manual_review"
        assert row["observed_release_status"] == "Requested"
        assert row["verification_attempts"] == 3
        assert row["cmdlet_error_category"] == "PermissionDenied"
        assert row["cmdlet_http_status_code"] == "403"
        assert "diagnostic_bundle" in row
        assert ar.get_message() == disposition_rejected_output(action)["message"]

    @pytest.mark.parametrize(
        "action,handler_name",
        [
            ("deny", "_handle_deny_quarantine_release"),
        ],
    )
    def test_cmdlet_failure_preserves_exact_diagnostics(
        self, action, handler_name
    ):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, cmdlet_failure_output(action=action))
            assert getattr(c, handler_name)({
                "identity": IDENTITY,
                "operation_id": f"{action}-cmdlet-failure",
            }) == APP_ERROR

        row = ar.get_data()[0]
        assert row["state"] == "confirmed_failed"
        assert row["handling"] == "retry_requires_new_operation"
        assert row["exchange_online_management_version"] == "3.5.0"
        assert row["cmdlet_warning"] == "mock warning"
        assert row["cmdlet_information"] == "mock information"
        assert row["cmdlet_verbose"] == "mock verbose"
        assert row["cmdlet_error"] == "mock cmdlet failure"
        assert ar.get_message() == "mock cmdlet failure"
        diagnostic_bundle = json.loads(row["diagnostic_bundle"])
        assert "powershell_edition" in diagnostic_bundle
        assert "cmdlet_error_details" in diagnostic_bundle
        assert "runbook_build_id" not in diagnostic_bundle
        assert "cmdlet_error" not in diagnostic_bundle
        identifier = (
            "release_quarantine_message"
            if action == "release"
            else "deny_quarantine_release"
        )
        assert action_result_paths(ar) <= manifest_action_paths(identifier)

    def test_diagnostic_integer_fallback_is_non_throwing(self):
        updates = (
            MSQuarantineForSplunkSOARConnector
            ._postcondition_operation_updates({
                "details": {
                    "verification_attempts": "not-an-integer",
                    "cmdlet_duration_ms": None,
                },
                "error": True,
            })
        )
        assert updates["verification_attempts"] == 0
        assert updates["cmdlet_duration_ms"] == 0

    def test_operation_registry_limit_tracks_diagnostic_record_growth(self):
        assert MAX_OPERATION_RECORDS == 50

    def test_terminal_operation_is_pruned_to_admit_new_claim(self):
        c = make_connector()
        registry = {
            f"case-{index}": {
                "operation_id": f"case-{index}",
                "action": "release",
                "identity": IDENTITY,
                "state": (
                    "confirmed_success" if index == 0 else "outcome_unknown"
                ),
                "updated_at": f"2026-08-01T00:00:{index:02d}+00:00",
            }
            for index in range(MAX_OPERATION_RECORDS)
        }
        assert c.save_state({"irreversible_operations": registry}) == APP_SUCCESS
        claimed, record = c._claim_irreversible_operation(
            "new-operation",
            "release",
            IDENTITY,
        )
        assert claimed is True
        assert record["state"] == "reserved"
        saved = c.load_state()["irreversible_operations"]
        assert len(saved) == MAX_OPERATION_RECORDS
        assert "case-0" not in saved

    def test_same_operation_id_never_fires_second_webhook(self):
        c = make_connector()
        first_ar = patch_ar(c)
        output = self.successful_result()
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "case-42",
            }) == APP_SUCCESS
            first_webhook_count = len(irreversible_webhook_bodies(m))

        second_ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "case-42",
            }) == APP_SUCCESS
            assert not m.called

        assert first_webhook_count == 1
        assert first_ar.get_summary()["status"] == "confirmed_success"
        assert second_ar.get_summary()["status"] == "confirmed_success"
        assert "no second webhook" in second_ar.get_message()

    def test_timeout_claim_survives_connector_restart(self, tmp_path):
        state_path = tmp_path / "asset_state.json"
        first = make_connector(state_path=state_path)
        first_ar = patch_ar(first)
        with req_mock.Mocker() as m:
            mock_preflight_then_unfinished_operation(m, first, [])
            assert first._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "case-restart",
            }) == APP_ERROR

        restarted = make_connector(state_path=state_path)
        restarted_ar = patch_ar(restarted)
        with req_mock.Mocker() as m:
            assert restarted._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "case-restart",
            }) == APP_ERROR
            assert not m.called

        assert first_ar.get_summary()["azure_job_id"] == JOB_ID
        assert restarted_ar.get_summary()["state"] == "outcome_unknown"
        assert "No second webhook" in restarted_ar.get_message()

    def test_restart_then_reconcile_updates_same_durable_operation(
        self, tmp_path
    ):
        state_path = tmp_path / "reconcile_restart_state.json"
        first = make_connector(state_path=state_path)
        with req_mock.Mocker() as m:
            mock_preflight_then_unfinished_operation(m, first, [])
            assert first._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "case-reconcile-restart",
            }) == APP_ERROR

        restarted = make_connector(state_path=state_path)
        reconcile_ar = patch_ar(restarted)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(
                job_output_url(),
                text=json.dumps(self.successful_result()),
            )
            assert restarted._handle_reconcile_quarantine_operation(
                self.reconcile_params(
                    operation_id="case-reconcile-restart"
                )
            ) == APP_SUCCESS
            assert all(request.url != WEBHOOK_URL for request in m.request_history)

        assert reconcile_ar.get_summary()["status"] == "confirmed_success"

        third = make_connector(state_path=state_path)
        third_ar = patch_ar(third)
        with req_mock.Mocker() as m:
            assert third._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "case-reconcile-restart",
            }) == APP_SUCCESS
            assert not m.called
        assert third_ar.get_summary()["status"] == "confirmed_success"

    def test_parallel_same_operation_fires_exactly_one_webhook(self, tmp_path):
        state_path = tmp_path / "parallel_state.json"
        connectors = [
            make_connector(state_path=state_path),
            make_connector(state_path=state_path),
        ]
        results = []
        webhook_count = 0
        counter_lock = threading.Lock()
        release_first_claim = threading.Event()

        def fire_webhook(action, identity=None, page_size=None, **_):
            nonlocal webhook_count
            if action == "config_check":
                return PREFLIGHT_JOB_ID
            with counter_lock:
                webhook_count += 1
            release_first_claim.set()
            time.sleep(0.05)
            return JOB_ID

        def wait_for_result(job_id, action, identity=None, **_):
            if action == "config_check":
                return config_check_for_request({})
            return self.successful_result(action)

        for connector in connectors:
            connector._utils.fire_webhook = fire_webhook
            connector._utils.wait_for_action_result = wait_for_result

        def worker(connector):
            ar = patch_ar(connector)
            status = connector._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "parallel-case",
            })
            results.append((status, ar.get_summary()))

        first = threading.Thread(target=worker, args=(connectors[0],))
        second = threading.Thread(target=worker, args=(connectors[1],))
        first.start()
        assert release_first_claim.wait(timeout=1)
        second.start()
        first.join(timeout=2)
        second.join(timeout=2)

        assert not first.is_alive()
        assert not second.is_alive()
        assert webhook_count == 1
        assert len(results) == 2
        assert {summary["operation_id"] for _, summary in results} == {
            "parallel-case"
        }

    def test_same_operation_id_cannot_cross_release_and_deny(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            mock_full_flow(m, self.successful_result("release"))
            assert c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "shared-case",
            }) == APP_SUCCESS

        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_deny_quarantine_release({
                "identity": IDENTITY,
                "operation_id": "shared-case",
            }) == APP_ERROR
            assert not m.called
        assert "different action or identity" in ar.get_message()

    def test_reconcile_pending_is_read_only_and_keeps_retry_blocked(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Running"}})
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params()
            ) == APP_SUCCESS
            assert all(request.url != WEBHOOK_URL for request in m.request_history)

        assert ar.get_data()[0]["status"] == "pending"
        assert ar.get_data()[0]["state"] == "pending"
        assert ar.get_data()[0]["handling"] == "wait"
        assert ar.get_data()[0]["last_job_status"] == "Running"
        assert ar.get_summary()["status"] == "pending"
        assert ar.get_summary()["state"] == "pending"
        assert ar.get_summary()["handling"] == "wait"
        assert ar.get_summary()["last_job_status"] == "Running"

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_reconcile_completed_validates_action_identity_and_version(
        self, action
    ):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(
                job_output_url(),
                text=json.dumps(self.successful_result(action)),
            )
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params(
                    operation_id=f"{action}-complete",
                    action=action,
                )
            ) == APP_SUCCESS
            assert all(request.url != WEBHOOK_URL for request in m.request_history)

        assert ar.get_summary()["status"] == "confirmed_success"
        assert "state" not in ar.get_data()[0]
        assert ar.get_data()[0]["status"] == (
            "released" if action == "release" else "denied"
        )
        assert ar.get_data()[0]["runbook_version"] == RUNBOOK_VERSION

    def test_reconcile_validated_structured_failure_is_confirmed_failed(self):
        c = make_connector()
        ar = patch_ar(c)
        failure = {
            "action": "release",
            "error": True,
            "message": "Exchange rejected the request.",
            "details": {"identity": IDENTITY},
            **build_metadata(),
        }
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Failed"}})
            m.get(job_output_url(), text=json.dumps(failure))
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params(operation_id="case-failed")
            ) == APP_SUCCESS

        assert ar.get_data()[0]["state"] == "confirmed_failed"
        assert ar.get_data()[0]["handling"] == "retry_requires_new_operation"

    def test_reconcile_deterministic_rejection_is_confirmed_failed(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(
                job_output_url(),
                text=json.dumps(disposition_rejected_output()),
            )
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params(operation_id="case-rejected")
            ) == APP_SUCCESS
            assert all(
                request.url != WEBHOOK_URL for request in m.request_history
            )

        row = ar.get_data()[0]
        assert row["state"] == "confirmed_failed"
        assert row["handling"] == "manual_review"
        assert row["observed_release_status"] == "Requested"
        assert row["cmdlet_error_category"] == "PermissionDenied"
        assert row["cmdlet_http_status_code"] == "403"

    def test_reconcile_capability_failure_is_confirmed_without_retry(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(
                job_output_url(),
                text=json.dumps(disposition_capability_error_output()),
            )
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params(operation_id="case-capability")
            ) == APP_SUCCESS
            assert all(
                request.url != WEBHOOK_URL for request in m.request_history
            )

        row = ar.get_data()[0]
        assert row["state"] == "confirmed_failed"
        assert row["handling"] == "retry_requires_new_operation"
        assert row["cmdlet_executed"] is False
        assert "cmdlet_capability_status" not in row

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_reconcile_unconfirmed_postcondition_stays_unknown(
        self, action
    ):
        c = make_connector()
        ar = patch_ar(c)
        failure = postcondition_error_output(action=action)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Completed"}})
            m.get(job_output_url(), text=json.dumps(failure))
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params(
                    operation_id=f"{action}-unconfirmed",
                    action=action,
                )
            ) == APP_ERROR
            assert all(
                request.url != WEBHOOK_URL for request in m.request_history
            )

        row = ar.get_data()[0]
        assert row["state"] == "outcome_unknown"
        assert row["handling"] == "reconcile_before_retry"
        assert row["observed_release_status"] == "Requested"
        assert ar.get_summary()["state"] == "outcome_unknown"

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_explicit_exchange_refresh_resolves_unknown_without_disposition(
        self,
        action,
    ):
        c = make_connector()
        ar = patch_ar(c)
        failure = postcondition_error_output(action=action)
        c._utils.get_job_status = lambda job_id, deadline=None: {
            "status": "Completed",
            "exception": "",
        }

        def original_output(
            job_id,
            expected_action,
            identity,
            deadline=None,
        ):
            raise RunbookActionError("unconfirmed", failure)

        c._utils.get_validated_job_output = original_output
        refresh_calls = []

        def refresh(runbook_action, identity, **kwargs):
            refresh_calls.append((runbook_action, identity, kwargs))
            return self.read_only_refresh_result(action)

        c._utils.run_action = refresh
        params = self.reconcile_params(
            operation_id=f"{action}-refresh",
            action=action,
        )
        params["refresh_exchange_status"] = True
        assert c._handle_reconcile_quarantine_operation(params) == APP_SUCCESS
        assert refresh_calls == [(
            "reconcile",
            IDENTITY,
            {"operation_action": action},
        )]
        row = ar.get_data()[0]
        assert row["state"] == "confirmed_success"
        assert row["observed_release_status"] == (
            "Released" if action == "release" else "Denied"
        )
        assert row["last_job_status"] == "exchange_refresh_completed"

    def test_explicit_exchange_refresh_keeps_requested_outcome_unknown(self):
        c = make_connector()
        ar = patch_ar(c)
        failure = postcondition_error_output(action="release")
        c._utils.get_job_status = lambda job_id, deadline=None: {
            "status": "Completed",
            "exception": "",
        }
        c._utils.get_validated_job_output = (
            lambda *args, **kwargs: (_ for _ in ()).throw(
                RunbookActionError("unconfirmed", failure)
            )
        )
        c._utils.run_action = lambda *args, **kwargs: (
            self.read_only_refresh_result("release", "Requested")
        )
        params = self.reconcile_params(operation_id="release-still-requested")
        params["refresh_exchange_status"] = True
        assert c._handle_reconcile_quarantine_operation(params) == APP_ERROR
        assert ar.get_data()[0]["state"] == "outcome_unknown"
        assert ar.get_data()[0]["handling"] == "reconcile_before_retry"

    def test_explicit_exchange_refresh_preserves_validated_read_error(self):
        c = make_connector()
        ar = patch_ar(c)
        failure = postcondition_error_output(action="release")
        c._utils.get_job_status = lambda job_id, deadline=None: {
            "status": "Completed",
            "exception": "",
        }
        c._utils.get_validated_job_output = (
            lambda *args, **kwargs: (_ for _ in ()).throw(
                RunbookActionError("unconfirmed", failure)
            )
        )
        refresh_error = self.read_only_refresh_error()
        c._utils.run_action = lambda *args, **kwargs: (_ for _ in ()).throw(
            RunbookActionError("refresh unconfirmed", refresh_error)
        )
        params = self.reconcile_params(operation_id="release-refresh-error")
        params["refresh_exchange_status"] = True
        assert c._handle_reconcile_quarantine_operation(params) == APP_ERROR
        row = ar.get_data()[0]
        assert row["state"] == "outcome_unknown"
        assert row["handling"] == "reconcile_before_retry"
        assert row["last_job_status"] == "exchange_refresh_unconfirmed"
        assert row["last_verification_error"] == (
            "Transient Exchange read error."
        )
        assert row["cmdlet_executed"] is False

    @pytest.mark.parametrize(
        "field,value",
        [
            ("cmdlet_executed", True),
            ("operation_action", "export"),
            ("verification_attempts", 2),
            ("handling", "manual_review"),
        ],
    )
    def test_read_only_reconcile_error_rejects_malformed_evidence(
        self,
        field,
        value,
    ):
        c = make_connector()
        result = self.read_only_refresh_error()
        result["details"][field] = value
        c._utils._validate_runbook_result(
            result,
            requested_action="reconcile",
            requested_identity=IDENTITY,
        )
        with pytest.raises(AutomationError, match="protocol error"):
            c._utils._raise_for_runbook_error(
                result,
                requested_action="reconcile",
                requested_identity=IDENTITY,
            )

    @pytest.mark.parametrize(
        "field,value",
        [
            ("handling", "retry_requires_new_operation"),
            ("observed_release_status", "Requested"),
            ("cmdlet_executed", True),
        ],
    )
    def test_read_only_reconcile_success_rejects_contradictory_evidence(
        self,
        field,
        value,
    ):
        c = make_connector()
        result = self.read_only_refresh_result()
        result[field] = value
        with pytest.raises(AutomationError, match="protocol error"):
            c._utils._validate_runbook_result(
                result,
                requested_action="reconcile",
                requested_identity=IDENTITY,
            )

    @pytest.mark.parametrize(
        "azure_status,raw_output",
        [
            ("Suspended", "PowerShell host stopped"),
            (
                "Completed",
                json.dumps({
                    "action": "deny",
                    "identity": IDENTITY,
                    "status": "denied",
                    "runbook_version": RUNBOOK_VERSION,
                }),
            ),
            (
                "Completed",
                json.dumps({
                    "action": "release",
                    "identity": IDENTITY + "0",
                    "status": "released",
                    "runbook_version": RUNBOOK_VERSION,
                }),
            ),
        ],
    )
    def test_reconcile_malformed_or_wrong_envelope_stays_unknown(
        self, azure_status, raw_output
    ):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": azure_status}})
            m.get(job_output_url(), text=raw_output)
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params(operation_id="case-unknown")
            ) == APP_ERROR

        assert ar.get_data()[0]["state"] == "outcome_unknown"
        assert ar.get_data()[0]["handling"] == "manual_review"

    def test_operation_state_contains_no_asset_secrets(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            mock_preflight_then_unfinished_operation(m, c, [])
            c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": "secret-check",
            })

        raw_state = Path(c.get_state_file_path()).read_text()
        assert CLIENT_SECRET not in raw_state
        assert WEBHOOK_URL not in raw_state
        assert MOCK_TOKEN not in raw_state
        assert "secret-check" in raw_state

    def test_reconcile_action_emits_only_declared_paths(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.get(job_url(), json={"properties": {"status": "Running"}})
            assert c._handle_reconcile_quarantine_operation(
                self.reconcile_params()
            ) == APP_SUCCESS

        assert action_result_paths(ar) <= manifest_action_paths(
            "reconcile_quarantine_operation"
        )


# ---------------------------------------------------------------------------
# Exchange connection settings (Runbook 3.4.2 Managed Identity-only contract)
# ---------------------------------------------------------------------------

NEW_RUNBOOK_VERSION = "3.4.2"


def upgrade_to_connection_contract(
    output,
    *,
    attempted=None,
    evidence=None,
):
    """Turn a legacy 3.3.4 fixture into a 3.4.1 runbook result."""
    output = json.loads(json.dumps(output))
    output["runbook_version"] = NEW_RUNBOOK_VERSION
    targets = [output]
    if isinstance(output.get("details"), dict):
        output["details"]["runbook_version"] = NEW_RUNBOOK_VERSION
        targets.append(output["details"])
    for target in targets:
        if "cmdlet_executed" not in target:
            continue
        target.update(evidence or connection_evidence())
        target.setdefault("exchange_online_management_version", "3.5.0")
        target["cmdlet_invocation_attempted"] = (
            target["cmdlet_executed"] if attempted is None else attempted
        )
        target["cmdlet_invocation_form"] = (
            "Release-QuarantineMessage -Identity <identity> -ReleaseToAll "
            "-Confirm:$false -ErrorAction Stop"
        )
        target["cmdlet_error_position"] = ""
        target["cmdlet_script_stack_trace"] = ""
        for legacy in (
            "cmdlet_capability_status",
            "cmdlet_capability_parameter_set",
            "cmdlet_capability_error",
        ):
            target.pop(legacy, None)
    return output


def config_check_output(**overrides):
    output = {
        "action": "config_check",
        "status": "verified",
        "config_contract": "exchange_connection_v1",
        **build_metadata(),
        **connection_evidence(),
    }
    output["runbook_version"] = NEW_RUNBOOK_VERSION
    output.update(overrides)
    return output


def config_check_for_request(body):
    """What a 3.4.2 runbook reports for the settings in this webhook body."""
    organization = body.get("organization")
    return config_check_output(**connection_evidence(
        organization=organization or ORG,
        organization_source="webhook" if organization else "automation_variable",
    ))


def released_output(action="release"):
    status = "Released" if action == "release" else "Denied"
    output = {
        "action": action,
        "identity": IDENTITY,
        "status": "released" if action == "release" else "denied",
        "message": "ok",
        "verification_method": "Get-QuarantineMessage",
        "expected_release_status": status,
        "observed_release_status": status,
        "observed_identity": IDENTITY,
        "observed_release_status_history": status,
        "verification_attempts": 1,
        "last_verification_error": "",
        "precondition_trace": PRECONDITION_TRACE,
        "postcondition_trace": POSTCONDITION_TRACE,
        **build_metadata(),
        **disposition_diagnostics(action=action),
    }
    return output


def dispatch_flow(m, outputs):
    """Mock the webhook so each action gets its own runbook output."""
    bodies = []
    state = {}
    m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN, "expires_in": 3600})

    def webhook(request, context):
        body = request.json()
        bodies.append(body)
        state["action"] = body["action"]
        context.status_code = 200
        return {"JobIds": [JOB_ID]}

    def job_output(request, context):
        return json.dumps(outputs[state["action"]])

    m.post(WEBHOOK_URL, json=webhook)
    m.get(job_url(), json={"properties": {"status": "Completed"}})
    m.get(job_output_url(), text=job_output)
    return bodies


STALE_LEGACY_SETTINGS = {
    "exchange_auth_method": "Credential",
    "exchange_credential_name": "StaleCredential",
}
ALL_WEBHOOK_ACTIONS = (
    "list", "export", "diagnose", "reconcile",
    "release", "deny", "config_check",
)


def fire_every_route(utils, m):
    """Drive every webhook route and return the bodies that were sent."""
    bodies = dispatch_flow(m, {
        action: {"action": action} for action in ALL_WEBHOOK_ACTIONS
    })
    for action in ("list", "export", "diagnose", "release", "deny"):
        utils.fire_webhook(action, identity=IDENTITY)
    utils.fire_webhook(
        "reconcile", identity=IDENTITY, operation_action="release"
    )
    utils.fire_webhook("config_check")
    return bodies


class TestExchangeConnectionAssets:

    def test_blank_organization_still_forwards_managed_identity(self):
        c = make_connector(config_overrides={"exchange_organization": "  "})
        assert c._utils._connection_settings == {
            "auth_method": "ManagedIdentity"
        }
        with req_mock.Mocker() as m:
            bodies = dispatch_flow(m, {"list": {"action": "list"}})
            c._utils.fire_webhook("list")
        assert bodies == [{"action": "list", "auth_method": "ManagedIdentity"}]

    def test_missing_organization_asset_forwards_managed_identity_only(self):
        c = make_connector()
        assert "exchange_organization" not in c.get_config()
        assert c._utils._connection_settings == {
            "auth_method": "ManagedIdentity"
        }

    @pytest.mark.parametrize("overrides,expected", [
        ({}, {"auth_method": "ManagedIdentity"}),
        (
            {"exchange_organization": ORG},
            {"auth_method": "ManagedIdentity", "organization": ORG},
        ),
        (
            {"exchange_organization": f"  {ORG}  "},
            {"auth_method": "ManagedIdentity", "organization": ORG},
        ),
    ])
    def test_managed_identity_reaches_every_webhook_route(
        self, overrides, expected
    ):
        c = make_connector(config_overrides=overrides)
        with req_mock.Mocker() as m:
            bodies = fire_every_route(c._utils, m)
        assert [body["action"] for body in bodies] == [
            "list", "export", "diagnose", "release", "deny",
            "reconcile", "config_check",
        ]
        for body in bodies:
            for key, value in expected.items():
                assert body[key] == value
            assert ("organization" in body) == ("organization" in expected)
            assert set(body) <= {
                "action", "identity", "operation_action", "auth_method",
                "organization", "page_size", "include_rbac",
            }

    @pytest.mark.parametrize("stale", [
        {"exchange_auth_method": "Credential"},
        {"exchange_auth_method": "Password"},
        {"exchange_auth_method": "managedidentity"},
        {"exchange_credential_name": "StaleCredential"},
        {"exchange_credential_name": "bad\nname"},
        {"exchange_credential_name": "x" * 300},
        STALE_LEGACY_SETTINGS,
    ])
    def test_stale_legacy_soar_values_are_ignored_not_forwarded(self, stale):
        c = make_connector(config_overrides={
            **stale, "exchange_organization": ORG,
        })
        assert c._utils._connection_settings == {
            "auth_method": "ManagedIdentity", "organization": ORG,
        }
        with req_mock.Mocker() as m:
            bodies = fire_every_route(c._utils, m)
        assert len(bodies) == 7
        text = json.dumps(bodies).lower()
        for body in bodies:
            assert body["auth_method"] == "ManagedIdentity"
            assert "credential_name" not in body
        assert "stale" not in text
        assert "credential" not in text
        assert "password" not in text

    @pytest.mark.parametrize("organization", [
        "not a domain; drop",
        "x" * 300,
        "line\nbreak",
        12,
    ])
    def test_invalid_organization_is_rejected_without_fallback(
        self, organization
    ):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            **base_asset_config(), "exchange_organization": organization,
        }
        assert c.initialize() == APP_ERROR
        assert c._utils is None or c._utils._connection_settings == {}

    @pytest.mark.parametrize("missing", [
        "webhook_url", "azure_tenant_id", "azure_client_id",
        "azure_client_secret", "azure_subscription_id",
        "azure_resource_group", "azure_automation_account",
    ])
    def test_azure_api_inputs_stay_required(self, missing):
        c = MSQuarantineForSplunkSOARConnector()
        c._config = {
            **base_asset_config(),
            "exchange_organization": ORG,
            missing: "",
        }
        assert c.initialize() == APP_ERROR

    @pytest.mark.parametrize("organization", [
        "contoso.onmicrosoft.com",
        "contoso",
        "contoso.onmicrosoft.us",
        "xn--bcher-kva.example",
        "Contoso_Tenant.example.com",
    ])
    def test_organization_is_not_gated_by_a_domain_regex(self, organization):
        from ms_quarantine_for_splunk_soar_utils import (
            normalize_exchange_connection_settings,
        )

        settings = normalize_exchange_connection_settings(
            organization=f"  {organization} "
        )
        assert settings == {
            "auth_method": "ManagedIdentity", "organization": organization,
        }

    def test_normalizer_no_longer_accepts_credential_arguments(self):
        from ms_quarantine_for_splunk_soar_utils import (
            normalize_exchange_connection_settings,
        )

        with pytest.raises(TypeError):
            normalize_exchange_connection_settings(auth_method="Credential")
        with pytest.raises(TypeError):
            normalize_exchange_connection_settings(credential_name="X")
        assert normalize_exchange_connection_settings() == {
            "auth_method": "ManagedIdentity"
        }

    def test_utils_constructor_has_no_credential_parameters(self):
        with pytest.raises(TypeError):
            MSQuarantineForSplunkSOARUtils(
                webhook_url=WEBHOOK_URL, tenant_id=TENANT_ID,
                client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                subscription_id=SUB_ID, resource_group=RG,
                automation_account=AA,
                exchange_credential_name="X",
            )


class TestExchangeCompatibilityPreflight:

    def release(self, c, outputs, operation_id="preflight"):
        with req_mock.Mocker() as m:
            bodies = dispatch_flow(m, outputs)
            status = c._handle_release_quarantine_message({
                "identity": IDENTITY,
                "operation_id": operation_id,
            })
        return status, bodies

    @pytest.mark.parametrize("overrides,source", [
        ({}, "automation_variable"),
        ({"exchange_organization": ORG}, "webhook"),
        (
            {**STALE_LEGACY_SETTINGS, "exchange_organization": ORG},
            "webhook",
        ),
    ])
    def test_preflight_always_runs_before_the_write(self, overrides, source):
        c = make_connector(config_overrides=overrides)
        ar = patch_ar(c)
        check = config_check_for_request(
            c._utils._connection_settings
        )
        released = released_output()
        released.update(connection_evidence(organization_source=source))
        status, bodies = self.release(c, {
            "config_check": check,
            "release": released,
        })
        assert status == APP_SUCCESS
        assert [b["action"] for b in bodies] == ["config_check", "release"]
        for body in bodies:
            assert body["auth_method"] == "ManagedIdentity"
        row = ar.get_data()[0]
        assert row["exchange_auth_method"] == "ManagedIdentity"
        assert row["exchange_auth_method_source"] == "webhook"
        assert row["exchange_organization"] == ORG
        assert row["exchange_organization_source"] == source
        assert not [key for key in row if "credential" in key]

    def test_contract_is_verified_once_per_asset_instance(self):
        c = make_connector(config_overrides={"exchange_organization": ORG})
        patch_ar(c)
        with req_mock.Mocker() as m:
            bodies = dispatch_flow(m, {
                "config_check": config_check_output(),
                "release": released_output(),
            })
            for number in range(2):
                assert c._handle_release_quarantine_message({
                    "identity": IDENTITY,
                    "operation_id": f"once-{number}",
                }) == APP_SUCCESS
        assert [b["action"] for b in bodies].count("config_check") == 1

    @pytest.mark.parametrize("unsupported", [
        {
            "action": "config_check",
            "error": True,
            "error_code": "unknown_action",
            "message": "Unknown action 'config_check'.",
            **build_metadata(),
        },
        config_check_output(runbook_version="3.4.1"),
        config_check_output(runbook_version="3.3.4"),
        {
            key: value
            for key, value in config_check_output().items()
            if key != "config_contract"
        },
    ])
    def test_old_runbook_blocks_every_irreversible_write(self, unsupported):
        for action, handler in (
            ("release", "_handle_release_quarantine_message"),
            ("deny", "_handle_deny_quarantine_release"),
        ):
            c = make_connector(config_overrides={"exchange_organization": ORG})
            ar = patch_ar(c)
            with req_mock.Mocker() as m:
                bodies = dispatch_flow(m, {
                    "config_check": unsupported,
                    action: released_output(action),
                })
                assert getattr(c, handler)({
                    "identity": IDENTITY,
                    "operation_id": f"old-{action}",
                }) == APP_ERROR
            assert [b["action"] for b in bodies] == ["config_check"]
            assert "no irreversible action was sent" in ar.get_message()
            assert "3.4.2" in ar.get_message()

    @pytest.mark.parametrize("credential_field", [
        {"exchange_credential_name": "ExchangeQuarantineAdmin"},
        {"exchange_credential_source": "default"},
    ])
    def test_runbook_reporting_credential_evidence_blocks_the_write(
        self, credential_field
    ):
        c = make_connector(config_overrides={"exchange_organization": ORG})
        ar = patch_ar(c)
        status, bodies = self.release(c, {
            "config_check": config_check_output(**credential_field),
            "release": released_output(),
        })
        assert status == APP_ERROR
        assert [b["action"] for b in bodies] == ["config_check"]
        assert "credential" in ar.get_message().lower()

    @pytest.mark.parametrize("effective", [
        {"exchange_auth_method": "Credential"},
        {"exchange_auth_method": ""},
        {"exchange_auth_method_source": "automation_variable"},
        {"exchange_organization": "other.onmicrosoft.com"},
        {"exchange_organization_source": "automation_variable"},
    ])
    def test_effective_value_mismatch_blocks_the_write(self, effective):
        c = make_connector(config_overrides={"exchange_organization": ORG})
        ar = patch_ar(c)
        status, bodies = self.release(c, {
            "config_check": config_check_output(**effective),
            "release": released_output(),
        })
        assert status == APP_ERROR
        assert [b["action"] for b in bodies] == ["config_check"]
        assert "No operation was claimed" in ar.get_message()

    def test_variable_sourced_organization_must_be_reported_as_such(self):
        c = make_connector()
        ar = patch_ar(c)
        status, bodies = self.release(c, {
            "config_check": config_check_output(
                exchange_organization_source="webhook"
            ),
            "release": released_output(),
        })
        assert status == APP_ERROR
        assert [b["action"] for b in bodies] == ["config_check"]
        assert "organization" in ar.get_message()

    def test_failed_preflight_leaves_no_claimed_operation(self):
        c = make_connector()
        patch_ar(c)
        status, bodies = self.release(c, {
            "config_check": config_check_output(runbook_version="3.4.1"),
            "release": released_output(),
        }, operation_id="never-claimed")
        assert status == APP_ERROR
        state_file = Path(c.get_state_file_path())
        if state_file.exists():
            assert "never-claimed" not in state_file.read_text()

    def test_release_deny_results_from_an_older_runbook_are_rejected(self):
        for action in ("release", "deny"):
            output = released_output(action)
            output["runbook_version"] = "3.4.1"
            with pytest.raises(AutomationError) as exc_info:
                make_utils()._validate_runbook_result(
                    output, action, IDENTITY
                )
            assert "3.4.2" in str(exc_info.value)


class TestIrreversibleRegistryLookup:
    """Replay never claims or writes; read errors fail closed; new operations
    are config-checked before their atomic claim."""

    HANDLERS = {
        "release": "_handle_release_quarantine_message",
        "deny": "_handle_deny_quarantine_release",
    }

    def setup_connector(self, monkeypatch, tmp_path):
        c = make_connector(state_path=tmp_path / "state.json")
        ar = patch_ar(c)
        calls = {"verify": 0, "webhook": 0, "claim": 0}

        original_verify = c._utils.verify_connection_contract
        original_claim = c._claim_irreversible_operation

        def verify():
            calls["verify"] += 1
            return original_verify()

        def claim(*args, **kwargs):
            calls["claim"] += 1
            return original_claim(*args, **kwargs)

        original_fire = c._utils.fire_webhook

        def fire(action, *args, **kwargs):
            if action in {"release", "deny"}:
                calls["webhook"] += 1
                raise WebhookError("blocked in test")
            return original_fire(action, *args, **kwargs)

        monkeypatch.setattr(c._utils, "verify_connection_contract", verify)
        monkeypatch.setattr(c, "_claim_irreversible_operation", claim)
        monkeypatch.setattr(c._utils, "fire_webhook", fire)
        return c, ar, calls

    def run(self, c, action, operation_id):
        with req_mock.Mocker() as m:
            status = getattr(c, self.HANDLERS[action])({
                "identity": IDENTITY,
                "operation_id": operation_id,
            })
        return status, m.request_history

    def registry(self, c):
        return c.load_state().get(OPERATION_STATE_KEY, {})

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_transient_first_read_failure_fails_closed(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        original = c._load_operation_registry_unlocked
        reads = {"count": 0}

        def flaky():
            reads["count"] += 1
            if reads["count"] == 1:
                raise AutomationError("transient state read failure")
            return original()

        monkeypatch.setattr(c, "_load_operation_registry_unlocked", flaky)
        status, history = self.run(c, action, "transient-read")
        assert status == APP_ERROR
        assert calls == {"verify": 0, "webhook": 0, "claim": 0}
        assert reads["count"] == 1
        assert history == []
        assert "transient-read" not in self.registry(c)

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_record_vanishing_after_lookup_cannot_cause_a_write(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        original_claim = c._claim_irreversible_operation
        claimed, _ = original_claim("pruned-race", action, IDENTITY)
        assert claimed is True
        calls["claim"] = 0
        original_lookup = c._lookup_irreversible_operation

        def lookup_then_prune(*args, **kwargs):
            record = original_lookup(*args, **kwargs)
            state = c.load_state()
            state[OPERATION_STATE_KEY].pop("pruned-race")
            assert c.save_state(state)
            return record

        monkeypatch.setattr(
            c, "_lookup_irreversible_operation", lookup_then_prune
        )
        status, history = self.run(c, action, "pruned-race")
        assert status == APP_ERROR
        assert "already exists" in ar.get_message()
        assert calls == {"verify": 0, "webhook": 0, "claim": 0}
        assert history == []
        assert "pruned-race" not in self.registry(c)

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_existing_record_replays_without_claim_or_azure(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        c._claim_irreversible_operation("replayed", action, IDENTITY)
        calls["claim"] = 0
        before = json.dumps(self.registry(c), sort_keys=True)
        status, history = self.run(c, action, "replayed")
        assert status == APP_ERROR
        assert "No second webhook was sent" in ar.get_message()
        assert calls == {"verify": 0, "webhook": 0, "claim": 0}
        assert history == []
        assert json.dumps(self.registry(c), sort_keys=True) == before

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_confirmed_record_replays_success_without_azure(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        c._claim_irreversible_operation("done", action, IDENTITY)
        c._update_irreversible_operation(
            "done", action, IDENTITY, state="confirmed_success"
        )
        calls["claim"] = 0
        status, history = self.run(c, action, "done")
        assert status == APP_SUCCESS
        assert calls == {"verify": 0, "webhook": 0, "claim": 0}
        assert history == []

    @pytest.mark.parametrize("action,other", [
        ("release", "deny"), ("deny", "release"),
    ])
    def test_binding_conflict_fails_closed_without_azure(
        self, action, other, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        c._claim_irreversible_operation("bound", other, IDENTITY)
        calls["claim"] = 0
        status, history = self.run(c, action, "bound")
        assert status == APP_ERROR
        assert "already bound" in ar.get_message()
        assert calls == {"verify": 0, "webhook": 0, "claim": 0}
        assert history == []

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_malformed_record_fails_closed_without_azure(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        assert c.save_state({OPERATION_STATE_KEY: {"broken": "not-a-dict"}})
        status, history = self.run(c, action, "broken")
        assert status == APP_ERROR
        assert "malformed" in ar.get_message()
        assert calls == {"verify": 0, "webhook": 0, "claim": 0}
        assert history == []

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_missing_record_preflights_before_the_atomic_claim(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        order = []
        original_verify = c._utils.verify_connection_contract
        original_claim = c._claim_irreversible_operation
        monkeypatch.setattr(
            c._utils, "verify_connection_contract",
            lambda: order.append("verify") or original_verify(),
        )
        monkeypatch.setattr(
            c, "_claim_irreversible_operation",
            lambda *a, **k: order.append("claim") or original_claim(*a, **k),
        )
        with req_mock.Mocker() as m:
            bodies = dispatch_flow(m, {
                "config_check": config_check_for_request(
                    c._utils._connection_settings
                ),
                action: released_output(action),
            })
            status = getattr(c, self.HANDLERS[action])({
                "identity": IDENTITY,
                "operation_id": "fresh",
            })
        assert status == APP_ERROR
        assert order == ["verify", "claim"]
        assert [b["action"] for b in bodies] == ["config_check"]
        assert calls["webhook"] == 1
        assert self.registry(c)["fresh"]["action"] == action

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_failed_preflight_leaves_no_claim(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        with req_mock.Mocker() as m:
            bodies = dispatch_flow(m, {
                "config_check": config_check_output(runbook_version="3.4.1"),
                action: released_output(action),
            })
            status = getattr(c, self.HANDLERS[action])({
                "identity": IDENTITY,
                "operation_id": "rejected",
            })
        assert status == APP_ERROR
        assert [b["action"] for b in bodies] == ["config_check"]
        assert calls["claim"] == 0
        assert calls["webhook"] == 0
        assert "rejected" not in self.registry(c)

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_concurrent_claim_during_preflight_returns_replay(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        original_claim = c._claim_irreversible_operation
        monkeypatch.setattr(
            c._utils, "verify_connection_contract",
            lambda: original_claim("raced", action, IDENTITY) and {},
        )
        status, history = self.run(c, action, "raced")
        assert status == APP_ERROR
        assert "No second webhook was sent" in ar.get_message()
        assert calls["webhook"] == 0
        assert history == []

    @pytest.mark.parametrize("action", ["release", "deny"])
    def test_unreadable_registry_at_claim_time_still_fails_closed(
        self, action, monkeypatch, tmp_path
    ):
        c, ar, calls = self.setup_connector(monkeypatch, tmp_path)
        original = c._load_operation_registry_unlocked
        reads = {"count": 0}

        def second_read_fails():
            reads["count"] += 1
            if reads["count"] == 2:
                raise AutomationError("claim-time state read failure")
            return original()

        monkeypatch.setattr(
            c._utils, "verify_connection_contract", lambda: {}
        )
        monkeypatch.setattr(
            c, "_load_operation_registry_unlocked", second_read_fails
        )
        status, history = self.run(c, action, "claim-read")
        assert status == APP_ERROR
        assert calls["webhook"] == 0
        assert history == []


class TestConnectionContractEvidence:

    def validate(self, output, action="release"):
        make_utils()._validate_runbook_result(output, action, IDENTITY)

    def test_success_result_validates(self):
        output = released_output()
        assert "cmdlet_capability_status" not in output
        assert not [key for key in output if "credential" in key]
        self.validate(output)

    def test_attempted_without_execution_keeps_native_error_evidence(self):
        details = disposition_diagnostics(executed=False)
        details.update({
            "cmdlet_invocation_attempted": True,
            "cmdlet_started_at_utc": "2026-07-30T08:00:00.0000000Z",
            "cmdlet_completed_at_utc": "2026-07-30T08:00:00.0100000Z",
            "cmdlet_duration_ms": 10,
            "cmdlet_error": "A parameter cannot be found",
            "cmdlet_fully_qualified_error_id": (
                "NamedParameterNotFound,Release-QuarantineMessage"
            ),
            "cmdlet_exception_type": (
                "System.Management.Automation.ParameterBindingException"
            ),
            "cmdlet_error_position": "At line:1 char:1",
            "cmdlet_script_stack_trace": "at <ScriptBlock>",
        })
        output = {
            **cmdlet_failure_output(),
            "details": {
                **cmdlet_failure_output()["details"],
                **details,
            },
        }
        self.validate(output)

    def test_executed_cmdlet_must_have_been_invoked(self):
        output = released_output()
        output["cmdlet_invocation_attempted"] = False
        with pytest.raises(AutomationError):
            self.validate(output)

    def test_unattempted_cmdlet_must_not_claim_timing(self):
        output = released_output()
        output["cmdlet_invocation_attempted"] = False
        output["cmdlet_executed"] = False
        with pytest.raises(AutomationError):
            self.validate(output)

    @pytest.mark.parametrize("field,value", [
        ("exchange_auth_method", "Basic"),
        ("exchange_auth_method", "Credential"),
        ("exchange_auth_method_source", "guess"),
        ("exchange_auth_method_source", "automation_variable"),
        ("exchange_organization_source", "guess"),
        ("exchange_disconnect_status", "unknown"),
        ("cmdlet_invocation_attempted", "yes"),
        ("exchange_organization", 7),
    ])
    def test_invalid_connection_evidence_is_rejected(self, field, value):
        output = released_output()
        output[field] = value
        with pytest.raises(AutomationError):
            self.validate(output)

    @pytest.mark.parametrize("field,value", [
        ("exchange_credential_name", ""),
        ("exchange_credential_name", "ExchangeQuarantineAdmin"),
        ("exchange_credential_source", "not_applicable"),
    ])
    def test_credential_evidence_is_unsupported_in_results(self, field, value):
        output = released_output()
        output[field] = value
        with pytest.raises(AutomationError) as exc_info:
            self.validate(output)
        assert "ManagedIdentity only" in str(exc_info.value)

    def test_missing_connection_evidence_is_rejected(self):
        output = released_output()
        del output["exchange_auth_method_source"]
        with pytest.raises(AutomationError):
            self.validate(output)

    def test_default_method_source_is_accepted(self):
        output = released_output()
        output["exchange_auth_method_source"] = "default"
        self.validate(output)

    def test_idempotent_result_needs_no_cleanup_evidence_and_no_cmdlet(self):
        output = released_output()
        output.update({
            "status": "already_released",
            "idempotent": True,
            "handling": "no_retry_needed",
            "postcondition_trace": "",
            **disposition_diagnostics(executed=False),
        })
        output["idempotent"] = True
        for field in ("exchange_disconnect_status", "exchange_disconnect_error"):
            output.pop(field)
        self.validate(output)

    def test_secret_values_are_never_part_of_the_connection_evidence(self):
        output = released_output()
        assert not any(
            "password" in key.lower() or "secret" in key.lower()
            for key in output
        )


# ---------------------------------------------------------------------------
# TestManifestActionResultContracts
# ---------------------------------------------------------------------------

class TestManifestActionResultContracts:

    @pytest.mark.parametrize(
        "identifier,export_mode,handler_name,param,output",
        [
            (
                "inspect_release_environment",
                EXPORT_VAULT,
                "_handle_inspect_release_environment",
                {"identity": IDENTITY, "include_rbac": True},
                diagnostic_success_output(),
            ),
            (
                "release_quarantine_message",
                EXPORT_VAULT,
                "_handle_release_quarantine_message",
                {"identity": IDENTITY},
                {
                    "action": "release",
                    "identity": IDENTITY,
                    "status": "released",
                    "message": "Released.",
                },
            ),
            (
                "deny_quarantine_release",
                EXPORT_VAULT,
                "_handle_deny_quarantine_release",
                {"identity": IDENTITY},
                {
                    "action": "deny",
                    "identity": IDENTITY,
                    "status": "denied",
                    "message": "Denied.",
                },
            ),
        ],
    )
    def test_success_handlers_emit_only_declared_paths(
        self, identifier, export_mode, handler_name, param, output
    ):
        c = make_connector(export_mode=export_mode)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert getattr(c, handler_name)(param) == APP_SUCCESS

        actual_paths = action_result_paths(ar)
        declared_paths = manifest_action_paths(identifier)
        assert actual_paths <= declared_paths

        if identifier in {
            "release_quarantine_message",
            "deny_quarantine_release",
        }:
            row = ar.get_data()[0]
            assert "action" not in row
            assert row["identity"] == IDENTITY
            assert row["status"] in {"released", "denied"}
            assert row["runbook_version"] == RUNBOOK_VERSION
            assert "action_result.data.*.action" in declared_paths
            assert "action_result.data.*.runbook_version" in declared_paths
        if identifier == "inspect_release_environment":
            row = ar.get_data()[0]
            assert row["handling"] == "read_only"
            assert row["observed_identity"] == IDENTITY
            assert "no release or deny cmdlet was executed" in (
                ar.get_message()
            )
            assert "action_result.data.*.cmdlet_parameter_sets" in (
                declared_paths
            )
            assert (
                "action_result.data.*.cmdlet_default_parameter_set"
                in declared_paths
            )
            for path in (
                "action_result.data.*.rbac_diagnostics_status",
                "action_result.data.*.release_to_all_roles",
                "action_result.data.*.release_deny_roles",
                "action_result.data.*.managed_identity_app_id",
                "action_result.data.*.managed_identity_object_id",
                "action_result.data.*.service_principal_registered",
                "action_result.data.*.role_assignment_matches_identity",
                "action_result.data.*.quarantine_role_group_total_count",
                "action_result.data.*.quarantine_role_group_inspected_count",
                (
                    "action_result.data.*."
                    "quarantine_role_group_inspection_truncated"
                ),
                "action_result.data.*.permission_query_errors.*.query",
                "action_result.summary.rbac_diagnostics_status",
                "action_result.summary.role_assignment_matches_identity",
                "action_result.summary.quarantine_role_group_total_count",
                "action_result.summary.quarantine_role_group_inspected_count",
                (
                    "action_result.summary."
                    "quarantine_role_group_inspection_truncated"
                ),
            ):
                assert path in declared_paths


# ---------------------------------------------------------------------------
# TestRunbookExportContract
# ---------------------------------------------------------------------------

class TestRunbookExportContract:

    @staticmethod
    def _runbook():
        return (Path(__file__).resolve().parents[2] / "runbook" / "runbook.ps1").read_text()

    @staticmethod
    def _integer_constant(runbook, name):
        match = re.search(
            rf"\${name}\s*=\s*(\d+)\s*\*\s*1024(?:\s*\*\s*1024)?",
            runbook,
        )
        assert match, f"PowerShell constant ${name} not found"
        factors = re.search(
            rf"\${name}\s*=\s*\d+((?:\s*\*\s*1024)+)",
            runbook,
        ).group(1)
        return int(match.group(1)) * (1024 ** factors.count("1024"))

    def test_versions_and_limits_are_in_sync(self):
        runbook = self._runbook()
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        assert re.search(r'(?m)^\$RunbookVersion\s*=\s*"([^"]+)"$', runbook).group(1) == manifest["app_version"]
        assert "$PostconditionMaxAttempts = 7" in runbook
        assert MAX_DIAGNOSTIC_TRACE_RECORDS == 25
        assert MAX_RBAC_ROLE_GROUP_INSPECTIONS == 20
        assert "$RbacDiagnosticMaxGroups  = 20" in runbook
        assert "$PostconditionPollSeconds = 10" in runbook
        assert self._integer_constant(
            runbook, "ExportMaxDecodedBytes"
        ) == MAX_DECODED_EML_BYTES
        assert "$ExportMaxChunkCount      = 200" in runbook
        assert "$ErrorMaxChunkCount       = 200" in runbook

    def test_runbook_uses_exact_error_contract_without_wrapper_text(self):
        runbook = self._runbook()
        for helper in (
            "function ConvertTo-SecretRedactedText",
            "function Get-OriginalErrorMessage",
            "function Join-OriginalRecordText",
            "function Write-ErrorEnvelope",
        ):
            assert helper in runbook
        assert 'mode          = "error_chunk"' in runbook
        assert 'mode                  = "error_complete"' in runbook
        assert "PowerShell error during" not in runbook
        assert "Failed to connect to Exchange Online: $_" not in runbook
        assert "Cmdlet error: $($disposition.Error)" not in runbook

    def test_webhook_scalars_and_identity_are_checked_before_exchange(self):
        runbook = self._runbook()
        connect_index = runbook.index("Connect-ExchangeOnline `")
        for evidence in (
            'ErrorCode "invalid_action_type"',
            'ErrorCode "invalid_identity_type"',
            'ErrorCode "invalid_operation_action_type"',
            'ErrorCode "invalid_include_rbac_type"',
            'ErrorCode "include_rbac_not_supported"',
            'ErrorCode "invalid_page_size"',
            "Test-QuarantineIdentityValue -Value $identity",
        ):
            assert runbook.index(evidence) < connect_index

    def test_managed_identity_resource_path_is_never_persisted(self):
        runbook = self._runbook()
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text()
        )
        assert "xms_mirid" not in runbook
        assert "managed_identity_resource_id" not in runbook
        assert "managed_identity_resource_id" not in json.dumps(manifest)

    def test_strong_rbac_identity_matching_uses_guid_fields_only(self):
        runbook = self._runbook()
        helper = runbook[
            runbook.index("function Get-ObjectIdentityGuids"):
            runbook.index("function Test-ObjectIdentityMatch")
        ]
        for field in (
            '"AppId"',
            '"ObjectId"',
            '"ExternalDirectoryObjectId"',
            '"Guid"',
            '"Id"',
            '"RoleAssignee"',
        ):
            assert field in helper
        assert '"Identity"' not in helper
        assert '"RoleAssigneeName"' not in helper

    def test_runbook_build_id_is_self_verifying_sha256(self):
        runbook = self._runbook()
        canonical = re.sub(
            r'(?m)^\$RunbookSourceRevision\s*=\s*"[^"]+"$',
            '$RunbookSourceRevision = "<canonical>"',
            runbook,
        )
        canonical = re.sub(
            r'(?m)^\$RunbookBuildId\s*=\s*"[^"]+"$',
            '$RunbookBuildId = "<canonical>"',
            canonical,
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        source_revision = re.search(
            r'(?m)^\$RunbookSourceRevision\s*=\s*"([^"]+)"$',
            runbook,
        ).group(1)
        build_id = re.search(
            r'(?m)^\$RunbookBuildId\s*=\s*"([^"]+)"$',
            runbook,
        ).group(1)
        assert source_revision == f"sha256:{digest}"
        version = re.search(r'(?m)^\$RunbookVersion\s*=\s*"([^"]+)"$', runbook).group(1)
        assert build_id == f"ms-quarantine-for-splunk-soar-runbook-{version}+sha256.{digest}"

    def test_cmdlet_metadata_is_collected_after_exchange_connection(self):
        runbook = self._runbook()
        connected_marker = 'Write-Verbose "Connected to Exchange Online."'
        initialization = "Initialize-DiagnosticEvidence\n"
        assert runbook.index(connected_marker) < runbook.index(initialization)

    def test_exact_24_mib_fits_chunk_contract(self):
        decoded_size = 24 * 1024 * 1024
        base64_length = ((decoded_size + 2) // 3) * 4
        chunk_count = (
            base64_length + (250 * 1024) - 1
        ) // (250 * 1024)
        assert decoded_size == MAX_DECODED_EML_BYTES
        assert base64_length == 33_554_432
        assert chunk_count == 132
        assert chunk_count <= 200
        assert decoded_size + 1 > MAX_DECODED_EML_BYTES

    def test_known_24_602_271_byte_message_remains_supported(self):
        decoded_size = 24_602_271
        base64_length = ((decoded_size + 2) // 3) * 4
        chunk_count = (
            base64_length + (250 * 1024) - 1
        ) // (250 * 1024)
        assert decoded_size < MAX_DECODED_EML_BYTES
        assert base64_length == 32_803_028
        assert chunk_count == 129

    def test_large_path_has_no_full_payload_decode_or_cleanup_copy(self):
        runbook = self._runbook()
        assert "[System.Convert]::FromBase64String($emlBase64)" not in runbook
        assert '$emlBase64 = ([string]$emlBase64) -replace' not in runbook
        assert "function Get-Base64PayloadInfo" in runbook
        assert "function Write-ChunkedExport" in runbook
        assert "$sha256.TransformBlock" in runbook
        assert "$sha256.TransformFinalBlock" in runbook

    def test_irreversible_actions_require_exchange_postcondition(self):
        runbook = self._runbook()
        assert "function Wait-QuarantinePostcondition" in runbook
        # Read-only reconcile also passes -ExpectedStatus $expectedStatus and
        # reconcile_before_retry, so pin the release/deny flow itself.
        flow = re.search(
            r"(?ms)^function Invoke-RequestedDisposition \{$.*?^\}$",
            runbook,
        ).group(0)
        assert '$expectedStatus = "Released"' in flow
        assert '$expectedStatus = "Denied"' in flow
        disposition = flow.index(
            "    $disposition = Invoke-QuarantineDisposition `\n"
        )
        verification = flow.index(
            "    $verification = Wait-QuarantinePostcondition `\n"
            "        -Identity $identity `\n"
            "        -ExpectedStatus $expectedStatus\n"
        )
        assert disposition < verification
        assert 'ErrorCode "postcondition_unconfirmed"' in flow[verification:]
        assert (
            'handling                = "reconcile_before_retry"'
        ) in flow[verification:]


# ---------------------------------------------------------------------------
# TestIdentityFormatValidation
# ---------------------------------------------------------------------------

class TestIdentityFormatValidation:
    """Malformed identity must fail instantly, without firing the webhook."""

    def test_valid_identity_passes(self):
        from ms_quarantine_for_splunk_soar_connector import validate_identity_format
        assert validate_identity_format(IDENTITY) == ""

    def test_missing_backslash_rejected(self):
        from ms_quarantine_for_splunk_soar_connector import validate_identity_format
        err = validate_identity_format("c14401cf-aa9a-465b-cfd5-08d0f0ca37c5")
        assert err != ""

    def test_garbage_rejected(self):
        from ms_quarantine_for_splunk_soar_connector import validate_identity_format
        assert validate_identity_format("not-an-identity") != ""

    def test_export_rejects_bad_identity_without_webhook(self):
        """No HTTP call should happen for a malformed identity."""
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            # No mocks registered - any HTTP call would raise NoMockAddress
            assert c._handle_get_quarantine_message(
                {"identity": "garbage"}) == APP_ERROR
        assert "Invalid identity format" in ar.get_message()

    def test_release_rejects_bad_identity(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_release_quarantine_message(
                {"identity": "12345"}) == APP_ERROR
        assert "Invalid identity format" in ar.get_message()

    def test_inspection_rejects_bad_identity_without_webhook(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_inspect_release_environment(
                {"identity": "12345"}
            ) == APP_ERROR
            assert not m.called
        assert "Invalid identity format" in ar.get_message()

    def test_deny_rejects_bad_identity(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            assert c._handle_deny_quarantine_release(
                {"identity": "abc\\def"}) == APP_ERROR
        assert "Invalid identity format" in ar.get_message()


# ---------------------------------------------------------------------------
# TestExportErrors
# ---------------------------------------------------------------------------

class TestExportErrors:

    def test_missing_identity_error(self):
        c = make_connector()
        patch_ar(c)
        assert c._handle_get_quarantine_message({"identity": ""}) == APP_ERROR

    def test_empty_eml_error(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        output = {"action": "export", "identity": IDENTITY, "eml": ""}
        with req_mock.Mocker() as m:
            mock_full_flow(m, output)
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_ERROR

    def test_timeout_error(self):
        c = make_connector(poll_timeout=0)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.post(TOKEN_URL, json={"access_token": MOCK_TOKEN})
            m.post(WEBHOOK_URL, json={"JobIds": [JOB_ID]})
            m.get(job_url(), json={"properties": {"status": "Running"}})
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_ERROR
        assert "timeout" in ar.get_message().lower() or "timed out" in ar.get_message().lower()


def test_product_rename_preserves_persisted_deduplication_identifiers():
    connector = MSQuarantineForSplunkSOARConnector()
    assert connector._artifact_identifier("ready", "message") == 'msqm-email-02c5527a5d903e1ef8c6604b3a05985dec481bf0e0cb208dc97edac433662c15'
    assert connector._worker_source_identifier("identity", 4) == 'msqm-quarantine-asset-4-4788975f96aa7db080e5722a3b2c2e866997613dba36e60ec7ada4d7f9622f43'
