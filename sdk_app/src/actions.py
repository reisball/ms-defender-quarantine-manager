# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

"""SDK action boundary; Azure request and runbook validation stay in the shared transport."""

import fcntl
import hashlib
import os
import re
import stat
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from tempfile import gettempdir

from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure, AssetMisconfiguration
from soar_sdk.logging import getLogger
from soar_sdk.meta.actions import ActionMeta
from soar_sdk.params import Param, Params

from .ms_quarantine_for_splunk_soar_utils import (
    DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE,
    DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE,
    AutomationError,
    JobFailedError,
    JobTimeoutError,
    MSQuarantineForSplunkSOARUtils,
    RunbookActionError,
    TokenError,
    WebhookError,
    parse_strict_integer,
)
from .special_actions import register_special


logger = getLogger()
_GUID = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
_IDENTITY = re.compile(rf"{_GUID}\\{_GUID}")
_VERSION = r"[0-9]{1,8}(?:\.[0-9]{1,8}){2}"
_BUILD = rf"ms-quarantine-for-splunk-soar-runbook-{_VERSION}\+sha256\.[0-9a-f]{{64}}"
_DIAGNOSTIC_ERRORS = frozenset(
    {
        "diagnostic_inspection_failed",
        "diagnostic_inspection_unconfirmed",
        DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE,
        DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE,
    }
)


class ConnectivitySummary(ActionOutput):
    app_version: str
    runbook_version: str
    runbook_build_id: str
    version_warning: str


class DispositionParams(Params):
    identity: str = Param(
        description=r"Exact quarantine identity in GUID1\GUID2 format. Use container:data.quarantine_identity from the SOAR event or linked ES finding container.",
        primary=True,
    )


class InspectReleaseEnvironmentParams(Params):
    identity: str = Param(
        description="Exact quarantine Identity in GUID1\\GUID2 form. The diagnose action reads this identity but never releases or denies it.",
        primary=True,
    )
    include_rbac: bool | None = Param(
        description="Explicitly opt in to tenant-wide read-only RBAC and role-group diagnostics after the exact quarantine identity has been bound. Defaults to false.",
        default=False,
    )


class PermissionQueryErrorsOutput(ActionOutput):
    query: str
    cmdlet: str
    error: str
    exception_type: str


class InspectReleaseEnvironmentOutput(ActionOutput):
    action: str
    identity: str
    status: str
    inspected_at_utc: str
    result_count: float
    observed_identity: str
    observed_release_status: str
    inspection_error: str
    handling: str
    error_code: str
    runbook_version: str
    runbook_source_revision: str
    runbook_build_id: str
    powershell_version: str
    powershell_edition: str
    powershell_platform: str
    powershell_os: str
    exchange_auth_method: str
    exchange_online_management_version: str
    exchange_online_management_path: str
    cmdlet_name: str
    cmdlet_command_type: str
    cmdlet_module_name: str
    cmdlet_module_version: str
    cmdlet_default_parameter_set: str
    cmdlet_parameter_sets: str
    cmdlet_metadata_error: str
    exchange_auth_method_source: str
    exchange_organization: str
    exchange_organization_source: str
    exchange_connection_metadata: str
    exchange_connection_metadata_error: str
    cmdlet_contract_id: str
    cmdlet_expected_argument_names: str
    cmdlet_parameter_names: str
    permission_queries_read_only: bool
    include_rbac: bool
    rbac_included: bool
    rbac_diagnostics_status: str = OutputField(example_values=["complete", "partial", "not_evaluated", "not_requested"])
    rbac_diagnostics_reason: str
    rbac_empty_contracts: list[str]
    rbac_required_cmdlets: list[str]
    rbac_available_cmdlets: list[str]
    missing_cmdlets: list[str]
    missing_cmdlet_count: float
    read_roles: str
    export_roles: str
    release_to_all_roles: str
    release_deny_roles: str
    quarantine_role_present: bool
    quarantine_role_groups: str
    matched_quarantine_role_groups: str
    managed_identity_claims_status: str
    managed_identity_app_id: str
    managed_identity_object_id: str
    service_principal_registered: bool
    registered_service_principal_identity: str
    registered_service_principal_app_id: str
    registered_service_principal_object_id: str
    role_group_membership_evaluated: bool
    quarantine_group_membership_confirmed: bool
    quarantine_administrator_membership_confirmed: bool
    role_assignment_matches_identity: bool
    quarantine_role_group_total_count: float
    quarantine_role_group_inspected_count: float
    quarantine_role_group_inspection_truncated: bool
    permission_query_error_count: float
    permission_query_error_retained_count: float
    permission_query_error_dropped_count: float
    permission_query_errors_truncated: bool
    permission_query_errors: list[PermissionQueryErrorsOutput]
    cmdlet_proxy_diagnostics: str
    cmdlet_proxy_diagnostics_status: str


class ReleaseQuarantineMessageOutput(ActionOutput):
    status: str = OutputField(example_values=["released", "already_released"])
    message: str = OutputField(example_values=["Quarantine release confirmed by Exchange."])
    identity: str = OutputField(example_values=["c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"])
    action: str = OutputField(example_values=["release"])
    runbook_version: str = OutputField(example_values=["1.1.0"])
    azure_job_id: str = OutputField(example_values=["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"])
    last_job_status: str = OutputField(example_values=["Running", "Stopped", "Completed"])
    observed_release_status: str = OutputField(example_values=["Released", "PreparingToRelease"])
    observed_identity: str = OutputField(example_values=["c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"])
    outcome: str
    error_code: str
    error: bool
    runbook_build_id: str


class DenyQuarantineReleaseOutput(ActionOutput):
    status: str = OutputField(example_values=["denied", "already_denied"])
    message: str = OutputField(example_values=["Quarantine deny confirmed by Exchange."])
    identity: str = OutputField(example_values=["c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"])
    action: str = OutputField(example_values=["deny"])
    runbook_version: str = OutputField(example_values=["1.1.0"])
    azure_job_id: str = OutputField(example_values=["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"])
    last_job_status: str = OutputField(example_values=["Running", "Stopped", "Completed"])
    observed_release_status: str = OutputField(example_values=["Denied", "PreparingToRelease"])
    observed_identity: str = OutputField(example_values=["c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"])
    outcome: str
    error_code: str
    error: bool
    runbook_build_id: str


class DispositionSummary(ActionOutput):
    status: str
    outcome: str
    azure_job_id: str
    last_job_status: str
    runbook_version: str
    observed_release_status: str


class InspectSummary(ActionOutput):
    status: str
    handling: str
    runbook_version: str
    runbook_build_id: str
    observed_release_status: str
    cmdlet_proxy_diagnostics_status: str
    rbac_diagnostics_status: str
    rbac_diagnostics_reason: str
    missing_cmdlets: list[str]
    missing_cmdlet_count: int
    quarantine_role_present: bool
    service_principal_registered: bool
    role_assignment_matches_identity: bool
    quarantine_role_present_evaluation: str
    service_principal_registered_evaluation: str
    role_assignment_matches_identity_evaluation: str
    quarantine_role_group_total_count: int
    quarantine_role_group_inspected_count: int
    quarantine_role_group_inspection_truncated: bool
    permission_query_error_count: int
    permission_query_error_retained_count: int
    permission_query_error_dropped_count: int
    permission_query_errors_truncated: bool


def build_azure(asset: BaseAsset) -> MSQuarantineForSplunkSOARUtils:
    """Build a fresh Azure client from the SDK asset, without making requests."""
    field_names = {
        "webhook_url": "webhook_url",
        "tenant_id": "azure_tenant_id",
        "client_id": "azure_client_id",
        "client_secret": "azure_client_secret",  # pragma: allowlist secret -- asset field name, not a value
        "subscription_id": "azure_subscription_id",
        "resource_group": "azure_resource_group",
        "automation_account": "azure_automation_account",
    }
    required = {}
    for arg, field in field_names.items():
        value = getattr(asset, field, None)
        if not isinstance(value, str) or not value.strip():
            raise AssetMisconfiguration(f"'{field}' is required but empty.")
        required[arg] = value.strip()

    def seconds(field: str, default: int, lower: int, upper: int) -> int:
        value = getattr(asset, field, None)
        if value is None:
            return default
        try:
            value = int(value) if isinstance(value, float) and value.is_integer() else parse_strict_integer(value)
        except ValueError:
            raise AssetMisconfiguration(f"'{field}' must be a whole number.") from None
        if not lower <= value <= upper:
            raise AssetMisconfiguration(f"'{field}' must be between {lower} and {upper}.")
        return value

    try:
        return MSQuarantineForSplunkSOARUtils(
            **required,
            poll_interval=seconds("poll_interval_seconds", 5, 1, 60),
            poll_timeout=seconds("poll_timeout_seconds", 600, 600, 3600),
            retain_chunked_base64=False,
            exchange_organization=getattr(asset, "exchange_organization", None),
            progress_callback=logger.progress,
        )
    except ValueError as exc:
        # The transport configuration validators use fixed, secret-free errors.
        raise AssetMisconfiguration(str(exc)) from None


def _identity(value: str) -> str:
    identity = value.strip()
    if not identity:
        raise ValueError("The 'identity' parameter is required.")
    if not _IDENTITY.fullmatch(identity):
        raise ValueError(
            r"Invalid identity format. Expected GUID1\GUID2; use container:data.quarantine_identity from the SOAR event or linked ES finding container."
        )
    return identity


def _validate_list(output: dict) -> None:
    messages = output.get("messages")
    if isinstance(messages, dict):
        messages = [messages]
    if not isinstance(messages, list) or any(not isinstance(item, dict) for item in messages):
        raise AutomationError("Runbook protocol error: 'messages' must contain JSON objects.")
    count = output.get("count")
    if count is not None:
        try:
            count = parse_strict_integer(count)
        except ValueError as exc:
            raise AutomationError("Runbook protocol error: 'count' must be an integer.") from exc
        if not isinstance(output["messages"], dict) and count != len(messages):
            raise AutomationError("Runbook protocol error: 'count' does not match the 'messages' array length.")
    for item in messages:
        identity = item.get("Identity")
        if not isinstance(identity, str) or not _IDENTITY.fullmatch(identity):
            raise AutomationError(r"Runbook protocol error: list Identity must be an exact GUID1\GUID2.")
        recipients = item.get("RecipientAddress")
        if recipients is None or isinstance(recipients, str):
            continue
        if not isinstance(recipients, list) or not all(value is None or isinstance(value, str) for value in recipients):
            raise AutomationError("Runbook protocol error: RecipientAddress must be a string, an array of strings, or null.")


def _map_error(azure: MSQuarantineForSplunkSOARUtils, exc: AutomationError, label: str) -> str:
    if isinstance(exc, RunbookActionError):
        message = azure.redact_sensitive_text(exc.result.get("message") or str(exc), max_chars=None)
    else:
        error = azure.redact_sensitive_text(exc)
        if isinstance(exc, TokenError):
            message = f"Failed to acquire Azure AD token for '{label}': {error}. Check azure_tenant_id, azure_client_id, azure_client_secret."
        elif isinstance(exc, WebhookError):
            message = f"Webhook failed for '{label}': {error}. Check webhook_url and Azure Automation; no second webhook was sent."
        elif isinstance(exc, JobTimeoutError):
            message = f"Action '{label}' timed out: {error}. The result is unknown; the Azure job may still run and the Exchange command may already have executed."
        elif isinstance(exc, JobFailedError):
            message = f"Azure Automation job failed for '{label}': {error}"
        else:
            message = f"Action '{label}' failed: {error}"
    if job_id := getattr(exc, "job_id", ""):
        safe_id = azure.redact_sensitive_text(job_id)
        if safe_id not in message:
            message += f" Azure job ID: {safe_id}."
        message += " Inspect the job in Azure Automation for the reported cause."
    return message


def _redact_data(azure: MSQuarantineForSplunkSOARUtils, value):
    """Keep data types and nested diagnostic details while excluding configured secrets."""
    if isinstance(value, dict):
        return {key: _redact_data(azure, item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_data(azure, item) for item in value]
    if isinstance(value, str):
        return azure.redact_sensitive_text(value, max_chars=None)
    return value


def _result(
    status: bool,
    message: str,
    params: Params,
    data: dict | None = None,
    summary: dict | None = None,
) -> ActionResult:
    result = ActionResult(status, message, params.model_dump())
    if data is not None:
        result.add_data(data)
    if summary is not None:
        result.set_summary(summary)
    return result


def _inspect_summary(data: dict) -> dict:
    summary = {
        name: data.get(name, "")
        for name in (
            "status",
            "handling",
            "runbook_version",
            "runbook_build_id",
            "observed_release_status",
            "rbac_diagnostics_status",
            "rbac_diagnostics_reason",
        )
    }
    summary["cmdlet_proxy_diagnostics_status"] = data.get("cmdlet_proxy_diagnostics_status", "not_available")
    summary["missing_cmdlets"] = (
        [x for x in (data.get("missing_cmdlets") or []) if isinstance(x, str)] if isinstance(data.get("missing_cmdlets"), list) else []
    )
    for name in (
        "missing_cmdlet_count",
        "quarantine_role_group_total_count",
        "quarantine_role_group_inspected_count",
        "permission_query_error_count",
        "permission_query_error_retained_count",
        "permission_query_error_dropped_count",
    ):
        count = data.get(
            name,
            summary.get("permission_query_error_count", 0) if name == "permission_query_error_retained_count" else 0,
        )
        try:
            summary[name] = parse_strict_integer(count or 0)
        except ValueError:
            summary[name] = 0
    for name in (
        "quarantine_role_group_inspection_truncated",
        "permission_query_errors_truncated",
    ):
        summary[name] = data.get(name) is True
    for name in (
        "quarantine_role_present",
        "service_principal_registered",
        "role_assignment_matches_identity",
    ):
        value = data.get(name)
        summary[f"{name}_evaluation"] = "not_evaluated"
        if isinstance(value, bool):
            summary[name] = value
            summary[f"{name}_evaluation"] = str(value).lower()
    return summary


def _inspect(params: InspectReleaseEnvironmentParams, asset: BaseAsset, azure_factory: Callable) -> ActionResult:
    try:
        identity = _identity(params.identity)
        azure = azure_factory(asset)
    except (ValueError, AssetMisconfiguration) as exc:
        return _result(False, str(exc), params)

    include_rbac = params.include_rbac is True
    logger.progress(f"Starting read-only Azure Automation diagnosis (include_rbac={include_rbac}).")
    try:
        output = azure.run_action("diagnose", identity=identity, include_rbac=include_rbac)
    except RunbookActionError as exc:
        code = exc.result.get("error_code")
        if not isinstance(code, str) or code not in _DIAGNOSTIC_ERRORS:
            return _result(False, _map_error(azure, exc, "inspect release environment"), params)
        output = exc.result.get("details")
        data = _redact_data(azure, output) if isinstance(output, dict) else {}
        data.update(
            error_code=code,
            runbook_version=_redact_data(azure, exc.result.get("runbook_version") or data.get("runbook_version", "")),
        )
        summary = _inspect_summary(data)
        summary.update(status=data.get("status", "inspection_failed"), handling="read_only")
        return _result(
            False,
            _map_error(azure, exc, "inspect release environment"),
            params,
            data,
            summary,
        )
    except AutomationError as exc:
        return _result(False, _map_error(azure, exc, "inspect release environment"), params)

    observed_identity = output.get("observed_identity")
    observed_status = output.get("observed_release_status")
    if (
        output.get("status") != "inspected"
        or not isinstance(observed_identity, str)
        or observed_identity.strip().casefold() != identity.casefold()
        or not isinstance(observed_status, str)
        or not observed_status.strip()
        or (include_rbac and output.get("rbac_diagnostics_status") != "complete")
    ):
        return _result(False, "Runbook did not confirm the requested inspection.", params)
    data = _redact_data(azure, output)
    summary = _inspect_summary(data)
    message = (
        "Read-only release environment inspected; no release or deny cmdlet was executed. "
        f"Runbook: {summary['runbook_version'] or 'not reported'}; RBAC: {summary['rbac_diagnostics_status'] or 'not reported'}."
    )
    return _result(True, message, params, data, summary)


@contextmanager
def _execution_lock(namespace: str, resource: str, *, parent: Path | None = None) -> Iterator[None]:
    """Use a private process-held lock on the shared local execution host."""
    uid = os.geteuid()
    root = Path(gettempdir()) if parent is None else parent
    directory = root / f"msq-soar-{namespace}-{uid}"
    directory.mkdir(mode=0o700, exist_ok=True, parents=True)
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(dir_fd)
        if info.st_uid != uid or info.st_mode & 0o077:
            raise PermissionError("Execution lock directory is not private.")
        key = hashlib.sha256(resource.encode("ascii")).hexdigest()
        fd = os.open(key, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
                raise PermissionError("Execution lock file is not private.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            # Never unlink: a concurrent worker may hold a descriptor for this inode.
            os.close(fd)
    finally:
        os.close(dir_fd)


def _disposition_lock(tenant: str, identity: str):
    return _execution_lock("disposition", f"{tenant}|{identity.lower()}")


def _disposition_failure(
    params: DispositionParams,
    action: str,
    identity: str,
    outcome: str,
    code: str,
    message: str,
    *,
    data: dict | None = None,
    job_id: str = "",
    last_status: str = "",
) -> ActionResult:
    data = dict(
        data or {},
        action=action,
        identity=identity,
        azure_job_id=job_id,
        error=True,
        error_code=code,
        outcome=outcome,
        message=message,
    )
    if last_status:
        data["last_job_status"] = last_status
    summary = {
        "status": "error",
        "outcome": outcome,
        "azure_job_id": job_id,
        "last_job_status": last_status,
    }
    summary.update({key: data[key] for key in ("runbook_version", "observed_release_status") if data.get(key)})
    return _result(False, message, params, data, summary)


def _run_disposition(
    params: DispositionParams,
    action: str,
    identity: str,
    azure: MSQuarantineForSplunkSOARUtils,
) -> ActionResult:
    try:
        azure.get_mgmt_token()
    except AutomationError as exc:
        return _disposition_failure(params, action, identity, "not_executed", "azure_reader_unavailable", _map_error(azure, exc, action))
    job_id = ""
    logger.progress(f"Starting Azure Automation action={action}.")
    try:
        job_id = azure.fire_webhook(action, identity=identity)
        logger.progress(f"Waiting for Azure Automation action={action} result.")
        output = azure.wait_for_action_result(job_id, action=action, identity=identity)
    except AutomationError as exc:
        # The transport has already validated error envelopes and their requested identity.
        raw_data = exc.result if isinstance(exc, RunbookActionError) else {}
        code = raw_data.get("error_code", raw_data.get("code"))
        if not isinstance(code, str) or not code.strip():
            code = "outcome_unknown"
        outcome = {
            "precondition_unconfirmed": "not_executed",
            "disposition_failed": "failed",
            "release_pending": "pending",
        }.get(code, "unknown")
        message = _map_error(azure, exc, action)
        if outcome == "unknown":
            message += " Do not retry before checking Azure job history and the current Exchange status."
        return _disposition_failure(
            params,
            action,
            identity,
            outcome,
            azure.redact_sensitive_text(code),
            message,
            data=_redact_data(azure, raw_data),
            job_id=azure.redact_sensitive_text(job_id or getattr(exc, "job_id", "") or ""),
            last_status=azure.redact_sensitive_text(getattr(exc, "last_status", "") or ""),
        )

    except Exception:
        return _disposition_failure(
            params,
            action,
            identity,
            "unknown",
            "outcome_unknown",
            "Could not confirm the Azure submission or result. Verify Exchange status before retrying.",
            job_id=azure.redact_sensitive_text(job_id),
        )

    try:
        data = _redact_data(azure, dict(output, azure_job_id=job_id, outcome="confirmed"))
        message = data.get("message") or f"Quarantine {action} confirmed by Exchange."
        data["message"] = message
        summary = {
            "status": data["status"],
            "outcome": "confirmed",
            "azure_job_id": data["azure_job_id"],
            "observed_release_status": data["observed_release_status"],
            "runbook_version": data.get("runbook_version", ""),
        }
        return _result(True, message, params, data, summary)
    except Exception:
        return _disposition_failure(
            params,
            action,
            identity,
            "unknown",
            "outcome_unknown",
            "Could not validate the completed Azure job. Verify Exchange status before retrying.",
            job_id=azure.redact_sensitive_text(job_id),
        )


def _dispose(params: DispositionParams, asset: BaseAsset, action: str, azure_factory: Callable) -> ActionResult:
    try:
        identity = _identity(params.identity)
    except ValueError as exc:
        return _disposition_failure(params, action, "", "not_executed", "invalid_identity", str(exc))
    raw_tenant = getattr(asset, "azure_tenant_id", "")
    tenant = raw_tenant.strip().lower() if isinstance(raw_tenant, str) else ""
    if not re.fullmatch(_GUID, tenant):
        return _disposition_failure(
            params,
            action,
            identity,
            "not_executed",
            "invalid_tenant_id",
            "Configure azure_tenant_id as the Microsoft Entra tenant UUID.",
        )
    try:
        azure = azure_factory(asset)
    except AssetMisconfiguration as exc:
        return _disposition_failure(
            params,
            action,
            identity,
            "not_executed",
            "invalid_asset_configuration",
            str(exc),
        )

    with ExitStack() as stack:
        try:
            stack.enter_context(_disposition_lock(tenant, identity))
        except BlockingIOError:
            return _disposition_failure(
                params,
                action,
                identity,
                "not_executed",
                "operation_in_progress",
                "A Release or Deny operation is already in progress for this quarantine identity. No job was submitted.",
            )
        except OSError:
            return _disposition_failure(
                params,
                action,
                identity,
                "not_executed",
                "disposition_lock_unavailable",
                "Could not acquire a private disposition lock. No job was submitted.",
            )
        return _run_disposition(params, action, identity, azure)


def register_connectivity(app: App, *, app_version: str, azure_factory: Callable = build_azure) -> None:
    """Register the connectivity test before the other SDK actions."""

    def test_connectivity(_params: Params, _soar, asset: BaseAsset) -> ActionResult:
        azure = azure_factory(asset)
        try:
            logger.progress("Step 1/3: Acquiring Azure AD Management API token.")
            azure.get_mgmt_token()
            logger.progress("Step 2/3: Starting protected list and waiting for completion.")
            output = azure.run_action("list", validate_result=_validate_list)
        except AutomationError as exc:
            raise ActionFailure(_map_error(azure, exc, "test connectivity")) from None

        version, build = output.get("runbook_version"), output.get("runbook_build_id")
        logger.progress("Step 3/3: Validated the protected list result.")
        evidence = {}
        if re.fullmatch(_VERSION, app_version):
            evidence["app_version"] = app_version
        if isinstance(version, str) and re.fullmatch(_VERSION, version):
            evidence["runbook_version"] = version
        if isinstance(build, str) and re.fullmatch(_BUILD, build):
            evidence["runbook_build_id"] = build

        message = "Connectivity test passed."
        if not {"app_version", "runbook_version"} <= evidence.keys():
            evidence["version_warning"] = "App/runbook version comparison unavailable; verify the installed pair against the release package."
        elif app_version != version:
            evidence["version_warning"] = (
                f"App version {app_version} differs from runbook version {version}. "
                "Install the runbook from the same release before enabling automation."
            )
        if warning := evidence.get("version_warning"):
            message += " Warning: " + warning
        result = ActionResult(True, message)
        result.set_summary(evidence)
        return result

    register_special(
        app,
        ActionMeta(
            action="test connectivity",
            identifier="test_connectivity",
            type="test",
            description="Verify Azure authentication, webhook, job polling and protected Exchange list output.",
            read_only=True,
        ),
        ConnectivitySummary,
        test_connectivity,
    )


def register_quarantine_actions(app: App, *, azure_factory: Callable = build_azure) -> None:
    def register_disposition(operation, name, description, output):
        register_special(
            app,
            ActionMeta(
                action=name,
                identifier=name.replace(" ", "_"),
                description=description,
                verbose=f"Submits at most one job for an exact quarantine identity. Success requires Exchange to confirm {'Released' if operation == 'release' else 'Denied'}. A timeout does not cancel the job; inspect unknown or pending outcomes before attempting another disposition.",
                type="correct",
                read_only=False,
                parameters=DispositionParams,
                output=output,
            ),
            DispositionSummary,
            lambda params, _soar, asset: _dispose(params, asset, operation, azure_factory),
            invalid_asset=lambda params: _disposition_failure(
                params,
                operation,
                "",
                "not_executed",
                "invalid_asset_configuration",
                "Invalid asset configuration. No job was submitted.",
            ),
        )

    register_disposition(
        "deny",
        "deny quarantine release",
        "Deny a user's request to release a quarantined message",
        DenyQuarantineReleaseOutput,
    )
    register_disposition(
        "release",
        "release quarantine message",
        "Release a quarantined message to all original recipients",
        ReleaseQuarantineMessageOutput,
    )

    register_special(
        app,
        ActionMeta(
            action="inspect release environment",
            identifier="inspect_release_environment",
            description="Read-only inspection of the runbook, Exchange cmdlets and one exact quarantine identity; tenant RBAC diagnostics require opt-in",
            verbose="Checks the exact quarantine identity without releasing or denying it. Set include_rbac=true to also inspect tenant role contracts and relevant role-group membership.",
            type="investigate",
            read_only=True,
            parameters=InspectReleaseEnvironmentParams,
            output=InspectReleaseEnvironmentOutput,
        ),
        InspectSummary,
        lambda params, _soar, asset: _inspect(params, asset, azure_factory),
    )
