# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
#
# MS Defender Quarantine Manager - Splunk SOAR Connector (Azure Automation)
# ================================================================
#
# Manages Microsoft Defender quarantined emails via Azure Automation.
# Each action fires a webhook, polls for job completion, then reads output.
#
# References:
#   Splunk SOAR connector development:
#     https://help.splunk.com/en/splunk-soar/soar-cloud/develop-apps/develop-apps/app-structure/connector-module-development
#   Vault API:
#     https://docs.splunk.com/Documentation/SOAR/current/PlaybookAPI/VaultAPI

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from ms_quarantine_for_splunk_soar_ingestion import NativeIngestionMixin
from ms_quarantine_for_splunk_soar_mail import (
    ARTIFACT_CEF_KEYS as ARTIFACT_CEF_KEYS,
    ARTIFACT_EMAIL_FIELDS as ARTIFACT_EMAIL_FIELDS,
    ARTIFACT_FIELD_CONFIG_KEYS as ARTIFACT_FIELD_CONFIG_KEYS,
    ARTIFACT_FIELD_ORDER as ARTIFACT_FIELD_ORDER,
    ARTIFACT_FIELD_SET as ARTIFACT_FIELD_SET,
    ARTIFACT_LAYOUT_COMBINED as ARTIFACT_LAYOUT_COMBINED,
    ARTIFACT_LAYOUT_SEPARATE as ARTIFACT_LAYOUT_SEPARATE,
    DEFAULT_ARTIFACT_FIELDS as DEFAULT_ARTIFACT_FIELDS,
    DEFAULT_ARTIFACT_FIELD_SET as DEFAULT_ARTIFACT_FIELD_SET,
    DEFAULT_WORKER_TERMINAL_RETENTION_DAYS as DEFAULT_WORKER_TERMINAL_RETENTION_DAYS,
    IDENTITY_REGEX as IDENTITY_REGEX,
    LEGACY_ARTIFACT_ACTION_KEYS as LEGACY_ARTIFACT_ACTION_KEYS,
    MAX_ARTIFACT_ADDRESSES_PER_FIELD as MAX_ARTIFACT_ADDRESSES_PER_FIELD,
    MAX_ARTIFACT_HEADER_LENGTH as MAX_ARTIFACT_HEADER_LENGTH,
    MAX_ARTIFACT_VALUE_LENGTH as MAX_ARTIFACT_VALUE_LENGTH,
    MAX_ARTIFACT_WARNING_LENGTH as MAX_ARTIFACT_WARNING_LENGTH,
    MAX_WORKER_TERMINAL_RETENTION_DAYS as MAX_WORKER_TERMINAL_RETENTION_DAYS,
    MIN_WORKER_TERMINAL_RETENTION_DAYS as MIN_WORKER_TERMINAL_RETENTION_DAYS,
    ON_POLL_CANDIDATE_PAGE_SIZE as ON_POLL_CANDIDATE_PAGE_SIZE,
    ON_POLL_MAX_CONTAINERS as ON_POLL_MAX_CONTAINERS,
    VALID_ARTIFACT_LAYOUTS as VALID_ARTIFACT_LAYOUTS,
    _parse_config_integer as _parse_config_integer,
    _parse_poll_integer as _parse_poll_integer,
    normalize_recipient_address as normalize_recipient_address,
    parse_artifact_asset_config as parse_artifact_asset_config,
    parse_artifact_fields as parse_artifact_fields,
    parse_boolean_parameter as parse_boolean_parameter,
    validate_identity_format as validate_identity_format,
    QuarantineMail,
)
from ms_quarantine_for_splunk_soar_utils import (
    DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE,
    DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE,
    AutomationError,
    JobFailedError,
    JobTimeoutError,
    MSQuarantineForSplunkSOARUtils,
    RunbookActionError,
    TokenError,
    WebhookError,
    normalize_exchange_connection_settings,
    redact_sensitive_text,
    validate_webhook_url,
)


try:
    import phantom.rules as phrules
except ImportError:
    phrules = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPORT_VAULT = "vault"
EXPORT_INLINE = "inline"
VALID_EXPORT_MODES = {EXPORT_VAULT, EXPORT_INLINE}
# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------


class MSQuarantineForSplunkSOARConnector(NativeIngestionMixin, QuarantineMail, BaseConnector):
    """
    Splunk SOAR connector for Microsoft Defender Quarantine management
    via Azure Automation Runbook.

    All actions use the same flow:
        1. POST webhook  → job_id
        2. Poll job      → wait until Completed / Failed
        3. GET output    → parse JSON from Write-Output
    """

    def __init__(self):
        super().__init__()
        self._utils = None
        self._export_mode = None
        self._asset_artifact_options = None
        self._on_poll_max_containers = 10
        self._worker_terminal_retention_days = DEFAULT_WORKER_TERMINAL_RETENTION_DAYS

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def initialize(self):
        """
        Load and validate asset configuration.
        Called once before any action.
        """
        config = self.get_config()

        # Required string fields
        required = [
            "webhook_url",
            "azure_tenant_id",
            "azure_client_id",
            "azure_client_secret",
            "azure_subscription_id",
            "azure_resource_group",
            "azure_automation_account",
        ]
        for field in required:
            if not config.get(field, "").strip():
                return self.set_status(phantom.APP_ERROR, f"Asset configuration error: '{field}' is required but empty.")

        # Hidden legacy controls retain valid saved values, but stale invalid
        # values must not block an asset whose UI can no longer repair them.
        legacy_mode = config.get("export_mode", EXPORT_VAULT)
        legacy_mode = legacy_mode.strip().lower() if isinstance(legacy_mode, str) else ""
        self._export_mode = legacy_mode if legacy_mode in VALID_EXPORT_MODES else EXPORT_VAULT
        artifact_config = dict(config)
        try:
            parse_boolean_parameter(
                artifact_config.get("create_email_artifacts", False),
                "create_email_artifacts",
                source="Asset configuration field",
            )
        except ValueError:
            artifact_config["create_email_artifacts"] = False

        try:
            # The removed legacy enable switch must not prevent users from
            # deselecting all optional mail fields in the current import UI.
            self._asset_artifact_options = parse_artifact_asset_config(
                artifact_config,
                allow_empty_fields=True,
            )
        except ValueError as exc:
            return self.set_status(
                phantom.APP_ERROR,
                f"Asset configuration error: {exc}",
            )

        try:
            poll_interval = _parse_config_integer(
                config.get("poll_interval_seconds", 5),
                "poll_interval_seconds",
            )
            poll_timeout = _parse_config_integer(
                config.get("poll_timeout_seconds", 600),
                "poll_timeout_seconds",
            )
            raw_on_poll_max = config.get("on_poll_max_containers")
            on_poll_max_containers = 10 if raw_on_poll_max in (None, "") else _parse_poll_integer(raw_on_poll_max)
            raw_worker_retention = config.get("worker_terminal_retention_days")
            worker_terminal_retention_days = (
                DEFAULT_WORKER_TERMINAL_RETENTION_DAYS
                if raw_worker_retention in (None, "")
                else _parse_config_integer(raw_worker_retention, "worker_terminal_retention_days")
            )
        except (TypeError, ValueError) as exc:
            return self.set_status(
                phantom.APP_ERROR,
                "poll_interval_seconds, poll_timeout_seconds, and "
                "on_poll_max_containers, and "
                f"worker_terminal_retention_days must be integers. {exc}",
            )
        if poll_interval < 1 or poll_interval > 60:
            return self.set_status(phantom.APP_ERROR, "poll_interval_seconds must be between 1 and 60.")
        if poll_timeout < 600 or poll_timeout > 3600:
            return self.set_status(
                phantom.APP_ERROR,
                "poll_timeout_seconds must be between 600 and 3600. Values "
                "below 600 seconds are unsafe for Azure Automation cold "
                "starts and irreversible release/deny actions.",
            )
        if poll_timeout <= poll_interval:
            return self.set_status(phantom.APP_ERROR, "poll_timeout_seconds must be greater than poll_interval_seconds.")
        if on_poll_max_containers < 1 or on_poll_max_containers > ON_POLL_MAX_CONTAINERS:
            return self.set_status(
                phantom.APP_ERROR,
                f"on_poll_max_containers must be between 1 and {ON_POLL_MAX_CONTAINERS}.",
            )
        self._on_poll_max_containers = on_poll_max_containers
        if not (MIN_WORKER_TERMINAL_RETENTION_DAYS <= worker_terminal_retention_days <= MAX_WORKER_TERMINAL_RETENTION_DAYS):
            return self.set_status(
                phantom.APP_ERROR,
                "worker_terminal_retention_days must be between 1 and 365.",
            )
        self._worker_terminal_retention_days = worker_terminal_retention_days

        try:
            exchange_settings = normalize_exchange_connection_settings(
                organization=config.get("exchange_organization"),
            )
        except ValueError as exc:
            return self.set_status(
                phantom.APP_ERROR,
                f"Asset configuration error: {exc}",
            )

        try:
            webhook_url = validate_webhook_url(config["webhook_url"])
        except ValueError as exc:
            return self.set_status(phantom.APP_ERROR, str(exc))

        self._utils = MSQuarantineForSplunkSOARUtils(
            webhook_url=webhook_url,
            tenant_id=config["azure_tenant_id"].strip(),
            client_id=config["azure_client_id"].strip(),
            client_secret=config["azure_client_secret"].strip(),
            subscription_id=config["azure_subscription_id"].strip(),
            resource_group=config["azure_resource_group"].strip(),
            automation_account=config["azure_automation_account"].strip(),
            poll_interval=poll_interval,
            poll_timeout=poll_timeout,
            # Public export is retired; native import always stores EML in
            # Vault, independently of hidden legacy asset values.
            retain_chunked_base64=False,
            exchange_organization=exchange_settings.get("organization"),
            progress_callback=self.save_progress,
        )

        return phantom.APP_SUCCESS

    def finalize(self):
        return phantom.APP_SUCCESS

    # -----------------------------------------------------------------------
    # Vault helpers
    # -----------------------------------------------------------------------


    def _store_in_vault(self, eml_bytes: bytes, identity: str, *, container_id=None, file_name=None) -> tuple:
        """
        Write EML bytes to the SOAR Vault.

        Returns:
            (True, vault_metadata_dict) on success
            (False, error_message_str)  on failure
        """
        if phrules is None:
            return False, ("phantom.rules is not available. Switch export_mode to 'inline' for testing outside SOAR.")

        file_name = file_name or self._safe_filename(identity)

        try:
            vault_tmp = phrules.Vault.get_vault_tmp_dir()
        except Exception:
            vault_tmp = tempfile.gettempdir()

        fd, tmp_path = tempfile.mkstemp(
            suffix=".eml",
            prefix="quarantine_",
            dir=vault_tmp,
        )

        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(eml_bytes)

            success, message, vault_id = phrules.vault_add(
                container=self.get_container_id() if container_id is None else container_id,
                file_location=tmp_path,
                file_name=file_name,
                metadata={
                    "source": "MS Quarantine for Splunk SOAR",
                    "identity": identity,
                },
            )
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass

        if not success:
            return False, f"Vault add failed: {message}"

        return True, {"vault_id": vault_id, "file_name": file_name}

    # -----------------------------------------------------------------------
    # Email artifact helpers
    # -----------------------------------------------------------------------


    def _artifact_options(self, param) -> dict:
        if not (LEGACY_ARTIFACT_ACTION_KEYS & set(param)):
            options = self._asset_artifact_options
            if options is None:
                options = parse_artifact_asset_config({})
            if not options["enabled"]:
                return {"enabled": False}
            layout = options["layout"]
            fields = options["fields"]
        else:
            # Compatibility path for playbooks generated against App <= 3.2.6.
            # The parameters are no longer declared in the action manifest,
            # but connector-side handling remains deterministic if SOAR sends
            # an already-compiled legacy parameter map.
            enabled = parse_boolean_parameter(
                param.get("create_email_artifacts", False),
                "create_email_artifacts",
            )
            if not enabled:
                return {"enabled": False}

            layout_value = param.get(
                "artifact_layout",
                ARTIFACT_LAYOUT_COMBINED,
            )
            if not isinstance(layout_value, str):
                raise ValueError("Parameter 'artifact_layout' must be 'combined' or 'separate'.")
            layout = layout_value.strip().lower()
            if layout not in VALID_ARTIFACT_LAYOUTS:
                raise ValueError("Parameter 'artifact_layout' must be 'combined' or 'separate'.")

            fields = parse_artifact_fields(param.get("artifact_fields"))

        if phrules is None or not callable(getattr(phrules, "add_artifact", None)):
            raise ValueError("SOAR artifact API is unavailable; email artifacts cannot be created in this runtime.")
        return {
            "enabled": True,
            "layout": layout,
            "fields": fields,
        }


    # -----------------------------------------------------------------------
    # Error mapping
    # -----------------------------------------------------------------------

    def _map_error(self, exc: Exception, action_label: str) -> str:
        """Preserve the real cause and known job, using native action messages."""
        safe_error = self._utils.redact_sensitive_text(exc) if self._utils is not None else redact_sensitive_text(str(exc))
        if isinstance(exc, RunbookActionError):
            message = self._runbook_error_message(exc)
        elif isinstance(exc, TokenError):
            message = (
                f"Failed to acquire Azure AD token for '{action_label}': {safe_error}. "
                "Check azure_tenant_id, azure_client_id, azure_client_secret."
            )
        elif isinstance(exc, WebhookError):
            message = f"Webhook failed for '{action_label}': {safe_error}. Check webhook_url and Azure Automation; no second webhook was sent."
        elif isinstance(exc, JobTimeoutError):
            message = (
                f"Action '{action_label}' timed out: {safe_error}. "
                "The result is unknown; the Azure job may still run and the "
                "Exchange command may already have executed."
            )
        elif isinstance(exc, JobFailedError):
            message = f"Azure Automation job failed for '{action_label}': {safe_error}"
        else:
            message = f"Action '{action_label}' failed: {safe_error}"
        job_id = getattr(exc, "job_id", "")
        if job_id:
            if job_id not in message:
                message += f" Azure job ID: {job_id}."
            message += " Inspect the job in Azure Automation for the reported cause."
        return message

    def _runbook_error_message(self, exc: RunbookActionError) -> str:
        """Return the exact validated Runbook message with secret defence."""
        result = exc.result if isinstance(exc.result, dict) else {}
        message = result.get("message")
        if not isinstance(message, str) or not message:
            message = str(exc)
        if self._utils is None:
            return redact_sensitive_text(message, max_chars=None)
        return self._utils.redact_sensitive_text(message, max_chars=None)

    # -----------------------------------------------------------------------
    # Small native intake state helpers
    # -----------------------------------------------------------------------


    @contextmanager
    def _operation_state_lock(self):
        """
        Serialize state-file read/modify/write on SOAR on-prem.

        BaseConnector.save_state() replaces the state file atomically, but a
        separate advisory lock is required to make the whole claim operation
        atomic across concurrent connector processes.
        """
        state_file = self.get_state_file_path()
        state_dir = os.path.dirname(state_file)
        os.makedirs(state_dir, exist_ok=True)
        lock_path = state_file + ".irreversible.lock"
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            with os.fdopen(lock_fd, "a+") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except Exception:
            try:
                os.close(lock_fd)
            except OSError:
                pass
            raise

    # -----------------------------------------------------------------------
    # Intake identity helpers
    # -----------------------------------------------------------------------


    @staticmethod
    def _diagnostic_message(record: dict) -> str:
        """Return a concise, non-secret diagnostic line for SOAR logs."""
        fields = (
            ("runbook", record.get("runbook_version", "")),
            ("build", record.get("runbook_build_id", "")),
            ("source", record.get("runbook_source_revision", "")),
            ("contract", record.get("cmdlet_contract_id", "")),
            ("powershell", record.get("powershell_version", "")),
            (
                "exo",
                record.get("exchange_online_management_version", ""),
            ),
            (
                "error_id",
                record.get("cmdlet_fully_qualified_error_id", ""),
            ),
            ("category", record.get("cmdlet_error_category", "")),
            ("auth", record.get("exchange_auth_method", "")),
            ("organization", record.get("exchange_organization", "")),
            ("request_id", record.get("cmdlet_request_id", "")),
            ("correlation_id", record.get("cmdlet_correlation_id", "")),
            ("prepost", record.get("observed_release_status_history", "")),
            ("attempts", record.get("verification_attempts", 0)),
        )
        return "; ".join(f"{name}={value}" for name, value in fields if value not in ("", None, 0))

    @staticmethod
    def _diagnostic_tri_state(value) -> str:
        """Render an evaluated boolean without turning unknown into false."""
        if value is None:
            return "not_evaluated"
        return "true" if value is True else "false"

    @classmethod
    def _rbac_diagnostic_message(cls, record: dict) -> str:
        """Return a compact result of the read-only tenant RBAC checks."""
        missing_cmdlets = ",".join(record.get("missing_cmdlets", []) or [])
        quarantine_role = cls._diagnostic_tri_state(record.get("quarantine_role_present"))
        service_principal = cls._diagnostic_tri_state(record.get("service_principal_registered"))
        assignment = cls._diagnostic_tri_state(record.get("role_assignment_matches_identity"))
        role_group_inspected = int(record.get("quarantine_role_group_inspected_count", 0) or 0)
        role_group_total = int(record.get("quarantine_role_group_total_count", 0) or 0)
        role_group_truncated = bool(record.get("quarantine_role_group_inspection_truncated", False))
        return "; ".join(
            (
                f"rbac={record.get('rbac_diagnostics_status', '')}",
                f"rbac_reason={record.get('rbac_diagnostics_reason', '')}",
                f"missing_cmdlets={missing_cmdlets or 'none'}",
                f"quarantine_role={quarantine_role}",
                f"service_principal_registered={service_principal}",
                f"quarantine_membership={assignment}",
                f"role_groups={role_group_inspected}/{role_group_total}",
                f"role_groups_truncated={str(role_group_truncated).lower()}",
                "query_errors=" + str(int(record.get("permission_query_error_count", 0) or 0)),
                "query_errors_retained="
                + str(
                    int(
                        record.get(
                            "permission_query_error_retained_count",
                            record.get("permission_query_error_count", 0),
                        )
                        or 0
                    )
                ),
                "query_errors_dropped=" + str(int(record.get("permission_query_error_dropped_count", 0) or 0)),
            )
        )

    @classmethod
    def _rbac_summary(cls, record: dict) -> dict:
        """Return truthful summary values; omit unknown legacy booleans."""
        summary = {
            "rbac_diagnostics_status": record.get("rbac_diagnostics_status", ""),
            "rbac_diagnostics_reason": record.get("rbac_diagnostics_reason", ""),
            "missing_cmdlet_count": int(record.get("missing_cmdlet_count", 0) or 0),
            "missing_cmdlets": list(record.get("missing_cmdlets", []) or []),
            "quarantine_role_group_total_count": int(record.get("quarantine_role_group_total_count", 0) or 0),
            "quarantine_role_group_inspected_count": int(record.get("quarantine_role_group_inspected_count", 0) or 0),
            "quarantine_role_group_inspection_truncated": bool(
                record.get(
                    "quarantine_role_group_inspection_truncated",
                    False,
                )
            ),
            "permission_query_error_count": int(record.get("permission_query_error_count", 0) or 0),
            "permission_query_error_retained_count": int(
                record.get(
                    "permission_query_error_retained_count",
                    record.get("permission_query_error_count", 0),
                )
                or 0
            ),
            "permission_query_error_dropped_count": int(record.get("permission_query_error_dropped_count", 0) or 0),
            "permission_query_errors_truncated": bool(record.get("permission_query_errors_truncated", False)),
        }
        for field in (
            "quarantine_role_present",
            "service_principal_registered",
            "role_assignment_matches_identity",
        ):
            value = record.get(field)
            summary[f"{field}_evaluation"] = cls._diagnostic_tri_state(value)
            if isinstance(value, bool):
                summary[field] = value
        return summary

    # -----------------------------------------------------------------------
    # Action: test connectivity
    # -----------------------------------------------------------------------

    def _handle_test_connectivity(self, param):
        """
        End-to-end connectivity test:
          1. Acquire Azure AD token
          2. Fire webhook (action=list)
          3. Poll until job completes
          4. Verify output is valid JSON

        This confirms webhook URL, Azure AD credentials, and polling all work.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Step 1/3: Acquiring Azure AD Management API token...")
        try:
            self._utils.get_mgmt_token()
        except TokenError as exc:
            return action_result.set_status(phantom.APP_ERROR, self._map_error(exc, "test connectivity"))
        self.save_progress("Token acquired.")

        self.save_progress("Step 2/3: Starting protected list and waiting for completion...")
        try:

            def validate_list(output):
                self.save_progress("Step 3/3: Validating the list result...")
                self._normalise_list_result(output)

            result = self._utils.run_action("list", validate_result=validate_list)
        except (WebhookError, TokenError, JobTimeoutError, JobFailedError, AutomationError) as exc:
            return action_result.set_status(phantom.APP_ERROR, self._map_error(exc, "test connectivity"))

        metadata, warning = self._runbook_version_evidence(result)
        action_result.update_summary(metadata)
        message = "Connectivity test passed. Webhook, Azure AD token, job polling, and Exchange Online connection all working."
        if warning:
            message += " Warning: " + warning
        return action_result.set_status(phantom.APP_SUCCESS, message)

    @staticmethod
    def _runbook_version_evidence(result):
        # Use the actual installed manifest, not the runbook's self-reported
        # fingerprint as a proxy for a release version.
        manifest = Path(__file__).with_name("ms_quarantine_for_splunk_soar.json")
        try:
            app_version = json.loads(manifest.read_text(encoding="utf-8"))["app_version"]
        except (OSError, ValueError, KeyError, TypeError):
            app_version = ""
        version = result.get("runbook_version")
        build_id = result.get("runbook_build_id")
        version_pattern = r"[0-9]{1,8}(?:\.[0-9]{1,8}){2}"
        build_pattern = rf"ms-quarantine-for-splunk-soar-runbook-{version_pattern}\+sha256\.[0-9a-f]{{64}}"
        summary = {}
        if isinstance(app_version, str) and re.fullmatch(version_pattern, app_version):
            summary["app_version"] = app_version
        if isinstance(version, str) and re.fullmatch(version_pattern, version):
            summary["runbook_version"] = version
        if isinstance(build_id, str) and re.fullmatch(build_pattern, build_id):
            summary["runbook_build_id"] = build_id
        if not {"app_version", "runbook_version"} <= summary.keys():
            warning = "App/runbook version comparison unavailable; verify the installed pair against the release package."
        elif app_version != version:
            warning = (
                f"App version {app_version} differs from runbook version {version}. "
                "Install the runbook from the same release before enabling automation."
            )
        else:
            warning = ""
        if warning:
            summary["version_warning"] = warning
        return summary, warning

    # -----------------------------------------------------------------------
    # Shared Requested-list normalization
    # -----------------------------------------------------------------------


    # -----------------------------------------------------------------------
    # Action: on poll
    # -----------------------------------------------------------------------


    _ingest_failed = staticmethod(phantom.is_fail)
    _ingest_status = staticmethod(lambda success: phantom.APP_SUCCESS if success else phantom.APP_ERROR)

    def _ingest_action_result(self, param):
        return self.add_action_result(ActionResult(dict(param)))

    def _handle_on_es_poll(self, param):
        return self._run_native_poll(param, require_es=True)

    def _handle_on_poll(self, param):
        return self._run_native_poll(param)

    # -----------------------------------------------------------------------
    # Action: get quarantine message
    # -----------------------------------------------------------------------

    # -----------------------------------------------------------------------
    # Action: inspect release environment
    # -----------------------------------------------------------------------

    def _handle_inspect_release_environment(self, param):
        """Read runtime/cmdlet metadata and one exact quarantine identity."""
        action_result = self.add_action_result(ActionResult(dict(param)))

        identity = str(param.get("identity", "") or "").strip()
        if not identity:
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter is required.",
            )
        format_error = validate_identity_format(identity)
        if format_error:
            return action_result.set_status(phantom.APP_ERROR, format_error)
        try:
            include_rbac = parse_boolean_parameter(
                param.get("include_rbac", False),
                "include_rbac",
            )
        except ValueError as exc:
            return action_result.set_status(phantom.APP_ERROR, str(exc))

        self.save_progress(f"Firing read-only webhook: action=diagnose, identity={identity}, include_rbac={include_rbac}")
        try:
            result = self._utils.run_action(
                "diagnose",
                identity=identity,
                include_rbac=include_rbac,
            )
        except RunbookActionError as exc:
            exact_error = self._runbook_error_message(exc)
            if exc.result.get("error_code") not in {
                "diagnostic_inspection_failed",
                "diagnostic_inspection_unconfirmed",
                DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE,
                DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE,
            }:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    self._map_error(exc, "inspect release environment"),
                )
            details = dict(exc.result.get("details", {}))
            details["error_code"] = str(exc.result.get("error_code", ""))
            details["runbook_version"] = str(exc.result.get("runbook_version", ""))
            action_result.add_data(details)
            summary = {
                "status": details.get("status", "inspection_failed"),
                "handling": "read_only",
                "runbook_version": details.get("runbook_version", ""),
                "runbook_build_id": details.get("runbook_build_id", ""),
                "observed_release_status": details.get(
                    "observed_release_status",
                    "",
                ),
            }
            summary["cmdlet_proxy_diagnostics_status"] = details.get("cmdlet_proxy_diagnostics_status", "not_available")
            summary.update(self._rbac_summary(details))
            action_result.update_summary(summary)
            return action_result.set_status(
                phantom.APP_ERROR,
                exact_error,
            )
        except (
            TokenError,
            WebhookError,
            JobTimeoutError,
            JobFailedError,
            AutomationError,
        ) as exc:
            return action_result.set_status(
                phantom.APP_ERROR,
                self._map_error(exc, "inspect release environment"),
            )

        action_result.add_data(result)
        summary = {
            "status": result.get("status", ""),
            "handling": result.get("handling", ""),
            "runbook_version": result.get("runbook_version", ""),
            "runbook_build_id": result.get("runbook_build_id", ""),
            "observed_release_status": result.get(
                "observed_release_status",
                "",
            ),
        }
        summary["cmdlet_proxy_diagnostics_status"] = result.get("cmdlet_proxy_diagnostics_status", "not_available")
        summary.update(self._rbac_summary(result))
        action_result.update_summary(summary)
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Read-only release environment inspected; no release or deny "
            f"cmdlet was executed. {self._diagnostic_message(result)}; "
            f"{self._rbac_diagnostic_message(result)}.",
        )

    @contextmanager
    def _disposition_lock(self, tenant, identity):
        """Serialize same-tenant writes across workers sharing the local lock directory."""
        uid = os.geteuid()
        directory = os.path.join(tempfile.gettempdir(), f"msq-soar-disposition-{uid}")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(dir_fd)
            if info.st_uid != uid or info.st_mode & 0o077:
                raise PermissionError("Disposition lock directory is not private.")
            key = hashlib.sha256(f"{tenant}|{identity.lower()}".encode("ascii")).hexdigest()
            fd = os.open(
                key,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
                    raise PermissionError("Disposition lock file is not private.")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                # Closing releases the lock. Never unlink: another worker may
                # already hold an open descriptor for the same inode.
                os.close(fd)
        finally:
            os.close(dir_fd)

    @staticmethod
    def _disposition_error_result(
        action_result,
        action,
        identity,
        outcome,
        code,
        message,
        *,
        data=None,
        job_id="",
        last_status="",
    ):
        result = dict(data or {})
        result.update(
            {
                "action": action,
                "identity": identity,
                "azure_job_id": job_id,
                "error": True,
                "error_code": code,
                "outcome": outcome,
                "message": message,
            }
        )
        if last_status:
            result["last_job_status"] = last_status
        action_result.add_data(result)
        summary = {
            "status": "error",
            "outcome": outcome,
            "azure_job_id": job_id,
            "last_job_status": last_status,
        }
        for key in ("runbook_version", "observed_release_status"):
            if result.get(key):
                summary[key] = result[key]
        action_result.update_summary(summary)
        return action_result.set_status(phantom.APP_ERROR, message)

    def _execute_disposition(self, action_result, action, identity):
        """Keep the lock from before webhook submission through result validation."""
        configured_tenant = self.get_config().get("azure_tenant_id")
        tenant = configured_tenant.strip().lower() if isinstance(configured_tenant, str) else ""
        # Use the tenant UUID, not the asset ID, app registration or domain alias.
        if not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", tenant):
            return self._disposition_error_result(
                action_result,
                action,
                identity,
                "not_executed",
                "invalid_tenant_id",
                "Configure azure_tenant_id as the Microsoft Entra tenant UUID.",
            )
        with ExitStack() as stack:
            try:
                stack.enter_context(self._disposition_lock(tenant, identity))
            except BlockingIOError:
                return self._disposition_error_result(
                    action_result,
                    action,
                    identity,
                    "not_executed",
                    "operation_in_progress",
                    "A Release or Deny operation is already in progress for this quarantine identity. No job was submitted.",
                )
            except OSError:
                return self._disposition_error_result(
                    action_result,
                    action,
                    identity,
                    "not_executed",
                    "disposition_lock_unavailable",
                    "Could not acquire a private disposition lock. No job was submitted.",
                )
            return self._run_disposition_job(action_result, action, identity)

    def _run_disposition_job(self, action_result, action, identity):
        job_id = ""
        self.save_progress(f"Starting Azure Automation action={action}, identity={identity}")
        try:
            job_id = self._utils.fire_webhook(action, identity=identity)
            self.save_progress(f"Azure job {job_id}: waiting for {action} result.")
            result = self._utils.wait_for_action_result(
                job_id,
                action=action,
                identity=identity,
            )
        except AutomationError as exc:
            data = dict(exc.result) if isinstance(exc, RunbookActionError) else {}
            code = data.get("error_code", data.get("code"))
            if not isinstance(code, str) or not code.strip():
                code = "outcome_unknown"
            # Only use validated, explicit runbook evidence to assert that
            # the Exchange command did not execute or reported a failure.
            outcome = {
                "precondition_unconfirmed": "not_executed",
                "disposition_failed": "failed",
                "release_pending": "pending",
            }.get(code, "unknown")
            message = self._map_error(exc, action)
            if outcome == "unknown":
                message += " Do not retry before checking Azure job history and the current Exchange status."
            return self._disposition_error_result(
                action_result,
                action,
                identity,
                outcome,
                code,
                message,
                data=data,
                job_id=job_id or getattr(exc, "job_id", "") or "",
                last_status=getattr(exc, "last_status", ""),
            )

        data = dict(result, azure_job_id=job_id, outcome="confirmed")
        data["message"] = data.get("message") or f"Quarantine {action} confirmed by Exchange."
        action_result.add_data(data)
        summary = {
            "status": data["status"],
            "outcome": "confirmed",
            "azure_job_id": job_id,
            "observed_release_status": data["observed_release_status"],
            "runbook_version": data.get("runbook_version", ""),
        }
        action_result.update_summary(summary)
        return action_result.set_status(phantom.APP_SUCCESS, data["message"])

    def _handle_disposition(self, param, action):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param.get("identity", "")
        if not isinstance(value, str):
            message = r"The 'identity' parameter must be a string in GUID1\GUID2 format."
        else:
            value = value.strip()
            message = validate_identity_format(value[:128]) if value else "The 'identity' parameter is required."
        if message:
            return self._disposition_error_result(
                action_result,
                action,
                "",
                "not_executed",
                "invalid_identity",
                message,
            )
        return self._execute_disposition(action_result, action, value)

    def _handle_release_quarantine_message(self, param):
        return self._handle_disposition(param, "release")

    def _handle_deny_quarantine_release(self, param):
        return self._handle_disposition(param, "deny")

    # -----------------------------------------------------------------------
    # Dispatcher
    # -----------------------------------------------------------------------

    def handle_action(self, param):
        action = self.get_action_identifier()
        handlers = {
            "test_connectivity": self._handle_test_connectivity,
            "on_poll": self._handle_on_poll,
            "on_es_poll": self._handle_on_es_poll,
            "inspect_release_environment": (self._handle_inspect_release_environment),
            "release_quarantine_message": self._handle_release_quarantine_message,
            "deny_quarantine_release": self._handle_deny_quarantine_release,
        }
        handler = handlers.get(action)
        if handler:
            return handler(param)
        self.save_progress(f"Unknown action: {action}")
        return phantom.APP_ERROR


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _run_cli(argv=None):
    """Run the App-Wizard debug entrypoint with deterministic exit codes."""
    import sys

    args = list(sys.argv if argv is None else argv)
    if len(args) != 2:
        print(
            json.dumps({"error": "Usage: connector.py <input.json>"}),
            file=sys.stderr,
        )
        return 2

    try:
        with open(args[1], encoding="utf-8") as input_file:
            in_json = json.load(input_file)
        if not isinstance(in_json, dict):
            raise ValueError("top-level input must be a JSON object")
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "error": "Invalid CLI input",
                    "exception_type": type(exc).__name__,
                }
            ),
            file=sys.stderr,
        )
        return 2

    connector = MSQuarantineForSplunkSOARConnector()
    connector.print_progress_message = True
    try:
        ret_val = connector._handle_action(json.dumps(in_json), None)
        action_results = json.loads(connector.get_action_results())
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": "Connector CLI execution failed",
                    "exception_type": type(exc).__name__,
                }
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(action_results, indent=4))
    return 0 if phantom.APP_SUCCESS == ret_val else 1


if __name__ == "__main__":
    import sys

    sys.exit(_run_cli())
