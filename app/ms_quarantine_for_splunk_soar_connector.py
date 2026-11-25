# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
#
# MS Quarantine for Splunk SOAR – Splunk SOAR Connector (Azure Automation)
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

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
import fcntl
import hashlib
import json
import os
import re
import tempfile

import phantom.app as phantom

from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from ms_quarantine_for_splunk_soar_ingestion import NativeIngestionMixin

from ms_quarantine_for_splunk_soar_utils import (
    MSQuarantineForSplunkSOARUtils,
    AutomationError,
    normalize_exchange_connection_settings,
    validate_webhook_url,
    TokenError,
    WebhookError,
    JobTimeoutError,
    JobFailedError,
    RunbookActionError,
    OversizedExportError,
    MAX_DECODED_EML_BYTES,
    MAX_INLINE_DECODED_EML_BYTES,
    DIAGNOSTIC_RBAC_NOT_EVALUATED_ERROR_CODE,
    DIAGNOSTIC_RBAC_PARTIAL_ERROR_CODE,
    redact_sensitive_text,
    parse_strict_integer,
)

try:
    import phantom.rules as phrules
except ImportError:
    phrules = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXPORT_VAULT  = "vault"
EXPORT_INLINE = "inline"
VALID_EXPORT_MODES = {EXPORT_VAULT, EXPORT_INLINE}
ARTIFACT_LAYOUT_COMBINED = "combined"
ARTIFACT_LAYOUT_SEPARATE = "separate"
VALID_ARTIFACT_LAYOUTS = {
    ARTIFACT_LAYOUT_COMBINED,
    ARTIFACT_LAYOUT_SEPARATE,
}
ARTIFACT_FIELD_ORDER = (
    "from",
    "to",
    "cc",
    "reply_to",
    "sender_address",
    "recipient_address",
    "subject",
    "email_date",
    "received_date",
    "message_id",
    "quarantine_identity",
    "vault_id",
)
DEFAULT_ARTIFACT_FIELDS = (
    "from",
    "to",
    "subject",
    "email_date",
    "message_id",
)
ARTIFACT_FIELD_SET = set(ARTIFACT_FIELD_ORDER)
DEFAULT_ARTIFACT_FIELD_SET = frozenset(DEFAULT_ARTIFACT_FIELDS)
ARTIFACT_FIELD_CONFIG_KEYS = {
    field: f"artifact_field_{field}"
    for field in ARTIFACT_FIELD_ORDER
}
LEGACY_ARTIFACT_ACTION_KEYS = frozenset({
    "create_email_artifacts",
    "artifact_layout",
    "artifact_fields",
})
ARTIFACT_EMAIL_FIELDS = {
    "from",
    "to",
    "cc",
    "reply_to",
    "sender_address",
    "recipient_address",
}
ARTIFACT_CEF_KEYS = {
    "from": "fromEmail",
    "to": "toEmail",
    "cc": "ccEmail",
    "reply_to": "replyToEmail",
    "sender_address": "senderAddress",
    "recipient_address": "recipientAddress",
    "subject": "emailSubject",
    "message_id": "emailMessageId",
    "quarantine_identity": "quarantineIdentity",
    "vault_id": "vaultId",
}
MAX_ARTIFACT_HEADER_LENGTH = 8192
MAX_ARTIFACT_VALUE_LENGTH = 4096
MAX_ARTIFACT_ADDRESSES_PER_FIELD = 100
MAX_ARTIFACT_WARNING_LENGTH = 4096
ON_POLL_CANDIDATE_PAGE_SIZE = 50
ON_POLL_MAX_CONTAINERS = 50
DEFAULT_WORKER_TERMINAL_RETENTION_DAYS = 30
MIN_WORKER_TERMINAL_RETENTION_DAYS = 1
MAX_WORKER_TERMINAL_RETENTION_DAYS = 365

# Quarantine message identity format: GUID\GUID (per Microsoft docs)
# https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-quarantinemessage#-identity
IDENTITY_REGEX = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    r'\\'
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


def _parse_config_integer(value, field: str) -> int:
    """Preserve lossless SOAR numeric config, never truncate a fraction."""
    if not isinstance(value, bool):
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, (int, str)):
            try:
                return int(value)
            except ValueError:
                pass
    raise ValueError(
        f"{field} must be an integer; Boolean, fractional and non-finite "
        "values are not supported."
    )


def _parse_poll_integer(value) -> int:
    """Accept SOAR numeric whole-number floats only for poll limit fields."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return parse_strict_integer(value)


def validate_identity_format(identity: str) -> str:
    """
    Validate the quarantine identity format (GUID\\GUID) before firing the
    webhook. Returns an error message string, or empty string if valid.

    Early validation gives instant feedback instead of burning a full
    webhook + poll roundtrip (30-60s) on a typo.
    """
    if not isinstance(identity, str):
        return "The 'identity' parameter must be a string in GUID1\\GUID2 format."
    if not IDENTITY_REGEX.fullmatch(identity):
        return (
            f"Invalid identity format: '{identity}'. Expected GUID1\\GUID2, e.g. "
            "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7. "
            "Use container:data.quarantine_identity from the SOAR event or the ES finding’s linked SOAR container."
        )
    return ""


def normalize_recipient_address(value) -> str:
    """
    Normalise Exchange's scalar or multi-valued RecipientAddress property to
    the string promised by the SOAR app manifest.

    Microsoft 365's ``send email`` action accepts comma-separated recipients.
    Never use ``str(list_value)`` here: that produces a Python representation
    such as ``['user@example.com']``, which Microsoft Graph rejects as an
    invalid address.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            "RecipientAddress must be a string, an array of strings, or null."
        )

    recipients = []
    for item in value:
        if item is None:
            continue
        if not isinstance(item, str):
            raise ValueError(
                "RecipientAddress array items must be strings or null."
            )
        item = item.strip()
        if item:
            recipients.append(item)
    return ", ".join(recipients)


def parse_boolean_parameter(
    value,
    name: str,
    source: str = "Parameter",
) -> bool:
    """Parse a SOAR boolean value without Python truthiness surprises."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in {"true", "1", "yes", "on"}:
            return True
        if normalised in {"false", "0", "no", "off", ""}:
            return False
    raise ValueError(
        f"{source} '{name}' must be a boolean (true or false)."
    )


def parse_artifact_fields(value) -> tuple:
    """Return selected artifact fields in stable canonical order."""
    if value is None:
        requested = list(DEFAULT_ARTIFACT_FIELDS)
    elif not isinstance(value, str):
        raise ValueError(
            "Parameter 'artifact_fields' must be a comma-separated string."
        )
    else:
        tokens = [
            item.strip().lower()
            for item in value.split(",")
            if item.strip()
        ]
        if not tokens:
            raise ValueError(
                "Parameter 'artifact_fields' must select at least one field."
            )
        if "all" in tokens:
            if len(tokens) != 1:
                raise ValueError(
                    "Parameter 'artifact_fields' must use 'all' by itself."
                )
            requested = list(ARTIFACT_FIELD_ORDER)
        else:
            unknown = sorted(set(tokens) - ARTIFACT_FIELD_SET)
            if unknown:
                raise ValueError(
                    "Unknown artifact field(s): "
                    f"{', '.join(unknown)}. Allowed fields: "
                    f"{', '.join(ARTIFACT_FIELD_ORDER)}, or all."
                )
            requested = tokens

    selected = set(requested)
    return tuple(
        field for field in ARTIFACT_FIELD_ORDER if field in selected
    )


def parse_artifact_asset_config(config: dict, *, allow_empty_fields=False) -> dict:
    """Validate and normalize the asset-wide email-artifact policy."""
    enabled = parse_boolean_parameter(
        config.get("create_email_artifacts", False),
        "create_email_artifacts",
        source="Asset configuration field",
    )

    layout_value = config.get("artifact_layout")
    if layout_value is None or (
        isinstance(layout_value, str) and not layout_value.strip()
    ):
        layout_value = ARTIFACT_LAYOUT_COMBINED
    if not isinstance(layout_value, str):
        raise ValueError(
            "Asset configuration field 'artifact_layout' must be "
            "'combined' or 'separate'."
        )
    layout = layout_value.strip().lower()
    if layout not in VALID_ARTIFACT_LAYOUTS:
        raise ValueError(
            "Asset configuration field 'artifact_layout' must be "
            "'combined' or 'separate'."
        )

    selected_fields = []
    for field in ARTIFACT_FIELD_ORDER:
        config_key = ARTIFACT_FIELD_CONFIG_KEYS[field]
        default = field in DEFAULT_ARTIFACT_FIELD_SET
        configured_value = config.get(config_key, default)
        if configured_value is None or configured_value == "":
            configured_value = default
        if parse_boolean_parameter(
            configured_value,
            config_key,
            source="Asset configuration field",
        ):
            selected_fields.append(field)

    if enabled and not selected_fields and not allow_empty_fields:
        raise ValueError(
            "Email artifact creation is enabled, but no artifact field is "
            "selected. Enable at least one 'artifact_field_*' checkbox."
        )

    return {
        "enabled": enabled,
        "layout": layout,
        "fields": tuple(selected_fields),
    }


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class MSQuarantineForSplunkSOARConnector(NativeIngestionMixin, BaseConnector):
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
        self._utils                   = None
        self._export_mode             = None
        self._asset_artifact_options  = None
        self._on_poll_max_containers = 10
        self._worker_terminal_retention_days = (
            DEFAULT_WORKER_TERMINAL_RETENTION_DAYS
        )

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
                return self.set_status(
                    phantom.APP_ERROR,
                    f"Asset configuration error: '{field}' is required but empty."
                )

        # Hidden legacy controls retain valid saved values, but stale invalid
        # values must not block an asset whose UI can no longer repair them.
        legacy_mode = config.get("export_mode", EXPORT_VAULT)
        legacy_mode = (
            legacy_mode.strip().lower() if isinstance(legacy_mode, str) else ""
        )
        self._export_mode = (
            legacy_mode if legacy_mode in VALID_EXPORT_MODES else EXPORT_VAULT
        )
        artifact_config = dict(config)
        try:
            parse_boolean_parameter(
                artifact_config.get("create_email_artifacts", False),
                "create_email_artifacts", source="Asset configuration field",
            )
        except ValueError:
            artifact_config["create_email_artifacts"] = False

        try:
            # The removed legacy enable switch must not prevent users from
            # deselecting all optional mail fields in the current import UI.
            self._asset_artifact_options = parse_artifact_asset_config(
                artifact_config, allow_empty_fields=True,
            )
        except ValueError as exc:
            return self.set_status(
                phantom.APP_ERROR,
                f"Asset configuration error: {exc}",
            )

        try:
            poll_interval = _parse_config_integer(
                config.get("poll_interval_seconds", 5), "poll_interval_seconds",
            )
            poll_timeout = _parse_config_integer(
                config.get("poll_timeout_seconds", 600), "poll_timeout_seconds",
            )
            raw_on_poll_max = config.get("on_poll_max_containers")
            on_poll_max_containers = (
                10
                if raw_on_poll_max in (None, "")
                else _parse_poll_integer(raw_on_poll_max)
            )
            raw_worker_retention = config.get(
                "worker_terminal_retention_days"
            )
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
                f"worker_terminal_retention_days must be integers. {exc}"
            )
        if poll_interval < 1 or poll_interval > 60:
            return self.set_status(
                phantom.APP_ERROR,
                "poll_interval_seconds must be between 1 and 60."
            )
        if poll_timeout < 600 or poll_timeout > 3600:
            return self.set_status(
                phantom.APP_ERROR,
                "poll_timeout_seconds must be between 600 and 3600. Values "
                "below 600 seconds are unsafe for Azure Automation cold "
                "starts and irreversible release/deny actions."
            )
        if poll_timeout <= poll_interval:
            return self.set_status(
                phantom.APP_ERROR,
                "poll_timeout_seconds must be greater than poll_interval_seconds."
            )
        if (
            on_poll_max_containers < 1
            or on_poll_max_containers > ON_POLL_MAX_CONTAINERS
        ):
            return self.set_status(
                phantom.APP_ERROR,
                "on_poll_max_containers must be between 1 and "
                f"{ON_POLL_MAX_CONTAINERS}.",
            )
        self._on_poll_max_containers = on_poll_max_containers
        if not (
            MIN_WORKER_TERMINAL_RETENTION_DAYS
            <= worker_terminal_retention_days
            <= MAX_WORKER_TERMINAL_RETENTION_DAYS
        ):
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
            webhook_url        = webhook_url,
            tenant_id          = config["azure_tenant_id"].strip(),
            client_id          = config["azure_client_id"].strip(),
            client_secret      = config["azure_client_secret"].strip(),
            subscription_id    = config["azure_subscription_id"].strip(),
            resource_group     = config["azure_resource_group"].strip(),
            automation_account = config["azure_automation_account"].strip(),
            poll_interval      = poll_interval,
            poll_timeout       = poll_timeout,
            # Public export is retired; native import always stores EML in
            # Vault, independently of hidden legacy asset values.
            retain_chunked_base64 = False,
            exchange_organization = exchange_settings.get("organization"),
            progress_callback = self.save_progress,
        )

        return phantom.APP_SUCCESS

    def finalize(self):
        return phantom.APP_SUCCESS

    # -----------------------------------------------------------------------
    # Vault helpers
    # -----------------------------------------------------------------------

    def _safe_filename(self, identity: str) -> str:
        """Build a filesystem-safe .eml filename from a quarantine identity."""
        first_part = identity.split("\\", 1)[0] if "\\" in identity else identity
        safe = "".join(c for c in first_part if c.isalnum() or c == "-")[:36]
        return f"quarantine_{safe}.eml"

    def _calculate_hashes(self, data_bytes: bytes) -> dict:
        return {
            "md5": hashlib.md5(
                data_bytes,
                usedforsecurity=False,
            ).hexdigest(),
            "sha1": hashlib.sha1(
                data_bytes,
                usedforsecurity=False,
            ).hexdigest(),
            "sha256": hashlib.sha256(data_bytes).hexdigest(),
        }

    def _store_in_vault(self, eml_bytes: bytes, identity: str, *, container_id=None, file_name=None) -> tuple:
        """
        Write EML bytes to the SOAR Vault.

        Returns:
            (True, vault_metadata_dict) on success
            (False, error_message_str)  on failure
        """
        if phrules is None:
            return False, (
                "phantom.rules is not available. "
                "Switch export_mode to 'inline' for testing outside SOAR."
            )

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
                container     = self.get_container_id() if container_id is None else container_id,
                file_location = tmp_path,
                file_name     = file_name,
                metadata      = {
                    "source":   "MS Quarantine for Splunk SOAR",
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

    @staticmethod
    def _bounded_artifact_text(value, limit=MAX_ARTIFACT_VALUE_LENGTH) -> str:
        """Bound untrusted RFC header text before storing it in SOAR."""
        text = str(value or "").replace("\x00", "").strip()
        if len(text) <= limit:
            return text
        return text[:limit]

    def _header_values(self, message, name: str) -> list:
        values = []
        for value in message.get_all(name, []):
            text = self._bounded_artifact_text(
                value,
                MAX_ARTIFACT_HEADER_LENGTH,
            )
            if text:
                values.append(text)
        return values

    def _raw_header_values(self, message, name: str) -> list:
        """Return original RFC header values without header-registry rewriting."""
        expected = name.casefold()
        values = []
        for header_name, value in message.raw_items():
            if header_name.casefold() != expected:
                continue
            text = self._bounded_artifact_text(
                value,
                MAX_ARTIFACT_HEADER_LENGTH,
            )
            if text:
                values.append(text)
        return values

    def _extract_header_addresses(
        self,
        message,
        header_names,
        warnings,
        field_name,
    ) -> list:
        raw_values = []
        for header_name in header_names:
            raw_values.extend(self._header_values(message, header_name))

        addresses = []
        seen = set()
        for _display_name, address in getaddresses(raw_values):
            address = self._bounded_artifact_text(address, 1024)
            if not address:
                continue
            canonical = address.casefold()
            if canonical in seen:
                continue
            seen.add(canonical)
            addresses.append(address)
            if len(addresses) >= MAX_ARTIFACT_ADDRESSES_PER_FIELD:
                warnings.append(
                    f"{field_name}: limited to "
                    f"{MAX_ARTIFACT_ADDRESSES_PER_FIELD} addresses"
                )
                break
        return addresses

    def _parse_artifact_date(
        self,
        raw_value: str,
        field_name: str,
        warnings,
        raw_header=None,
    ) -> dict:
        value = {
            "raw": self._bounded_artifact_text(
                raw_value,
                MAX_ARTIFACT_HEADER_LENGTH,
            )
        }
        if raw_header:
            value["header_raw"] = self._bounded_artifact_text(
                raw_header,
                MAX_ARTIFACT_HEADER_LENGTH,
            )
        try:
            parsed = parsedate_to_datetime(value["raw"])
        except (TypeError, ValueError, OverflowError) as exc:
            warnings.append(f"{field_name}: date could not be parsed ({exc})")
            return value

        if parsed is None:
            warnings.append(f"{field_name}: date could not be parsed")
            return value
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            warnings.append(
                f"{field_name}: no timezone in header; ISO value omitted"
            )
            return value

        value["iso"] = parsed.isoformat()
        return value

    def _extract_email_artifact_metadata(self, eml_bytes: bytes) -> dict:
        """Parse bounded RFC headers from an exported EML message."""
        try:
            message = BytesParser(policy=policy.default).parsebytes(
                eml_bytes,
                headersonly=True,
            )
        except Exception as exc:
            raise ValueError(f"EML header parsing failed: {exc}") from exc

        warnings = []
        if message.defects:
            warnings.append(
                "email parser reported defects: "
                + ", ".join(
                    type(defect).__name__ for defect in message.defects[:10]
                )
            )

        values = {
            "from": self._extract_header_addresses(
                message, ("From",), warnings, "from"
            ),
            "to": self._extract_header_addresses(
                message, ("To",), warnings, "to"
            ),
            "cc": self._extract_header_addresses(
                message, ("Cc",), warnings, "cc"
            ),
            "reply_to": self._extract_header_addresses(
                message, ("Reply-To",), warnings, "reply_to"
            ),
            "sender_address": self._extract_header_addresses(
                message, ("Sender",), warnings, "sender_address"
            ),
            "recipient_address": self._extract_header_addresses(
                message,
                (
                    "X-MS-Exchange-Organization-OriginalEnvelopeRecipients",
                    "X-Original-To",
                    "Delivered-To",
                    "Envelope-To",
                ),
                warnings,
                "recipient_address",
            ),
            "subject": [],
            "message_id": [],
            "email_date": [],
            "received_date": [],
        }

        subject_values = self._header_values(message, "Subject")
        if subject_values:
            values["subject"] = [subject_values[0]]

        message_id_values = self._header_values(message, "Message-ID")
        if message_id_values:
            values["message_id"] = [message_id_values[0]]

        email_date_values = self._raw_header_values(message, "Date")
        if email_date_values:
            values["email_date"] = [
                self._parse_artifact_date(
                    email_date_values[0],
                    "email_date",
                    warnings,
                )
            ]

        received_headers = self._raw_header_values(message, "Received")
        if received_headers:
            topmost_received = received_headers[0]
            received_date_raw = (
                topmost_received.rsplit(";", 1)[1].strip()
                if ";" in topmost_received
                else topmost_received
            )
            values["received_date"] = [
                self._parse_artifact_date(
                    received_date_raw,
                    "received_date",
                    warnings,
                    raw_header=topmost_received,
                )
            ]

        return {"values": values, "warnings": warnings}

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
                raise ValueError(
                    "Parameter 'artifact_layout' must be 'combined' or "
                    "'separate'."
                )
            layout = layout_value.strip().lower()
            if layout not in VALID_ARTIFACT_LAYOUTS:
                raise ValueError(
                    "Parameter 'artifact_layout' must be 'combined' or "
                    "'separate'."
                )

            fields = parse_artifact_fields(param.get("artifact_fields"))

        if phrules is None or not callable(
            getattr(phrules, "add_artifact", None)
        ):
            raise ValueError(
                "SOAR artifact API is unavailable; email artifacts cannot "
                "be created in this runtime."
            )
        return {
            "enabled": True,
            "layout": layout,
            "fields": fields,
        }

    @staticmethod
    def _artifact_field_mapping(cef_data: dict) -> dict:
        mapping = {}
        for key in cef_data:
            if key in {
                "fromEmail",
                "toEmail",
                "ccEmail",
                "replyToEmail",
                "senderAddress",
                "recipientAddress",
            }:
                mapping[key] = ["email"]
            elif key == "vaultId":
                mapping[key] = ["vault id"]
        return mapping

    def _artifact_cef_for_value(self, field: str, value) -> dict:
        if field == "email_date":
            cef = {"emailDateRaw": value["raw"]}
            if value.get("iso"):
                cef["emailDate"] = value["iso"]
            return cef
        if field == "received_date":
            cef = {"receivedDateRaw": value["raw"]}
            if value.get("iso"):
                cef["receivedDate"] = value["iso"]
            return cef
        return {ARTIFACT_CEF_KEYS[field]: value}

    def _artifact_identifier(self, *parts) -> str:
        material = "\x1f".join(str(part) for part in parts)
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        # Persisted record IDs are data contracts, not the app display identity.
        return f"msqm-email-{digest}"

    def _build_email_artifact_specs(
        self,
        identity: str,
        hashes: dict,
        metadata: dict,
        options: dict,
        vault_id=None,
        required_cef=None,
    ) -> tuple:
        values = dict(metadata["values"])
        values["quarantine_identity"] = [identity]
        values["vault_id"] = [vault_id] if vault_id else []

        selected_fields = options["fields"]
        missing_fields = [
            field for field in selected_fields if not values.get(field)
        ]
        correlation = {
            "source": "MS Quarantine for Splunk SOAR",
            "quarantine_identity": identity,
            "eml_sha256": hashes["sha256"],
            "container_id": self.get_container_id(),
        }
        if vault_id:
            correlation["vault_id"] = vault_id

        specs = []
        if options["layout"] == ARTIFACT_LAYOUT_COMBINED:
            cef_data = {}
            raw_selected = {}
            for field in selected_fields:
                field_values = values.get(field) or []
                if not field_values:
                    continue
                raw_selected[field] = field_values
                if field in {"email_date", "received_date"}:
                    cef_data.update(
                        self._artifact_cef_for_value(
                            field,
                            field_values[0],
                        )
                    )
                    continue
                combined_value = (
                    field_values[0]
                    if len(field_values) == 1
                    else list(field_values)
                )
                cef_data.update(
                    self._artifact_cef_for_value(field, combined_value)
                )

            # Native combined ingestion supplies its workflow fields last so
            # optional RFC headers cannot replace Microsoft quarantine values.
            cef_data.update(required_cef or {})
            if cef_data:
                subject = (values.get("subject") or [""])[0]
                preview = self._bounded_artifact_text(subject, 120)
                name = preview or "No subject"
                specs.append({
                    "name": name,
                    "identifier": self._artifact_identifier(
                        identity,
                        options["layout"],
                        ",".join(selected_fields),
                        hashes["sha256"],
                    ),
                    "cef_data": cef_data,
                    "raw_data": {
                        **correlation,
                        "artifact_layout": options["layout"],
                        "selected_fields": list(selected_fields),
                        "email_metadata": raw_selected,
                    },
                })
        else:
            for field in selected_fields:
                for index, value in enumerate(values.get(field) or []):
                    cef_data = self._artifact_cef_for_value(field, value)
                    raw_value = value
                    if isinstance(value, dict):
                        preview_source = value.get("iso") or value.get("raw")
                    else:
                        preview_source = value
                    preview = self._bounded_artifact_text(
                        preview_source,
                        120,
                    )
                    specs.append({
                        "name": (
                            f"Quarantined email {field}"
                            + (f": {preview}" if preview else "")
                        ),
                        "identifier": self._artifact_identifier(
                            identity,
                            options["layout"],
                            field,
                            index,
                            json.dumps(
                                value,
                                ensure_ascii=False,
                                sort_keys=True,
                            ),
                        ),
                        "cef_data": cef_data,
                        "raw_data": {
                            **correlation,
                            "artifact_layout": options["layout"],
                            "artifact_field": field,
                            "artifact_value": raw_value,
                        },
                    })

        return specs, missing_fields


    # -----------------------------------------------------------------------
    # Error mapping
    # -----------------------------------------------------------------------

    def _map_error(self, exc: Exception, action_label: str) -> str:
        """Preserve the real cause and known job, using native action messages."""
        safe_error = (
            self._utils.redact_sensitive_text(exc)
            if self._utils is not None
            else redact_sensitive_text(str(exc))
        )
        if isinstance(exc, RunbookActionError):
            message = self._runbook_error_message(exc)
        elif isinstance(exc, TokenError):
            message = (
                f"Failed to acquire Azure AD token for '{action_label}': {safe_error}. "
                "Check azure_tenant_id, azure_client_id, azure_client_secret."
            )
        elif isinstance(exc, WebhookError):
            message = (
                f"Webhook failed for '{action_label}': {safe_error}. "
                "Check webhook_url and Azure Automation; no second webhook was sent."
            )
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

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()


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
    def _parse_state_timestamp(value):
        """Parse one connector-owned UTC timestamp, returning None on empty."""
        text = str(value or "").strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise AutomationError(
                f"Worker ledger contains an invalid timestamp: '{value}'."
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise AutomationError(
                "Worker ledger timestamps must include a UTC offset."
            )
        return parsed.astimezone(timezone.utc)


    @staticmethod
    def _worker_identity_key(identity: str, asset_id) -> str:
        material = f"{asset_id}|{identity}".encode("utf-8")
        return "work-" + hashlib.sha256(material).hexdigest()[:40]

    @staticmethod
    def _worker_source_identifier(identity: str, asset_id) -> str:
        digest = hashlib.sha256(
            f"{asset_id}|{identity}".encode("utf-8")
        ).hexdigest()
        # Keep existing deduplication identifiers stable across product renames.
        return f"msqm-quarantine-asset-{asset_id}-{digest}"


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
        return "; ".join(
            f"{name}={value}"
            for name, value in fields
            if value not in ("", None, 0)
        )

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
        quarantine_role = cls._diagnostic_tri_state(
            record.get("quarantine_role_present")
        )
        service_principal = cls._diagnostic_tri_state(
            record.get("service_principal_registered")
        )
        assignment = cls._diagnostic_tri_state(
            record.get("role_assignment_matches_identity")
        )
        role_group_inspected = int(
            record.get("quarantine_role_group_inspected_count", 0) or 0
        )
        role_group_total = int(
            record.get("quarantine_role_group_total_count", 0) or 0
        )
        role_group_truncated = bool(
            record.get("quarantine_role_group_inspection_truncated", False)
        )
        return "; ".join((
            f"rbac={record.get('rbac_diagnostics_status', '')}",
            f"rbac_reason={record.get('rbac_diagnostics_reason', '')}",
            f"missing_cmdlets={missing_cmdlets or 'none'}",
            f"quarantine_role={quarantine_role}",
            f"service_principal_registered={service_principal}",
            f"quarantine_membership={assignment}",
            f"role_groups={role_group_inspected}/{role_group_total}",
            f"role_groups_truncated={str(role_group_truncated).lower()}",
            "query_errors=" + str(int(
                record.get("permission_query_error_count", 0) or 0
            )),
            "query_errors_retained=" + str(int(
                record.get(
                    "permission_query_error_retained_count",
                    record.get("permission_query_error_count", 0),
                ) or 0
            )),
            "query_errors_dropped=" + str(int(
                record.get("permission_query_error_dropped_count", 0) or 0
            )),
        ))

    @classmethod
    def _rbac_summary(cls, record: dict) -> dict:
        """Return truthful summary values; omit unknown legacy booleans."""
        summary = {
            "rbac_diagnostics_status": record.get(
                "rbac_diagnostics_status", ""
            ),
            "rbac_diagnostics_reason": record.get(
                "rbac_diagnostics_reason", ""
            ),
            "missing_cmdlet_count": int(
                record.get("missing_cmdlet_count", 0) or 0
            ),
            "missing_cmdlets": list(record.get("missing_cmdlets", []) or []),
            "quarantine_role_group_total_count": int(
                record.get("quarantine_role_group_total_count", 0) or 0
            ),
            "quarantine_role_group_inspected_count": int(
                record.get("quarantine_role_group_inspected_count", 0) or 0
            ),
            "quarantine_role_group_inspection_truncated": bool(
                record.get(
                    "quarantine_role_group_inspection_truncated",
                    False,
                )
            ),
            "permission_query_error_count": int(
                record.get("permission_query_error_count", 0) or 0
            ),
            "permission_query_error_retained_count": int(
                record.get(
                    "permission_query_error_retained_count",
                    record.get("permission_query_error_count", 0),
                ) or 0
            ),
            "permission_query_error_dropped_count": int(
                record.get("permission_query_error_dropped_count", 0) or 0
            ),
            "permission_query_errors_truncated": bool(
                record.get("permission_query_errors_truncated", False)
            ),
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
            return action_result.set_status(
                phantom.APP_ERROR,
                self._map_error(exc, "test connectivity")
            )
        self.save_progress("Token acquired.")

        self.save_progress("Step 2/3: Starting protected list and waiting for completion...")
        try:
            output = self._utils.run_action("list")
            self.save_progress("Step 3/3: Validating the list result...")
            self._normalise_list_result(output)
        except (WebhookError, TokenError, JobTimeoutError,
                JobFailedError, AutomationError) as exc:
            return action_result.set_status(
                phantom.APP_ERROR, self._map_error(exc, "test connectivity")
            )

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Connectivity test passed. Webhook, Azure AD token, job polling, "
            "and Exchange Online connection all working."
        )

    # -----------------------------------------------------------------------
    # Shared Requested-list normalization
    # -----------------------------------------------------------------------

    def _normalise_list_result(self, result: dict) -> list:
        """Validate the runbook list contract for actions and ingestion."""
        if not isinstance(result, dict):
            raise AutomationError(
                "Runbook protocol error: list output must be an object."
            )
        messages_value = result.get("messages")
        legacy_single_message = isinstance(messages_value, dict)
        if messages_value is None:
            messages = []
        elif legacy_single_message:
            self.save_progress(
                "Runbook returned one list result as an object; normalising "
                "it to a one-element list. Upgrade the runbook."
            )
            messages = [messages_value]
        elif isinstance(messages_value, list):
            messages = messages_value
        else:
            raise AutomationError(
                "Runbook protocol error: 'messages' must be an array, "
                "an object for one legacy result, or null."
            )

        if any(not isinstance(message, dict) for message in messages):
            raise AutomationError(
                "Runbook protocol error: every 'messages' item must be an "
                "object."
            )

        reported_count = result.get("count")
        if reported_count is not None:
            try:
                parsed_count = parse_strict_integer(reported_count)
            except (TypeError, ValueError) as exc:
                raise AutomationError(
                    "Runbook protocol error: 'count' must be an integer."
                ) from exc
            if not legacy_single_message and parsed_count != len(messages):
                raise AutomationError(
                    "Runbook protocol error: 'count' does not match the "
                    "'messages' array length."
                )

        normalised_messages = []
        try:
            for message in messages:
                identity = message.get("Identity")
                format_error = validate_identity_format(identity)
                if format_error:
                    raise AutomationError(
                        "Runbook protocol error: list Identity is invalid. "
                        f"{format_error}"
                    )
                normalised_messages.append({
                    "Identity": identity,
                    "SenderAddress": message.get("SenderAddress", ""),
                    "RecipientAddress": normalize_recipient_address(
                        message.get("RecipientAddress")
                    ),
                    "Subject": message.get("Subject", ""),
                    "Type": message.get("Type", ""),
                    "ReceivedTime": message.get("ReceivedTime", ""),
                    "Expires": message.get("Expires", ""),
                    "PolicyName": message.get("PolicyName", ""),
                    "ReleaseStatus": message.get("ReleaseStatus", ""),
                })
        except ValueError as exc:
            raise AutomationError(
                f"Runbook protocol error: {exc}"
            ) from exc
        return normalised_messages


    # -----------------------------------------------------------------------
    # Action: on poll
    # -----------------------------------------------------------------------

    def _on_poll_container_limit(self, param: dict) -> int:
        """Resolve scheduled versus Poll Now container limits."""
        if not self.is_poll_now():
            return self._on_poll_max_containers

        raw_value = param.get("container_count")
        if raw_value in (None, ""):
            return self._on_poll_max_containers
        try:
            requested = _parse_poll_integer(raw_value)
        except (TypeError, ValueError) as exc:
            raise AutomationError(
                "container_count must be an integer."
            ) from exc
        if requested <= 0:
            return self._on_poll_max_containers
        return min(requested, ON_POLL_MAX_CONTAINERS)

    def _build_poll_container(self, claim: dict) -> dict:
        """Build one deterministic container with its initial artifact."""
        message = claim["message"]
        identity = claim["identity"]
        work_item_id = claim["work_item_id"]
        source_id = claim["source_data_identifier"]
        subject = self._bounded_artifact_text(
            message.get("Subject", ""),
            240,
        )
        sender = self._bounded_artifact_text(
            message.get("SenderAddress", ""),
        )
        recipient = self._bounded_artifact_text(
            message.get("RecipientAddress", ""),
        )
        raw_data = {
            "source": "MS Quarantine for Splunk SOAR",
            "work_item_id": work_item_id,
            "quarantine_identity": identity,
            "sender_address": sender,
            "recipient_address": recipient,
            "subject": subject,
            "quarantine_type": self._bounded_artifact_text(
                message.get("Type", "")
            ),
            "received_time": self._bounded_artifact_text(
                message.get("ReceivedTime", "")
            ),
            "expires": self._bounded_artifact_text(
                message.get("Expires", "")
            ),
            "policy_name": self._bounded_artifact_text(
                message.get("PolicyName", "")
            ),
            "release_status": self._bounded_artifact_text(
                message.get("ReleaseStatus", "")
            ),
        }
        cef = {
            "quarantineIdentity": identity,
            "senderAddress": sender,
            "recipientAddress": recipient,
            "emailSubject": subject,
            "quarantineType": raw_data["quarantine_type"],
            "receivedTime": raw_data["received_time"],
            "expires": raw_data["expires"],
            "policyName": raw_data["policy_name"],
            "releaseStatus": raw_data["release_status"],
            "workItemId": work_item_id,
        }
        name = subject or "[No subject]"
        return {
            "name": name,
            "description": (
                f"{self._utils.selection_release_status} quarantine message "
                "ingested by "
                "MS Quarantine for Splunk SOAR."
            ),
            "source_data_identifier": source_id,
            "severity": "medium",
            "data": {
                "source": "MS Quarantine for Splunk SOAR",
                "work_item_id": work_item_id,
                "quarantine_identity": identity,
            },
            "artifacts": [{
                "name": "Quarantine release request",
                "label": "email",
                "type": "email",
                "severity": "medium",
                "source_data_identifier": source_id + "-message",
                "cef": cef,
                "data": raw_data,
            }],
        }

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

        self.save_progress(
            "Firing read-only webhook: action=diagnose, "
            f"identity={identity}, include_rbac={include_rbac}"
        )
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
            details["error_code"] = str(
                exc.result.get("error_code", "")
            )
            details["runbook_version"] = str(
                exc.result.get("runbook_version", "")
            )
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
            summary["cmdlet_proxy_diagnostics_status"] = details.get(
                "cmdlet_proxy_diagnostics_status", "not_available"
            )
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
        summary["cmdlet_proxy_diagnostics_status"] = result.get(
            "cmdlet_proxy_diagnostics_status", "not_available"
        )
        summary.update(self._rbac_summary(result))
        action_result.update_summary(summary)
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Read-only release environment inspected; no release or deny "
            f"cmdlet was executed. {self._diagnostic_message(result)}; "
            f"{self._rbac_diagnostic_message(result)}.",
        )

    def _execute_disposition(self, action_result, action, identity):
        """Run one requested disposition; native SOAR owns its result/history."""
        job_id = ""
        self.save_progress(f"Starting Azure Automation action={action}, identity={identity}")
        try:
            job_id = self._utils.fire_webhook(action, identity=identity)
            self.save_progress(f"Azure job {job_id}: waiting for {action} result.")
            result = self._utils.wait_for_action_result(
                job_id, action=action, identity=identity,
            )
        except AutomationError as exc:
            result = dict(exc.result) if isinstance(exc, RunbookActionError) else {}
            result.update({
                "action": action,
                "identity": identity,
                "azure_job_id": job_id or getattr(exc, "job_id", "") or "",
                "error": True,
            })
            last_status = getattr(exc, "last_status", "")
            if last_status:
                result["last_job_status"] = last_status
            message = self._map_error(exc, action)
            if result["azure_job_id"] and result["azure_job_id"] not in message:
                message += f" Azure job ID: {result['azure_job_id']}."
            if "Azure Automation" not in message:
                message += " Inspect the job in Azure Automation for the reported cause."
            result["message"] = message
            action_result.add_data(result)
            action_result.update_summary({
                "status": "error",
                "azure_job_id": result["azure_job_id"],
                "last_job_status": last_status,
            })
            return action_result.set_status(phantom.APP_ERROR, message)

        data = dict(result)
        data["azure_job_id"] = job_id
        action_result.add_data(data)
        action_result.update_summary({
            "status": data["status"],
            "azure_job_id": job_id,
            "runbook_version": data.get("runbook_version", ""),
            "observed_release_status": data.get("observed_release_status", ""),
        })
        return action_result.set_status(
            phantom.APP_SUCCESS,
            data.get("message") or f"Quarantine {action} confirmed by Exchange.",
        )

    # -----------------------------------------------------------------------
    # Action: release quarantine message
    # -----------------------------------------------------------------------

    def _handle_release_quarantine_message(self, param):
        """
        Release one quarantined message to all original recipients.
        Runbook executes: Release-QuarantineMessage -Identity <id>
        -ReleaseToAll
        IRREVERSIBLE.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        identity = param.get("identity", "")
        if not isinstance(identity, str):
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter must be a string in GUID1\\GUID2 format.",
            )
        identity = identity.strip()
        if not identity:
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter is required."
            )

        format_error = validate_identity_format(identity)
        if format_error:
            return action_result.set_status(phantom.APP_ERROR, format_error)

        return self._execute_disposition(
            action_result,
            "release",
            identity,
        )

    # -----------------------------------------------------------------------
    # Action: deny quarantine release
    # -----------------------------------------------------------------------

    def _handle_deny_quarantine_release(self, param):
        """
        Deny a user's release request.
        Runbook executes: Release-QuarantineMessage -Identity <id>
        -ReleaseToAll -ActionType Deny
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        identity = param.get("identity", "")
        if not isinstance(identity, str):
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter must be a string in GUID1\\GUID2 format.",
            )
        identity = identity.strip()
        if not identity:
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter is required."
            )

        format_error = validate_identity_format(identity)
        if format_error:
            return action_result.set_status(phantom.APP_ERROR, format_error)

        return self._execute_disposition(
            action_result,
            "deny",
            identity,
        )

    # -----------------------------------------------------------------------
    # Dispatcher
    # -----------------------------------------------------------------------

    def handle_action(self, param):
        action = self.get_action_identifier()
        handlers = {
            "test_connectivity":          self._handle_test_connectivity,
            "on_poll":                    self._handle_on_poll,
            "on_es_poll":                 self._handle_on_es_poll,
            "inspect_release_environment": (
                self._handle_inspect_release_environment
            ),
            "release_quarantine_message": self._handle_release_quarantine_message,
            "deny_quarantine_release":    self._handle_deny_quarantine_release,
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
            json.dumps({
                "error": "Invalid CLI input",
                "exception_type": type(exc).__name__,
            }),
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
            json.dumps({
                "error": "Connector CLI execution failed",
                "exception_type": type(exc).__name__,
            }),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(action_results, indent=4))
    return 0 if phantom.APP_SUCCESS == ret_val else 1


if __name__ == "__main__":
    import sys

    sys.exit(_run_cli())
