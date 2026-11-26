# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

"""Platform-neutral SOAR mail metadata and quarantine record projection."""

import hashlib
import json
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from ms_quarantine_for_splunk_soar_utils import AutomationError, parse_strict_integer


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
ARTIFACT_FIELD_CONFIG_KEYS = {field: f"artifact_field_{field}" for field in ARTIFACT_FIELD_ORDER}
LEGACY_ARTIFACT_ACTION_KEYS = frozenset(
    {
        "create_email_artifacts",
        "artifact_layout",
        "artifact_fields",
    }
)
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
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"\\"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
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
    raise ValueError(f"{field} must be an integer; Boolean, fractional and non-finite values are not supported.")


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
        raise ValueError("RecipientAddress must be a string, an array of strings, or null.")

    recipients = []
    for item in value:
        if item is None:
            continue
        if not isinstance(item, str):
            raise ValueError("RecipientAddress array items must be strings or null.")
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
    raise ValueError(f"{source} '{name}' must be a boolean (true or false).")


def parse_artifact_fields(value) -> tuple:
    """Return selected artifact fields in stable canonical order."""
    if value is None:
        requested = list(DEFAULT_ARTIFACT_FIELDS)
    elif not isinstance(value, str):
        raise ValueError("Parameter 'artifact_fields' must be a comma-separated string.")
    else:
        tokens = [item.strip().lower() for item in value.split(",") if item.strip()]
        if not tokens:
            raise ValueError("Parameter 'artifact_fields' must select at least one field.")
        if "all" in tokens:
            if len(tokens) != 1:
                raise ValueError("Parameter 'artifact_fields' must use 'all' by itself.")
            requested = list(ARTIFACT_FIELD_ORDER)
        else:
            unknown = sorted(set(tokens) - ARTIFACT_FIELD_SET)
            if unknown:
                raise ValueError(f"Unknown artifact field(s): {', '.join(unknown)}. Allowed fields: {', '.join(ARTIFACT_FIELD_ORDER)}, or all.")
            requested = tokens

    selected = set(requested)
    return tuple(field for field in ARTIFACT_FIELD_ORDER if field in selected)


def parse_artifact_asset_config(config: dict, *, allow_empty_fields=False) -> dict:
    """Validate and normalize the asset-wide email-artifact policy."""
    enabled = parse_boolean_parameter(
        config.get("create_email_artifacts", False),
        "create_email_artifacts",
        source="Asset configuration field",
    )

    layout_value = config.get("artifact_layout")
    if layout_value is None or (isinstance(layout_value, str) and not layout_value.strip()):
        layout_value = ARTIFACT_LAYOUT_COMBINED
    if not isinstance(layout_value, str):
        raise ValueError("Asset configuration field 'artifact_layout' must be 'combined' or 'separate'.")
    layout = layout_value.strip().lower()
    if layout not in VALID_ARTIFACT_LAYOUTS:
        raise ValueError("Asset configuration field 'artifact_layout' must be 'combined' or 'separate'.")

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
            "Email artifact creation is enabled, but no artifact field is selected. Enable at least one 'artifact_field_*' checkbox."
        )

    return {
        "enabled": enabled,
        "layout": layout,
        "fields": tuple(selected_fields),
    }


class QuarantineMail:
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
            # Legacy SOAR artifact IOC, not an integrity or authentication check.
            # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
            "sha1": hashlib.sha1(
                data_bytes,
                usedforsecurity=False,
            ).hexdigest(),
            "sha256": hashlib.sha256(data_bytes).hexdigest(),
        }

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
                warnings.append(f"{field_name}: limited to {MAX_ARTIFACT_ADDRESSES_PER_FIELD} addresses")
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
            warnings.append(f"{field_name}: no timezone in header; ISO value omitted")
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
            warnings.append("email parser reported defects: " + ", ".join(type(defect).__name__ for defect in message.defects[:10]))

        values = {
            "from": self._extract_header_addresses(message, ("From",), warnings, "from"),
            "to": self._extract_header_addresses(message, ("To",), warnings, "to"),
            "cc": self._extract_header_addresses(message, ("Cc",), warnings, "cc"),
            "reply_to": self._extract_header_addresses(message, ("Reply-To",), warnings, "reply_to"),
            "sender_address": self._extract_header_addresses(message, ("Sender",), warnings, "sender_address"),
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
            received_date_raw = topmost_received.rsplit(";", 1)[1].strip() if ";" in topmost_received else topmost_received
            values["received_date"] = [
                self._parse_artifact_date(
                    received_date_raw,
                    "received_date",
                    warnings,
                    raw_header=topmost_received,
                )
            ]

        return {"values": values, "warnings": warnings}

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
        missing_fields = [field for field in selected_fields if not values.get(field)]
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
                combined_value = field_values[0] if len(field_values) == 1 else list(field_values)
                cef_data.update(self._artifact_cef_for_value(field, combined_value))

            # Native combined ingestion supplies its workflow fields last so
            # optional RFC headers cannot replace Microsoft quarantine values.
            cef_data.update(required_cef or {})
            if cef_data:
                subject = (values.get("subject") or [""])[0]
                preview = self._bounded_artifact_text(subject, 120)
                name = preview or "No subject"
                specs.append(
                    {
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
                    }
                )
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
                    specs.append(
                        {
                            "name": (f"Quarantined email {field}" + (f": {preview}" if preview else "")),
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
                        }
                    )

        return specs, missing_fields

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

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
            raise AutomationError(f"Worker ledger contains an invalid timestamp: '{value}'.") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise AutomationError("Worker ledger timestamps must include a UTC offset.")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _worker_identity_key(identity: str, asset_id) -> str:
        material = f"{asset_id}|{identity}".encode()
        return "work-" + hashlib.sha256(material).hexdigest()[:40]

    @staticmethod
    def _worker_source_identifier(identity: str, asset_id) -> str:
        digest = hashlib.sha256(f"{asset_id}|{identity}".encode()).hexdigest()
        # Keep existing deduplication identifiers stable across product renames.
        return f"msqm-quarantine-asset-{asset_id}-{digest}"

    def _normalise_list_result(self, result: dict) -> list:
        """Validate the runbook list contract for actions and ingestion."""
        if not isinstance(result, dict):
            raise AutomationError("Runbook protocol error: list output must be an object.")
        messages_value = result.get("messages")
        legacy_single_message = isinstance(messages_value, dict)
        if messages_value is None:
            messages = []
        elif legacy_single_message:
            self.save_progress("Runbook returned one list result as an object; normalising it to a one-element list. Upgrade the runbook.")
            messages = [messages_value]
        elif isinstance(messages_value, list):
            messages = messages_value
        else:
            raise AutomationError("Runbook protocol error: 'messages' must be an array, an object for one legacy result, or null.")

        if any(not isinstance(message, dict) for message in messages):
            raise AutomationError("Runbook protocol error: every 'messages' item must be an object.")

        reported_count = result.get("count")
        if reported_count is not None:
            try:
                parsed_count = parse_strict_integer(reported_count)
            except (TypeError, ValueError) as exc:
                raise AutomationError("Runbook protocol error: 'count' must be an integer.") from exc
            if not legacy_single_message and parsed_count != len(messages):
                raise AutomationError("Runbook protocol error: 'count' does not match the 'messages' array length.")

        normalised_messages = []
        try:
            for message in messages:
                identity = message.get("Identity")
                format_error = validate_identity_format(identity)
                if format_error:
                    raise AutomationError(f"Runbook protocol error: list Identity is invalid. {format_error}")
                normalised_messages.append(
                    {
                        "Identity": identity,
                        "SenderAddress": message.get("SenderAddress", ""),
                        "RecipientAddress": normalize_recipient_address(message.get("RecipientAddress")),
                        "Subject": message.get("Subject", ""),
                        "Type": message.get("Type", ""),
                        "ReceivedTime": message.get("ReceivedTime", ""),
                        "Expires": message.get("Expires", ""),
                        "PolicyName": message.get("PolicyName", ""),
                        "ReleaseStatus": message.get("ReleaseStatus", ""),
                    }
                )
        except ValueError as exc:
            raise AutomationError(f"Runbook protocol error: {exc}") from exc
        return normalised_messages

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
            raise AutomationError("container_count must be an integer.") from exc
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
            "quarantine_type": self._bounded_artifact_text(message.get("Type", "")),
            "received_time": self._bounded_artifact_text(message.get("ReceivedTime", "")),
            "expires": self._bounded_artifact_text(message.get("Expires", "")),
            "policy_name": self._bounded_artifact_text(message.get("PolicyName", "")),
            "release_status": self._bounded_artifact_text(message.get("ReleaseStatus", "")),
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
            "description": (f"{self._utils.selection_release_status} quarantine message ingested by MS Defender Quarantine Manager."),
            "source_data_identifier": source_id,
            "severity": "medium",
            "data": {
                "source": "MS Quarantine for Splunk SOAR",
                "work_item_id": work_item_id,
                "quarantine_identity": identity,
            },
            "artifacts": [
                {
                    "name": "Quarantine release request",
                    "label": "email",
                    "type": "email",
                    "severity": "medium",
                    "source_data_identifier": source_id + "-message",
                    "cef": cef,
                    "data": raw_data,
                }
            ],
        }
