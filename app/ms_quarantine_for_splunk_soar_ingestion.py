# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""App-owned native intake; never performs an Exchange disposition.

The existing Runbook 3.4.3 list/export/reconcile wire contract is unchanged.
Definitively rejected publication may retry; uncertain automation delivery
stays visible and is never blindly repeated.
"""
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email import policy
from email.feedparser import BytesFeedParser
import fcntl
import hashlib
import json
import os
import time

import phantom.app as phantom
from phantom.action_result import ActionResult
from ms_quarantine_for_splunk_soar_utils import AutomationError, OversizedExportError, MAX_DECODED_EML_BYTES

INGEST_STATE_KEY = "quarantine_native_ingest_v1"
MAX_INGEST_RECORDS = 1000
MAX_MIME_PARTS = 200
MAX_ATTACHMENTS = 100
MAX_MIME_DEPTH = 30


class _MimeStructureLimit(AutomationError):
    """Stop before constructing a forbidden MIME node."""


class _BoundedMimeParser(BytesFeedParser):
    # CPython 3.9-3.13 builds every recursive MIME node through this hook.
    # Its stack depth before construction equals the new node's depth (root 0).
    def __init__(self):
        super().__init__(policy=policy.default)
        self._created_parts = 0

    def _new_message(self):
        if self._created_parts >= MAX_MIME_PARTS or len(self._msgstack) > MAX_MIME_DEPTH:
            raise _MimeStructureLimit("EML exceeds MIME structure limits.")
        super()._new_message()
        self._created_parts += 1


def _parse_mime_mail(eml):
    parser = _BoundedMimeParser()
    for offset in range(0, len(eml), 8192):
        parser.feed(eml[offset:offset + 8192])
    return parser.close()


def mail_files(eml):
    """Validate every MIME node and return stable positional attachments."""
    return parse_mail_files(eml)[1]


def parse_mail_files(eml):
    """Return one validated tree and its attachments for both intake targets."""
    if not isinstance(eml, bytes) or not eml or len(eml) > MAX_DECODED_EML_BYTES:
        raise AutomationError("Missing or oversized EML; import not published.")
    try:
        mail = _parse_mime_mail(eml)
    except _MimeStructureLimit:
        raise
    except Exception:
        raise AutomationError("EML parser failed; import not published.") from None
    if not mail.keys():
        raise AutomationError("EML contains no mail headers.")
    return mail, _mail_files_from_parsed(mail)


def _mail_files_from_parsed(mail):
    """Validate and extract without reparsing a previously budgeted tree."""
    stack = [(mail, 0, True)]
    files = []
    extra_containers = []
    parts = total_bytes = 0

    def append_file(name, data):
        nonlocal total_bytes
        name = os.path.basename(str(name).replace("\\", "/"))
        name = "".join(c for c in name if c.isprintable() and c not in "/\\")[:180]
        name = name or "attachment.bin"
        total_bytes += len(data)
        if len(files) >= MAX_ATTACHMENTS or total_bytes > MAX_DECODED_EML_BYTES * 2:
            raise AutomationError("EML exceeds attachment count/decoded-size limits.")
        files.append((f"{len(files) + 1:03d}_{name}", data))

    while stack:
        part, depth, extract = stack.pop()
        parts += 1
        if parts > MAX_MIME_PARTS or depth > MAX_MIME_DEPTH:
            raise AutomationError("EML exceeds MIME structure limits.")
        if part.defects:
            raise AutomationError("Malformed MIME part; import not published.")
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if not isinstance(payload, list) or not payload:
                raise AutomationError("Attached email is incomplete.")
            # Validate attached mail descendants without extracting them twice.
            stack.extend((child, depth + 1, False) for child in reversed(payload))
            if not extract:
                continue
            data = b"".join(p.as_bytes(policy=policy.default) for p in payload)
            name = part.get_filename() or "attached-message.eml"
        elif part.is_multipart():
            children = part.get_payload()
            if not isinstance(children, list):
                raise AutomationError("Malformed multipart email.")
            stack.extend((child, depth + 1, extract) for child in reversed(children))
            if extract and (
                part.get_content_type() == "message/global"
                or (part.get_content_maintype() == "multipart" and (
                    part.get_filename() or part.get_content_disposition() == "attachment"
                ))
            ):
                extra_containers.append(part)
            continue
        else:
            data = part.get_payload(decode=True)
            # Transfer decoding can add defects, even on an ordinary body.
            if part.defects:
                raise AutomationError("Malformed MIME part; import not published.")
            if not extract:
                continue
            name = part.get_filename()
            is_file = (name or part.get_content_disposition() == "attachment"
                       or part.get_content_maintype() not in {"text", "multipart"}
                       or part.get("Content-ID"))
            if not is_file:
                continue
            if data is None:
                raise AutomationError("Attachment could not be decoded.")
            name = name or "attachment.bin"
        if part.defects:
            raise AutomationError("Malformed MIME attachment; import not published.")
        append_file(name, data)
    # Existing Vault/SDI references bind positional indices. New container
    # views follow all legacy files; previously extracted children stay intact.
    for part in extra_containers:
        if part.get_content_type() == "message/global":
            payload = part.get_payload()
            if not isinstance(payload, list) or not payload:
                raise AutomationError("Attached email is incomplete.")
            data = b"".join(child.as_bytes(policy=policy.default) for child in payload)
            name = part.get_filename() or "attached-message.eml"
        else:
            data = part.as_bytes(policy=policy.default)
            name = part.get_filename() or "attached-multipart.eml"
        append_file(name, data)
    if mail.defects:
        raise AutomationError("Malformed EML; import not published.")
    return files


class ImportBlocked(AutomationError):
    """Deterministic input defect; requires explicit recovery rather than re-export."""


class NativeIngestionMixin:
    def _handle_action(self, in_json, *args, **kwargs):
        self._ingest_runtime = json.loads(in_json)
        self._ingest_es_client_instance = None
        return super()._handle_action(in_json, *args, **kwargs)

    def _ingest_es_client(self):
        from ms_quarantine_for_splunk_soar_es_ingestion import NativeESClient
        client = getattr(self, "_ingest_es_client_instance", None)
        if client is None:
            base_url = self.get_config().get("es_soar_base_url") or self._get_phantom_base_url()
            client = NativeESClient(getattr(self, "_ingest_runtime", {}), base_url)
            self._ingest_es_client_instance = client
        return client

    def _ingest_settings(self):
        runtime = getattr(self, "_ingest_runtime", {})
        settings = self.get_config().get("ingest", {})
        if runtime.get("asset_id"):
            asset = self._ingest_es_client().request("GET", f"/rest/asset/{self.get_asset_id()}")
            settings = asset.get("configuration", {}).get("ingest", {})
        if not isinstance(settings, dict):
            raise AutomationError("Native ES ingest settings are malformed.")
        if "use_es_ingest" in settings and type(settings["use_es_ingest"]) is not bool:
            raise AutomationError("Native ES target switch must be boolean.")
        if settings.get("use_es_ingest") is True:
            for name in ("es_security_domain",):
                if not isinstance(settings.get(name), str) or not settings[name].strip():
                    raise AutomationError("Missing native ES ingest setting: " + name)
            for name in ("es_run_threat_analysis", "es_launch_automation"):
                if name in settings and type(settings[name]) is not bool:
                    raise AutomationError("Native ES setting must be boolean: " + name)
        self._ingest_target = "es" if settings.get("use_es_ingest") is True else "soar"
        self._ingest_es_settings = dict(settings)
        self._ingest_es_settings["_finding_source"] = "MS Quarantine for Splunk SOAR - " + str(runtime.get("asset_name") or self.get_asset_id())
        return settings

    @contextmanager
    def _ingest_poll_lock(self):
        """Serialize the entire poll independently of short operation-state locks."""
        path = self.get_state_file_path() + ".ingest.lock"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a+") as lock:
            os.chmod(path, 0o600)
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AutomationError("Another intake poll is still running.") from None
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _ingest_scope(self):
        config = self.get_config()
        return {
            "asset_id": str(self.get_asset_id()),
            "tenant": config["azure_tenant_id"].strip().lower(),
            "organization": str(config.get("exchange_organization") or "").strip().lower(),
            "target": getattr(self, "_ingest_target", "soar"),
        }

    def _ingest_load(self, state):
        if not isinstance(state, dict):
            raise AutomationError("App state is unavailable; intake refused.")
        data = state.get(INGEST_STATE_KEY)
        if data is None:
            if state.get("quarantine_es_deliveries"):
                raise AutomationError("Existing ES delivery state requires a controlled migration before native intake.")
            legacy = state.get("quarantine_worker_ledger", {})
            if not isinstance(legacy, dict):
                raise AutomationError("Legacy intake ledger is malformed.")
            records = {}
            migration_ranks = {}
            now = datetime.now(timezone.utc)
            for old in legacy.values():
                if not isinstance(old, dict):
                    raise AutomationError("Legacy intake record is malformed.")
                lease = self._parse_state_timestamp(old.get("lease_expires_at"))
                if (old.get("state") == "creating_container" and not old.get("container_id")
                        and lease is not None and lease <= now):
                    continue
                if old.get("state") not in {"completed", "failed", "oversized"}:
                    raise AutomationError(
                        "Legacy intake has unresolved workers. Disable intake and "
                        "complete legacy worker callbacks on the previous app "
                        "version before upgrading. This version cannot update "
                        "legacy workers."
                    )
                identity = str(old.get("identity") or "").strip().lower()
                if not identity:
                    raise AutomationError("Legacy intake identity is missing.")
                key = self._worker_identity_key(identity, self.get_asset_id())
                stamp = self._parse_state_timestamp(old.get("updated_at"))
                row = {
                    "key": key, "identity": identity, "phase": "terminal",
                    "container_id": old.get("container_id"),
                    "created_at": old.get("created_at"), "updated_at": old.get("updated_at"),
                    "migration_origin": "legacy_" + old["state"], "last_error": "",
                }
                # Keep the newest terminal record as a unit: mixing an older
                # timestamp with newer evidence can expire deduplication early.
                # A stable whole-row tie-break also handles equal/missing times.
                rank = (stamp is not None,
                        stamp or datetime.min.replace(tzinfo=timezone.utc),
                        json.dumps(row, sort_keys=True))
                if key not in records or rank > migration_ranks[key]:
                    records[key] = row
                    migration_ranks[key] = rank
            data = {"scope": self._ingest_scope(), "records": records}
        # Selection is no longer configurable. Drop only that obsolete scope
        # key; retain records and the tenant/organization/target boundaries.
        if isinstance(data, dict) and isinstance(data.get("scope"), dict):
            data["scope"] = dict(data["scope"])
            data["scope"].pop("selection_mode", None)
        if (not isinstance(data, dict) or not isinstance(data.get("records"), dict)
                or data.get("scope") != self._ingest_scope()):
            raise AutomationError(
                "Native intake state/scope mismatch. Restore the original asset pairing."
            )
        phases = {"reserved", "preparing", "ready", "publishing", "published", "terminal", "blocked"}
        for key, row in data["records"].items():
            if (not isinstance(row, dict) or row.get("phase") not in phases
                    or not isinstance(row.get("identity"), str)
                    or row.get("key") != key):
                raise AutomationError("Native intake record is malformed.")
        return data

    def _ingest_records(self):
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            return {key: dict(row) for key, row in data["records"].items()}

    def _ingest_update(self, key, **updates):
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            if key not in data["records"]:
                raise AutomationError("Native intake reservation disappeared.")
            row = data["records"][key]
            row.update(updates, updated_at=self._utc_now())
            state[INGEST_STATE_KEY] = data
            saved = self.save_state(state)
            if saved is False or phantom.is_fail(saved):
                raise AutomationError("Native intake state could not be saved.")
            return dict(row)

    def _ingest_reserve(self, messages, capacity, per_poll):
        """Reserve only free slots while holding the asset state lock."""
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            records = data["records"]
            cutoff = datetime.now(timezone.utc) - timedelta(
                days=self._worker_terminal_retention_days
            )
            for key, row in list(records.items()):
                stamp = self._parse_state_timestamp(row.get("updated_at"))
                if row["phase"] == "terminal" and stamp is not None and stamp < cutoff:
                    del records[key]
            if len(records) >= MAX_INGEST_RECORDS:
                self._ingest_ledger_full = True
            active = sum(r["phase"] != "terminal" for r in records.values())
            remaining = min(max(0, capacity - active), per_poll)
            for message in messages:
                if remaining <= 0:
                    break
                identity = message["Identity"].strip().lower()
                key = self._worker_identity_key(identity, self.get_asset_id())
                if key in records:
                    continue
                if len(records) >= MAX_INGEST_RECORDS:
                    self._ingest_ledger_full = True
                    break
                records[key] = {
                    "key": key, "identity": identity, "message": dict(message),
                    "phase": "reserved", "container_id": None, "files": {},
                    "created_at": self._utc_now(), "updated_at": self._utc_now(),
                    "last_error": "",
                }
                remaining -= 1
            state[INGEST_STATE_KEY] = data
            saved = self.save_state(state)
            if saved is False or phantom.is_fail(saved):
                raise AutomationError("Could not persist native intake reservations.")

    def _ingest_error(self, exc):
        if isinstance(exc, AutomationError):
            return self._utils.redact_sensitive_text(str(exc), max_chars=400)
        return type(exc).__name__

    def _ingest_budget_check(self):
        if time.monotonic() >= getattr(self, "_ingest_deadline", float("inf")):
            raise AutomationError("Poll time budget exhausted; remaining work retained for next poll.")

    def _ingest_scheduled(self, records, stage):
        """Resume after the last attempted identity, including after failures."""
        with self._operation_state_lock():
            data = self._ingest_load(self.load_state())
            scheduler = data.get("scheduler", {})
            if not isinstance(scheduler, dict):
                raise AutomationError("Native intake scheduler state is malformed.")
            cursor = scheduler.get(stage)
            if cursor is not None and not isinstance(cursor, str):
                raise AutomationError("Native intake scheduler cursor is malformed.")
        keys = list(records)
        if cursor in keys:
            offset = keys.index(cursor) + 1
            keys = keys[offset:] + keys[:offset]
        return [(key, records[key]) for key in keys]

    def _ingest_schedule_attempt(self, stage, key):
        # Persist before remote effects so restart/failure cannot reset to a prefix.
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            scheduler = data.setdefault("scheduler", {})
            scheduler[stage] = key
            state[INGEST_STATE_KEY] = data
            saved = self.save_state(state)
            if saved is False or phantom.is_fail(saved):
                raise AutomationError("Could not persist native intake scheduling progress.")

    def _ingest_poll_priority(self):
        """Alternate pending-work classes durably before either starts remote work."""
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            scheduler = data.setdefault("scheduler", {})
            if not isinstance(scheduler, dict):
                raise AutomationError("Native intake scheduler state is malformed.")
            priority = scheduler.get("next_priority", "prepare")
            if priority not in ("prepare", "reconcile"):
                raise AutomationError("Native intake scheduler priority is malformed.")
            scheduler["next_priority"] = "reconcile" if priority == "prepare" else "prepare"
            state[INGEST_STATE_KEY] = data
            saved = self.save_state(state)
            if saved is False or phantom.is_fail(saved):
                raise AutomationError("Could not persist native intake scheduling priority.")
            return priority

    def _ingest_reconcile(self, records, *, advance_cursor=True, exclude=()):
        errors = []
        terminal = 0
        # Rotate the complete ledger first: an excluded cursor still anchors order.
        for key, row in self._ingest_scheduled(records, "reconcile"):
            if key in exclude or row["phase"] == "terminal":
                continue
            self.save_progress("Checking tracked quarantine message status.")
            try:
                self._ingest_budget_check()
                if time.monotonic() >= getattr(self, "_ingest_reconcile_deadline", float("inf")):
                    break  # Reserve time for pending imports without discarding observations.
                if advance_cursor:
                    self._ingest_schedule_attempt("reconcile", key)
                result = self._utils.run_action(
                    "reconcile", identity=row["identity"], operation_action="release"
                )
                # Utils validates the complete exact-one-record read-only trace.
                if result.get("operation_action") != "release":
                    raise AutomationError("Reconcile comparison action mismatched the request.")
                observed = result.get("observed_release_status", "").lower()
                if observed in {"released", "denied"}:
                    self._ingest_update(
                        key, phase="terminal", observed_release_status=observed,
                        delivery_phase_at_terminal=row["phase"],
                        last_error="", message={}, files={},
                    )
                    terminal += 1
                else:
                    self._ingest_update(key, observed_release_status=observed)
            except Exception as exc:
                reason = self._ingest_error(exc)
                self._ingest_update(key, last_error=reason)
                errors.append(row["identity"] + ": status observation unavailable (" + reason + ")")
                break  # Do not multiply remote calls after a read/transport failure.
        return terminal, errors

    def _ingest_save_artifact(self, row, suffix, cef, name, *, publish=False):
        artifact = {
            "container_id": row["container_id"],
            "source_data_identifier": self._worker_source_identifier(
                row["identity"], self.get_asset_id()
            ) + "-" + suffix,
            "name": name, "label": "email", "type": "email",
            "severity": "medium", "cef": cef,
            "run_automation": publish,
        }
        status, _message, artifact_id = self.save_artifact(artifact)
        if phantom.is_fail(status):
            if publish:
                from ms_quarantine_for_splunk_soar_es_ingestion import ESSubmissionRejected
                raise ESSubmissionRejected(400)
            raise AutomationError("SOAR rejected the ingestion artifact.")
        if not artifact_id:
            raise AutomationError("SOAR did not confirm the ingestion artifact.")
        return artifact_id

    def _ingest_single_email_artifact(self):
        return (getattr(self, "_ingest_target", "soar") == "soar"
                and self._asset_artifact_options["layout"] == "combined")

    def _ingest_prepare(self, key, row):
        """All preparation writes suppress automation and are safe to retry."""
        self.save_progress("Importing quarantined EML and attachments.")
        single_artifact = self._ingest_single_email_artifact()
        self._ingest_budget_check()
        result = self._utils.run_action("export", identity=row["identity"])
        eml = result.get("_eml_bytes")
        if isinstance(eml, bytearray):
            # Chunked Vault transport returns a verified bytearray; MIME
            # validation and file persistence consume immutable bytes.
            eml = bytes(eml)
        if eml is None:
            encoded = self._utils.extract_eml(result)
            eml = base64.b64decode("".join((encoded or "").split()), validate=True)
        try:
            mail, attachments = parse_mail_files(eml)  # Validate before container side effects.
        except AutomationError as exc:
            raise ImportBlocked(str(exc)) from None
        digest = hashlib.sha256(eml).hexdigest()
        if row.get("eml_sha256") and row["eml_sha256"] != digest:
            raise AutomationError("Exported EML changed during import recovery.")
        row = self._ingest_update(key, phase="preparing", eml_sha256=digest)
        if row["container_id"] is None:
            claim = {"message": row["message"], "identity": row["identity"],
                     "work_item_id": key,
                     "source_data_identifier": self._worker_source_identifier(
                         row["identity"], self.get_asset_id())}
            container = self._build_poll_container(claim)
            if single_artifact:
                container["artifacts"] = []
            container["run_automation"] = False
            for artifact in container.get("artifacts", []):
                artifact["run_automation"] = False
            self._ingest_budget_check()
            status, _message, container_id = self.save_container(container)
            if (phantom.is_fail(status) or type(container_id) is not int
                    or container_id <= 0):
                raise AutomationError("SOAR did not confirm the ingestion container.")
            row = self._ingest_update(key, container_id=container_id)
        original = self._safe_filename(row["identity"])
        files = [(original, eml)] + attachments
        vaults = dict(row["files"])
        for index, (name, content) in enumerate(files):
            self._ingest_budget_check()
            file_key = str(index)
            file_hash = hashlib.sha256(content).hexdigest()
            if file_key not in vaults:
                ok, stored = self._store_in_vault(
                    content, row["identity"], container_id=row["container_id"],
                    file_name=name,
                )
                if not ok:
                    raise AutomationError("SOAR Vault upload was not confirmed.")
                vaults[file_key] = {
                    "vault_id": stored["vault_id"], "file_name": name,
                    "sha256": file_hash, "size": len(content),
                }
                row = self._ingest_update(key, files=dict(vaults))
            entry = vaults[file_key]
            if entry["sha256"] != file_hash:
                raise AutomationError("Stored attachment does not match recovery export.")
            if not single_artifact:
                hashes = self._calculate_hashes(content)
                self._ingest_budget_check()
                self._ingest_save_artifact(
                    row, "file-" + file_key,
                    {"quarantineIdentity": row["identity"], "workItemId": key,
                     "vaultId": entry["vault_id"], "fileName": name,
                     "fileHash": hashes["sha256"], "fileHashMd5": hashes["md5"],
                     "fileHashSha1": hashes["sha1"], "fileHashSha256": hashes["sha256"],
                     "isOriginalEmail": index == 0},
                    "Original quarantined email" if index == 0 else "Email attachment",
                )
        metadata = self._extract_email_artifact_metadata(eml)
        options = dict(self._asset_artifact_options)
        options["enabled"] = True
        required_cef = None
        if single_artifact:
            options["fields"] = tuple(
                field for field in options["fields"]
                if field not in {"vault_id", "sender_address", "recipient_address"}
            )
            required_cef = {
                "vaultId": vaults["0"]["vault_id"],
                "senderAddress": self._bounded_artifact_text(row["message"].get("SenderAddress", "")),
                "recipientAddress": self._bounded_artifact_text(row["message"].get("RecipientAddress", "")),
            }
        specs, missing = self._build_email_artifact_specs(
            row["identity"], self._calculate_hashes(eml), metadata, options,
            vault_id=vaults["0"]["vault_id"], required_cef=required_cef,
        )
        if not single_artifact:
            for index, spec in enumerate(specs):
                self._ingest_budget_check()
                self._ingest_save_artifact(
                    row, "metadata-" + str(index), spec["cef_data"], spec["name"]
                )
        # Persist the final artifact with the existing ready record. Rejected
        # publication can then retry without another export or Vault upload.
        prepared = ({"email_artifact": {"name": specs[0]["name"], "cef": specs[0]["cef_data"]}}
                    if single_artifact else {})
        row = self._ingest_update(
            key, phase="ready", vault_id=vaults["0"]["vault_id"],
            attachment_count=len(attachments), missing_artifact_fields=missing,
            last_error="", **prepared,
        )
        if getattr(self, "_ingest_target", "soar") == "es":
            from ms_quarantine_for_splunk_soar_es_ingestion import _build_finding_from_parsed
            client = self._ingest_es_client()
            file_index = iter(range(len(files)))
            def uploaded(name, content):
                entry = vaults[str(next(file_index))]
                if entry["sha256"] != hashlib.sha256(content).hexdigest():
                    raise AutomationError("ES attachment does not match prepared Vault content.")
                return entry["vault_id"]
            finding = _build_finding_from_parsed(
                row["message"], eml, row["identity"], key,
                self._worker_source_identifier(row["identity"], self.get_asset_id()),
                self._ingest_es_settings, uploaded, client.base_url, mail, attachments,
            )
            self._ingest_budget_check()
            row["_es_payload"] = client.prepare_bulk_payload(
                {"findings": [finding], "container_ids": [row["container_id"]]}
            )
        return row

    def _ingest_publish(self, key, row):
        # Persist intent before the first request that may start automation.
        # If a receipt/state save is lost, never launch analysis a second time.
        payload = row.get("_es_payload")
        is_es = getattr(self, "_ingest_target", "soar") == "es"
        if is_es and not payload:
            raise AutomationError("Native ES finding was not prepared.")
        self._ingest_budget_check()
        row = self._ingest_update(key, phase="publishing")
        if is_es:
            response = self._ingest_es_client().request(
                "POST", "/rest/enterprise_security/findings/bulk_create", json=payload
            )
            if (response.get("status") in {"success", "error", "failed", "partial_success"}
                    and isinstance(response.get("errors"), list)
                    and type(response.get("created")) is int and response["created"] == 0
                    and type(response.get("failed")) is int and response["failed"] == 1
                    and response.get("findings") == []
                    and response.get("container_ids") in ([], [row["container_id"]])):
                from ms_quarantine_for_splunk_soar_es_ingestion import ESSubmissionRejected
                raise ESSubmissionRejected(400)
            if (response.get("status") != "success" or type(response.get("created")) is not int
                    or response["created"] != 1 or type(response.get("failed")) is not int
                    or response["failed"] != 0 or response.get("errors")
                    or response.get("container_ids") != [row["container_id"]]
                    or not isinstance(response.get("findings"), list)
                    or len(response["findings"]) != 1
                    or not isinstance(response["findings"][0], str)
                    or not response["findings"][0]):
                raise AutomationError("Native ES did not confirm one linked finding.")
            return self._ingest_update(
                key, phase="published", finding_id=response["findings"][0], last_error=""
            )
        email_artifact = row.get("email_artifact")
        if email_artifact:
            artifact_id = self._ingest_save_artifact(
                row, "email", email_artifact["cef"], email_artifact["name"], publish=True,
            )
            return self._ingest_update(
                key, phase="published", email_artifact_id=artifact_id, last_error=""
            )
        artifact_id = self._ingest_save_artifact(
            row, "ready",
            {"quarantineIdentity": row["identity"], "workItemId": key,
             "vaultId": row["vault_id"], "fileName": self._safe_filename(row["identity"]),
             "fileHashSha256": row["eml_sha256"], "ingestionReady": True,
             "attachmentCount": row["attachment_count"]},
            "Quarantine email ready for analysis", publish=True,
        )
        return self._ingest_update(
            key, phase="published", ready_artifact_id=artifact_id, last_error=""
        )

    def _run_native_poll(self, param, *, require_es=False):
        ar = self.add_action_result(ActionResult(dict(param)))
        try:
            self._ingest_settings()
            if require_es and self._ingest_target != "es":
                raise AutomationError("Enable native ES ingestion before on es poll.")
        except Exception as exc:
            return ar.set_status(phantom.APP_ERROR, "Ingest target resolution failed: " + (
                self._utils.redact_sensitive_text(str(exc), max_chars=500)
                if isinstance(exc, AutomationError) else type(exc).__name__))
        try:
            self._ingest_deadline = time.monotonic() + 600
            self._ingest_ledger_full = False
            with self._ingest_poll_lock():
                records = self._ingest_records()
                has_pending = any(r["phase"] in {"reserved", "preparing", "ready"}
                                  for r in records.values())
                # Alternate class priority across polls: a slow preparation must
                # not indefinitely prevent the independent global status sweep.
                # Both classes share one deadline; running calls are not cancelled.
                priority = self._ingest_poll_priority() if has_pending else "reconcile"
                self._ingest_reconcile_deadline = self._ingest_deadline
                terminal, errors = (self._ingest_reconcile(records)
                                    if priority == "reconcile" else (0, []))
                attempted_pending = set()
                limit = self._on_poll_container_limit(param)
                active = sum(r["phase"] != "terminal" for r in self._ingest_records().values())
                messages = []
                if not errors and not has_pending and active < self._on_poll_max_containers:
                    try:
                        self._ingest_budget_check()
                        self.save_progress("Listing first 50 Requested quarantine candidates.")
                        result = self._utils.run_action("list", page_size=50)
                        messages = self._normalise_list_result(result)[:50]
                        valid = []
                        for message in messages:
                            if str(message.get("ReleaseStatus", "")).lower() != self._utils.selection_release_status.lower():
                                errors.append("Candidate ReleaseStatus is not Requested.")
                            else:
                                valid.append(message)
                        self._ingest_reserve(valid, self._on_poll_max_containers, limit)
                    except Exception as exc:
                        errors.append("Candidate discovery failed: " + self._ingest_error(exc))
                else:
                    self._ingest_reserve([], self._on_poll_max_containers, 0)
                if self._ingest_ledger_full:
                    errors.append("Native intake ledger capacity reached; existing work continues. Reduce terminal retention.")
                created = 0
                for key, row in self._ingest_scheduled(self._ingest_records(), "prepare"):
                    if row["phase"] in {"terminal", "published"}:
                        continue
                    if row["phase"] in {"publishing", "blocked"}:
                        errors.append(row["identity"] + ": " + (row.get("last_error") or
                            "automation delivery unconfirmed; inspect evidence and use recover quarantine ingestion"))
                        continue
                    try:
                        self._ingest_budget_check()
                        if has_pending:
                            attempted_pending.add(key)
                            # Preparation owns this singleton scheduling. Do not
                            # overwrite the independent remaining-status sweep cursor.
                            retired, read_errors = self._ingest_reconcile(
                                {key: row}, advance_cursor=False
                            )
                            terminal += retired
                            errors.extend(read_errors)
                            row = self._ingest_records()[key]
                            if (row["phase"] == "terminal" or read_errors
                                    or row.get("observed_release_status") != "requested"):
                                self._ingest_schedule_attempt("prepare", key)
                                continue
                            if time.monotonic() >= self._ingest_deadline:
                                break  # No preparation attempt: keep this identity next.
                        self._ingest_schedule_attempt("prepare", key)
                        if (row["phase"] != "ready" or self._ingest_target == "es"
                                or (self._ingest_single_email_artifact() and not row.get("email_artifact"))):
                            row = self._ingest_prepare(key, row)
                        self._ingest_publish(key, row)
                        created += 1
                    except Exception as exc:
                        from ms_quarantine_for_splunk_soar_es_ingestion import ESSubmissionRejected
                        reason = self._ingest_error(exc)
                        updates = {"last_error": reason}
                        if isinstance(exc, ESSubmissionRejected):
                            updates["phase"] = "ready"
                        elif isinstance(exc, (ImportBlocked, OversizedExportError)):
                            updates["phase"] = "blocked"
                        self._ingest_update(key, **updates)
                        errors.append(row["identity"] + ": import/publication failed (" + reason + ")")
                if has_pending and priority == "prepare":
                    retired, read_errors = self._ingest_reconcile(
                        self._ingest_records(), exclude=attempted_pending
                    )
                    terminal += retired
                    errors.extend(read_errors)
                records = self._ingest_records()
                ar.update_summary({
                    "candidates": len(messages), "containers_created": created, "messages_published": created,
                    "ingestion_enabled": True, "active_messages": sum(
                        r["phase"] != "terminal" for r in records.values()),
                    "active_limit": self._on_poll_max_containers, "ingest_target": self._ingest_target,
                    "requested_containers": limit, "terminal_observed": terminal,
                    "errors": len(errors), "candidate_window": 50,
                    "results_may_be_truncated": len(messages) >= 50,
                })
                if errors:
                    return ar.set_status(phantom.APP_ERROR, "; ".join(errors[:10]))
                return ar.set_status(phantom.APP_SUCCESS, f"Imported {created} mail(s); observed {terminal} terminal disposition(s).")
        except Exception as exc:
            return ar.set_status(phantom.APP_ERROR, self._map_error(exc, "on poll"))

    def _handle_ingest_recovery(self, param):
        """Audited local recovery only; never retires a message or sends a disposition."""
        ar = self.add_action_result(ActionResult(dict(param)))
        try:
            self._ingest_settings()
            identity = str(param.get("identity") or "").strip().lower()
            note = str(param.get("operator_note") or "").strip()
            resolution = param.get("resolution")
            if not identity or not note or len(note) > 1000:
                raise AutomationError("Identity and operator_note (1-1000 characters) are required.")
            if resolution not in {"retry_preparation", "confirm_published"}:
                raise AutomationError("Unsupported recovery resolution.")
            with self._ingest_poll_lock():
                key = self._worker_identity_key(identity, self.get_asset_id())
                row = self._ingest_records().get(key)
                if not row or row["identity"] != identity:
                    raise AutomationError("Identity has no native ingestion record.")
                if resolution == "confirm_published":
                    if row["phase"] != "publishing":
                        raise AutomationError("Only uncertain publishing can be confirmed; inspect artifact/finding evidence first.")
                    phase = "published"
                else:
                    if row["phase"] not in {"blocked", "reserved", "preparing", "ready"}:
                        raise AutomationError("Cannot retry uncertain or published delivery. Inspect native execution evidence first.")
                    phase = "preparing" if row.get("container_id") else "reserved"
                audit = list(row.get("recovery_audit", []))
                audit.append({"at": self._utc_now(), "from_phase": row["phase"],
                              "resolution": resolution,
                              "action_run_id": getattr(self, "_ingest_runtime", {}).get("action_run_id"),
                              "user_id": getattr(self, "_ingest_runtime", {}).get("user_id"),
                              "note": self._utils.redact_sensitive_text(note, max_chars=1000)})
                self._ingest_update(key, phase=phase, recovery_audit=audit[-50:], last_error="")
            ar.update_summary({"identity": identity, "phase": phase, "slot_retained": True})
            return ar.set_status(phantom.APP_SUCCESS, "Local recovery recorded; slot retained. No Exchange action performed.")
        except Exception as exc:
            return ar.set_status(phantom.APP_ERROR, self._ingest_error(exc))
