# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.
"""App-owned native intake; never performs an Exchange disposition.

Each identity has a small result record, not a resumable workflow. Scheduled
polls never replay failed/unknown attempts. Native Poll Now starts a fresh
attempt for failed Requested candidates; ES lost responses remain ambiguous.
"""

import base64
import fcntl
import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email import policy
from email.feedparser import BytesFeedParser

from ms_quarantine_for_splunk_soar_utils import MAX_DECODED_EML_BYTES, AutomationError


INGEST_STATE_KEY = "quarantine_native_ingest_v1"
MAX_INGEST_RECORDS = 1000
MAX_MIME_PARTS = 200
MAX_ATTACHMENTS = 100
MAX_MIME_DEPTH = 30
POLL_PHASE_SECONDS = 600
POLL_CANDIDATE_WINDOW = 50
_EXPIRY_TIMESTAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,7}))?(Z|[+-](?:0[0-9]|1[0-3]):[0-5][0-9]|[+-]14:00)"
)


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
        parser.feed(eml[offset : offset + 8192])
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
                or (part.get_content_maintype() == "multipart" and (part.get_filename() or part.get_content_disposition() == "attachment"))
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
            is_file = (
                name
                or part.get_content_disposition() == "attachment"
                or part.get_content_maintype() not in {"text", "multipart"}
                or part.get("Content-ID")
            )
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
        """Read current records, conservatively collapsing old pending workflows."""
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
            ranks = {}
            for old in legacy.values():
                if not isinstance(old, dict):
                    raise AutomationError("Legacy intake record is malformed.")
                identity = str(old.get("identity") or "").strip().lower()
                if not identity:
                    raise AutomationError("Legacy intake identity is missing.")
                key = self._worker_identity_key(identity, self.get_asset_id())
                row = {
                    "key": key,
                    "identity": identity,
                    "status": "completed" if old.get("state") == "completed" else "failed",
                    "terminal": old.get("state") in {"completed", "failed", "oversized"},
                    "container_id": old.get("container_id"),
                    "created_at": old.get("created_at"),
                    "updated_at": old.get("updated_at"),
                    "last_error": ""
                    if old.get("state") == "completed"
                    else "Previous-version attempt was not confirmed; scheduled replay disabled.",
                }
                stamp = self._parse_state_timestamp(old.get("updated_at"))
                rank = (stamp is not None, stamp or datetime.min.replace(tzinfo=timezone.utc), json.dumps(row, sort_keys=True))
                if key not in records or rank > ranks[key]:
                    records[key], ranks[key] = row, rank
            data = {"scope": self._ingest_scope(), "records": records, "version": 2}
        if not isinstance(data, dict) or not isinstance(data.get("records"), dict):
            raise AutomationError("Native intake state is malformed.")
        scope = dict(data.get("scope") or {})
        scope.pop("selection_mode", None)
        if scope != self._ingest_scope():
            raise AutomationError("Native intake state/scope mismatch. Restore the original asset pairing.")
        records = {}
        for key, old in data["records"].items():
            if not isinstance(old, dict) or not isinstance(old.get("identity"), str) or not old["identity"].strip() or old.get("key") != key:
                raise AutomationError("Native intake record is malformed.")
            row = dict(old)
            if data.get("version") != 2:
                phase = row.get("phase")
                if phase not in {"reserved", "preparing", "ready", "publishing", "published", "terminal", "blocked"}:
                    raise AutomationError("Native intake record is malformed.")
                row["status"] = (
                    "completed"
                    if (phase == "published" or (phase == "terminal" and row.get("delivery_phase_at_terminal", "published") == "published"))
                    else "failed"
                )
                row["terminal"] = phase == "terminal"
                if row.get("migration_origin") in {"legacy_failed", "legacy_oversized"}:
                    # Preserve the previous migrator's retired slot without
                    # misrepresenting a failed import as successful publication.
                    row["status"] = "failed"
                if row["status"] == "failed":
                    row["last_error"] = "Previous-version attempt was not confirmed; scheduled replay disabled."
                row["publication_started"] = phase == "publishing"
            if row.get("status") not in {"running", "failed", "completed"} or type(row.get("terminal")) is not bool:
                raise AutomationError("Native intake record is malformed.")
            # Never persist prepared payloads, file checkpoints, leases or history.
            fields = {
                "key",
                "identity",
                "status",
                "terminal",
                "container_id",
                "created_at",
                "updated_at",
                "last_error",
                "publication_started",
                "observed_release_status",
                "finding_id",
                "email_artifact_id",
                "ready_artifact_id",
                "missing_artifact_fields",
                "expires_at",
                "last_status_error",
            }
            records[key] = {name: value for name, value in row.items() if name in fields}
        return {"scope": scope, "records": records, "version": 2}

    def _ingest_save(self, state, data):
        state[INGEST_STATE_KEY] = data
        saved = self.save_state(state)
        if saved is False or self._ingest_failed(saved):
            raise AutomationError("Native intake state could not be saved.")

    def _ingest_records(self):
        with self._operation_state_lock():
            return self._ingest_load(self.load_state())["records"]

    def _ingest_update(self, key, **updates):
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            if key not in data["records"]:
                raise AutomationError("Native intake attempt disappeared.")
            row = data["records"][key]
            row.update(updates, updated_at=self._utc_now())
            self._ingest_save(state, data)
            return dict(row)

    def _ingest_begin_poll(self):
        # Only called with the process-held poll lock. A running marker now
        # belongs to an interrupted process, never to a concurrent live poll.
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._worker_terminal_retention_days)
            for key, row in list(data["records"].items()):
                stamp = self._parse_state_timestamp(row.get("updated_at"))
                if row["terminal"] and stamp is not None and stamp < cutoff:
                    del data["records"][key]
                elif row["status"] == "running":
                    row.update(
                        status="failed",
                        updated_at=self._utc_now(),
                        last_error="Interrupted attempt; publication may have succeeded. Inspect native evidence before Poll Now.",
                    )
            self._ingest_save(state, data)
            return data["records"]

    def _ingest_expiry(self, value):
        # Old rows and incomplete Exchange metadata are not expiry evidence.
        match = _EXPIRY_TIMESTAMP.fullmatch(value.strip()) if isinstance(value, str) else None
        if match is None:
            return None
        wall_time, fraction, offset = match.groups()
        if offset == "-00:00":
            return None
        fraction = fraction or ""
        # PowerShell's round-trip format has seven fractional digits; Python 3.9
        # supports six here. Round up so a slot cannot retire before the evidence.
        micros = fraction[:6].ljust(6, "0")
        try:
            expiry = self._parse_state_timestamp(f"{wall_time}.{micros}{offset}")
            if len(fraction) == 7 and fraction[-1] != "0":
                expiry += timedelta(microseconds=1)
            return expiry
        except (AutomationError, OverflowError):
            return None

    def _ingest_claim(self, message, retry_ids):
        """Count new identities once; explicitly retried failures retain their slot."""
        identity = message["Identity"].strip().lower()
        key = self._worker_identity_key(identity, self.get_asset_id())
        with self._operation_state_lock():
            state = self.load_state()
            data = self._ingest_load(state)
            records = data["records"]
            old = records.get(key)
            if old:
                if key not in retry_ids or old["status"] != "failed" or old["terminal"]:
                    return None
            else:
                if sum(not r["terminal"] for r in records.values()) >= self._on_poll_max_containers:
                    return None
                if len(records) >= MAX_INGEST_RECORDS:
                    raise AutomationError("Native intake ledger capacity reached. Reduce terminal retention.")
            row = {
                "key": key,
                "identity": identity,
                "status": "running",
                "terminal": False,
                "container_id": old.get("container_id") if old else None,
                "created_at": old.get("created_at") if old else self._utc_now(),
                "updated_at": self._utc_now(),
                "last_error": "",
                "publication_started": False,
            }
            expires = self._ingest_expiry(message.get("Expires"))
            if expires is not None:
                row["expires_at"] = expires.isoformat()
            elif old and old.get("expires_at"):
                row["expires_at"] = old["expires_at"]
            if old and old.get("last_status_error"):
                row["last_status_error"] = old["last_status_error"]
            records[key] = row
            self._ingest_save(state, data)
            return {**row, "message": dict(message)}

    def _ingest_error(self, exc):
        if isinstance(exc, AutomationError):
            if getattr(exc, "job_id", None):
                # Azure failures retain the known job/last-status hint. Native
                # Vault/ES errors have no Azure job and must not inherit one.
                return self._map_error(exc, "import")
            return self._utils.redact_sensitive_text(str(exc), max_chars=2048)
        return self._utils.redact_sensitive_text(type(exc).__name__ + ": " + str(exc), max_chars=2048)

    def _ingest_budget_check(self):
        if time.monotonic() >= getattr(self, "_ingest_deadline", float("inf")):
            raise AutomationError("Poll phase time budget exhausted; no further work started in this phase.")

    def _ingest_reconcile(self, records, listed_requested):
        errors = []
        terminal = 0
        intake_blocked = False
        unlisted = []
        for key, row in records.items():
            if row["terminal"]:
                continue
            if row["identity"] not in listed_requested:
                unlisted.append((key, row))
            elif row.get("last_status_error") or row.get("observed_release_status") != "requested":
                self._ingest_update(key, observed_release_status="requested", last_status_error="")
        # Least-recently checked first: slow jobs must not starve later rows.
        oldest = datetime.min.replace(tzinfo=timezone.utc)
        unlisted.sort(key=lambda item: self._parse_state_timestamp(item[1].get("updated_at")) or oldest)
        for key, row in unlisted:
            try:
                self._ingest_budget_check()
            except AutomationError as exc:
                errors.append(str(exc))
                break  # This row was not attempted; keep its place next poll.
            self.save_progress("Checking tracked quarantine message status.")
            try:
                result = self._utils.run_action("reconcile", identity=row["identity"])
                observed = str(result.get("observed_release_status") or "").lower()
                if not observed:
                    raise AutomationError("Current quarantine status is unavailable.")
            except Exception as exc:
                reason = self._ingest_error(exc)
                self._ingest_update(key, last_status_error=reason)
                errors.append(row["identity"] + ": status observation unavailable (" + reason + ")")
                intake_blocked = True
                break  # Unclassified, service and transport failures fail closed.
            expiry = self._ingest_expiry(row.get("expires_at"))
            expired_and_missing = observed == "notfound" and expiry is not None and expiry <= datetime.now(timezone.utc)
            is_terminal = observed in {"released", "denied"} or expired_and_missing
            reason = ""
            if observed == "notfound" and not is_terminal:
                reason = "Exact lookup returned no message; expiry is not confirmed."
                errors.append(row["identity"] + ": " + reason)
            elif observed == "error":
                reason = "Exchange reports ReleaseStatus=Error; no terminal disposition confirmed."
                errors.append(row["identity"] + ": " + reason)
            self._ingest_update(key, terminal=is_terminal, observed_release_status=observed, last_status_error=reason)
            terminal += int(is_terminal)
        return terminal, errors, intake_blocked

    def _ingest_save_artifact(self, row, suffix, cef, name, *, publish=False):
        artifact = {
            "container_id": row["container_id"],
            "source_data_identifier": self._worker_source_identifier(row["identity"], self.get_asset_id()) + "-" + suffix,
            "name": name,
            "label": "email",
            "type": "email",
            "severity": "medium",
            "cef": cef,
            "run_automation": publish,
        }
        status, _message, artifact_id = self.save_artifact(artifact)
        if self._ingest_failed(status):
            raise AutomationError("SOAR rejected the ingestion artifact: " + str(_message))
        if not artifact_id:
            raise AutomationError("SOAR did not confirm the ingestion artifact.")
        return artifact_id

    def _ingest_single_email_artifact(self):
        return getattr(self, "_ingest_target", "soar") == "soar" and self._asset_artifact_options["layout"] == "combined"

    def _ingest_prepare(self, key, row):
        """Prepare this attempt in memory; every file precedes automation."""
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
        mail, attachments = parse_mail_files(eml)
        # Microsoft context, not RFC headers, is required by downstream automation.
        for field in ("SenderAddress", "RecipientAddress"):
            if not isinstance(row["message"].get(field), str) or not self._bounded_artifact_text(row["message"][field]):
                raise AutomationError("Missing Microsoft " + field + "; import not published.")
        row["eml_sha256"] = hashlib.sha256(eml).hexdigest()
        separate_request = not single_artifact and getattr(self, "_ingest_separate_request", False)
        request = None
        if row["container_id"] is None or separate_request:
            claim = {
                "message": row["message"],
                "identity": row["identity"],
                "work_item_id": key,
                "source_data_identifier": self._worker_source_identifier(row["identity"], self.get_asset_id()),
            }
            container = self._build_poll_container(claim)
            if separate_request:
                (request,) = container["artifacts"]
            if single_artifact or separate_request:
                container["artifacts"] = []
            container["run_automation"] = False
            for artifact in container.get("artifacts", []):
                artifact["run_automation"] = False
            if row["container_id"] is None:
                self._ingest_budget_check()
                status, _message, container_id = self.save_container(container)
                if self._ingest_failed(status) or type(container_id) is not int or container_id <= 0:
                    raise AutomationError("SOAR did not confirm the ingestion container: " + str(_message))
                self._ingest_update(key, container_id=container_id)
                row["container_id"] = container_id
        if request is not None:
            # Confirm a standalone receipt before Vault or publication, also
            # when Poll Now is reusing a previously acknowledged container.
            self._ingest_budget_check()
            status, _message, artifact_id = self.save_artifact(dict(request, container_id=row["container_id"], run_automation=False))
            if self._ingest_failed(status) or type(artifact_id) is not int or artifact_id <= 0:
                raise AutomationError("SOAR did not confirm the Quarantine Request artifact.")
        original = self._safe_filename(row["identity"])
        files = [(original, eml), *attachments]
        vaults = {}
        for index, (name, content) in enumerate(files):
            self._ingest_budget_check()
            file_key = str(index)
            ok, stored = self._store_in_vault(
                content,
                row["identity"],
                container_id=row["container_id"],
                file_name=name,
            )
            if not ok or not isinstance(stored, dict) or not isinstance(stored.get("vault_id"), str) or not stored["vault_id"]:
                detail = str(stored) if not ok else "No Vault ID returned."
                raise AutomationError("SOAR Vault upload was not confirmed: " + detail)
            entry = {"vault_id": stored["vault_id"], "sha256": hashlib.sha256(content).hexdigest()}
            vaults[file_key] = entry
            if not single_artifact:
                hashes = self._calculate_hashes(content)
                self._ingest_budget_check()
                self._ingest_save_artifact(
                    row,
                    "file-" + file_key,
                    {
                        "quarantineIdentity": row["identity"],
                        "workItemId": key,
                        "vaultId": entry["vault_id"],
                        "fileName": name,
                        "fileHash": hashes["sha256"],
                        "fileHashMd5": hashes["md5"],
                        "fileHashSha1": hashes["sha1"],
                        "fileHashSha256": hashes["sha256"],
                        "isOriginalEmail": index == 0,
                    },
                    "Original quarantined email" if index == 0 else "Email attachment",
                )
        metadata = self._extract_email_artifact_metadata(eml)
        options = dict(self._asset_artifact_options)
        options["enabled"] = True
        required_cef = None
        if single_artifact:
            options["fields"] = tuple(field for field in options["fields"] if field not in {"vault_id", "sender_address", "recipient_address"})
            required_cef = {
                "vaultId": vaults["0"]["vault_id"],
                "senderAddress": self._bounded_artifact_text(row["message"].get("SenderAddress", "")),
                "recipientAddress": self._bounded_artifact_text(row["message"].get("RecipientAddress", "")),
            }
        specs, missing = self._build_email_artifact_specs(
            row["identity"],
            self._calculate_hashes(eml),
            metadata,
            options,
            vault_id=vaults["0"]["vault_id"],
            required_cef=required_cef,
        )
        if not single_artifact:
            for index, spec in enumerate(specs):
                self._ingest_budget_check()
                self._ingest_save_artifact(row, "metadata-" + str(index), spec["cef_data"], spec["name"])
        # The complete artifact/finding exists only during this attempt.
        if single_artifact:
            row["email_artifact"] = {"name": specs[0]["name"], "cef": specs[0]["cef_data"]}
        row.update(vault_id=vaults["0"]["vault_id"], attachment_count=len(attachments))
        self._ingest_update(key, missing_artifact_fields=missing)
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
                row["message"],
                eml,
                row["identity"],
                key,
                self._worker_source_identifier(row["identity"], self.get_asset_id()),
                self._ingest_es_settings,
                uploaded,
                client.base_url,
                mail,
                attachments,
            )
            self._ingest_budget_check()
            row["_es_payload"] = client.prepare_bulk_payload({"findings": [finding], "container_ids": [row["container_id"]]})
        return row

    def _ingest_publish(self, key, row, *, on_es_receipt):
        # Persist intent before the first request that may start automation.
        # A lost receipt/state save cannot trigger automatic re-publication.
        payload = row.get("_es_payload")
        is_es = getattr(self, "_ingest_target", "soar") == "es"
        if is_es and not payload:
            raise AutomationError("Native ES finding was not prepared.")
        self._ingest_budget_check()
        self._ingest_update(key, publication_started=True)
        if is_es:
            response = self._ingest_es_client().request("POST", "/rest/enterprise_security/findings/bulk_create", json=payload)
            if (
                response.get("status") in {"success", "error", "failed", "partial_success"}
                and isinstance(response.get("errors"), list)
                and type(response.get("created")) is int
                and response["created"] == 0
                and type(response.get("failed")) is int
                and response["failed"] == 1
                and response.get("findings") == []
                and response.get("container_ids") in ([], [row["container_id"]])
            ):
                raise AutomationError("Native ES rejected the finding: " + json.dumps(response["errors"]))
            if (
                response.get("status") != "success"
                or type(response.get("created")) is not int
                or response["created"] != 1
                or type(response.get("failed")) is not int
                or response["failed"] != 0
                or response.get("errors")
                or response.get("container_ids") != [row["container_id"]]
                or not isinstance(response.get("findings"), list)
                or len(response["findings"]) != 1
                or not isinstance(response["findings"][0], str)
                or not response["findings"][0]
            ):
                raise AutomationError("Native ES did not confirm one linked finding.")
            # The remote acknowledgement is independent of the local checkpoint.
            on_es_receipt()
            return self._ingest_update(key, status="completed", finding_id=response["findings"][0], last_error="")
        email_artifact = row.get("email_artifact")
        if email_artifact:
            artifact_id = self._ingest_save_artifact(
                row,
                "email",
                email_artifact["cef"],
                email_artifact["name"],
                publish=True,
            )
            return self._ingest_update(key, status="completed", email_artifact_id=artifact_id, last_error="")
        artifact_id = self._ingest_save_artifact(
            row,
            "ready",
            {
                "quarantineIdentity": row["identity"],
                "workItemId": key,
                "vaultId": row["vault_id"],
                "fileName": self._safe_filename(row["identity"]),
                "fileHashSha256": row["eml_sha256"],
                "ingestionReady": True,
                "attachmentCount": row["attachment_count"],
            },
            "Quarantine email ready for analysis",
            publish=True,
        )
        return self._ingest_update(key, status="completed", ready_artifact_id=artifact_id, last_error="")

    def _run_native_poll(self, param, *, require_es=False):
        ar = self._ingest_action_result(param)
        summary = None
        try:
            self._ingest_settings()
            if require_es and self._ingest_target != "es":
                raise AutomationError("Enable native ES ingestion before on es poll.")
            with self._ingest_poll_lock():
                records = self._ingest_begin_poll()
                # Snapshot once: a failure during this poll is never retried in it.
                manual_poll = self.is_poll_now()
                retry_ids = {key for key, row in records.items() if manual_poll and row["status"] == "failed" and not row["terminal"]}
                limit = self._on_poll_container_limit(param)
                self.save_progress("Listing first 50 Requested quarantine candidates.")
                result = self._utils.run_action("list", page_size=POLL_CANDIDATE_WINDOW)
                messages = self._normalise_list_result(result)[:POLL_CANDIDATE_WINDOW]
                listed_requested = {
                    message["Identity"].strip().lower() for message in messages if str(message.get("ReleaseStatus", "")).lower() == "requested"
                }
                # The list is read-only. Do not publish if a subsequent exact
                # lookup detects a shared failure. List absence alone proves nothing.
                self._ingest_deadline = time.monotonic() + POLL_PHASE_SECONDS
                terminal, errors, intake_blocked = self._ingest_reconcile(records, listed_requested)
                self._ingest_deadline = time.monotonic() + POLL_PHASE_SECONDS
                records = self._ingest_records()
                active = sum(not row["terminal"] for row in records.values())
                created = attempts = 0
                summary = {
                    "candidates": len(messages),
                    "containers_created": 0,
                    "messages_published": 0,
                    "ingestion_enabled": True,
                    "active_messages": active,
                    "active_limit": self._on_poll_max_containers,
                    "ingest_target": self._ingest_target,
                    "requested_containers": limit,
                    "terminal_observed": terminal,
                    "failed_imports": sum(r["status"] == "failed" and not r["terminal"] for r in records.values()),
                    "errors": len(errors),
                    "candidate_window": POLL_CANDIDATE_WINDOW,
                    "results_may_be_truncated": len(messages) >= POLL_CANDIDATE_WINDOW,
                }

                def count_es_receipt():
                    summary["messages_published"] += 1

                if not intake_blocked and (bool(retry_ids) or active < self._on_poll_max_containers):
                    # Prefer already-counted explicit retries over new candidates.
                    messages.sort(key=lambda m: self._worker_identity_key(m["Identity"].strip().lower(), self.get_asset_id()) not in retry_ids)
                    for message in messages:
                        if attempts >= limit:
                            break
                        if str(message.get("ReleaseStatus", "")).lower() != "requested":
                            errors.append("Candidate ReleaseStatus is not Requested.")
                            summary["errors"] = len(errors)
                            continue
                        self._ingest_budget_check()
                        row = self._ingest_claim(message, retry_ids)
                        if row is None:
                            continue
                        key = row["key"]
                        if key in retry_ids:
                            summary["failed_imports"] -= 1
                        else:
                            summary["active_messages"] += 1
                        retry_ids.discard(key)
                        attempts += 1
                        try:
                            prepared = self._ingest_prepare(key, row)
                            self._ingest_publish(key, prepared, on_es_receipt=count_es_receipt)
                            created += 1
                            summary["containers_created"] = created
                            if self._ingest_target != "es":
                                summary["messages_published"] = created
                        except Exception as exc:
                            reason = self._ingest_error(exc)
                            current = self._ingest_records()[key]
                            if current.get("publication_started"):
                                reason += "; publication may have succeeded. Inspect native evidence before Poll Now; a fresh ES attempt may duplicate a finding."
                            # If success was saved but its acknowledgement was lost,
                            # retain completion rather than allowing manual replay.
                            if current["status"] != "completed":
                                self._ingest_update(key, status="failed", last_error=reason)
                                summary["failed_imports"] += 1
                            errors.append(row["identity"] + ": import/publication failed (" + reason + ")")
                            summary["errors"] = len(errors)
                records = self._ingest_records()
                failed = sum(r["status"] == "failed" and not r["terminal"] for r in records.values())
                summary.update(active_messages=sum(not r["terminal"] for r in records.values()), failed_imports=failed)
                ar.update_summary(summary)
                if errors:
                    return ar.set_status(self._ingest_status(False), "; ".join(errors[:10]))
                message = f"Imported {created} mail(s); resolved {terminal} tracked status(es)."
                if failed:
                    message += f" {failed} failed import(s) retained; scheduled retries disabled. Inspect native evidence, then use Poll Now for Requested candidates in the first 50."
                return ar.set_status(self._ingest_status(True), message)
        except Exception as exc:
            if summary is not None:
                summary["errors"] += 1
                ar.update_summary(summary)
            return ar.set_status(self._ingest_status(False), self._map_error(exc, "on poll"))
