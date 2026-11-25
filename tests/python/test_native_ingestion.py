"""Native intake regressions; only synthetic mail and backend observations."""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import Mock

import pytest

if __package__:
    from . import test_connector as t
else:
    import test_connector as t

from ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY, mail_files
from ms_quarantine_for_splunk_soar_utils import AutomationError, TokenError

ES = {"use_es_ingest": True, "es_security_domain": "threat",
      "es_urgency": "high", "es_investigation_type": "phishing",
      "es_run_threat_analysis": False, "es_launch_automation": True}


def candidate(number, status="Requested"):
    return {**t.MOCK_MESSAGES[0],
            "Identity": f"{number:08x}" + t.IDENTITY[8:],
            "ReleaseStatus": status, "Subject": f"Synthetic {number}"}


def sample_mail():
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg["To"] = "analyst@example.test"
    msg["Subject"] = "Synthetic quarantine"
    msg["Message-ID"] = "<native@example.test>"
    msg.set_content("Synthetic body")
    msg.add_attachment(b"ATTACHMENT ONE", maintype="application",
                       subtype="octet-stream", filename="../../same.bin")
    msg.add_attachment(b"ATTACHMENT TWO", maintype="application",
                       subtype="octet-stream", filename="same.bin")
    return msg.as_bytes()


@pytest.fixture(params=["soar", "es"])
def target(request):
    return request.param


def setup(tmp_path, target="soar", mode="release_requested", limit=10,
          config_overrides=None):
    config = {"on_poll_max_containers": limit, "quarantine_selection_mode": mode}
    config.update(config_overrides or {})
    if target == "es":
        config["ingest"] = dict(ES)
    c = t.make_connector(state_path=tmp_path / "8_state.json", config_overrides=config)
    c.events = []
    c.artifacts = {}
    c.candidates = [candidate(i) for i in range(1, 31)]
    c.observed = {}
    c.eml = sample_mail()
    c.calls = []
    old_save_container = c.save_container

    def save_container(container):
        assert container["run_automation"] is False
        assert all(a["run_automation"] is False for a in container["artifacts"])
        c.events.append(("container", container["source_data_identifier"]))
        return old_save_container(container)
    c.save_container = save_container

    def save_artifact(artifact):
        key = (artifact["container_id"], artifact["source_data_identifier"])
        if artifact["run_automation"]:
            rows = c._ingest_records()
            row = next(r for r in rows.values() if r["container_id"] == artifact["container_id"])
            assert row["status"] == "running"
            assert row["publication_started"] is True
            assert artifact["cef"]["vaultId"]
            c.events.append(("publish", artifact["container_id"]))
        else:
            c.events.append(("artifact", artifact["container_id"]))
        c.artifacts.setdefault(key, dict(artifact))
        return t.APP_SUCCESS, "saved", len(c.artifacts)
    c.save_artifact = save_artifact

    def run(action, identity=None, **kwargs):
        c.calls.append((action, identity, kwargs))
        if action == "list":
            assert kwargs == {"page_size": 50}
            rows = [m for m in c.candidates if c.observed.get(m["Identity"].lower(), m["ReleaseStatus"])
                    == c._utils.selection_release_status][:50]
            out = dict(t.build_metadata(), action="list", count=len(rows), messages=rows)
        elif action == "export":
            out = dict(t.build_metadata(), action="export", identity=identity,
                       eml=base64.b64encode(c.eml).decode())
        elif action == "reconcile":
            assert kwargs == {}
            status = c.observed.get(identity, c._utils.selection_release_status)
            if isinstance(status, Exception):
                raise status
            out = {"action": "reconcile", "identity": identity,
                   "observed_release_status": status}
        else:
            raise AssertionError("Unexpected Exchange action: " + action)
        return out
    c._utils.run_action = run
    client = Mock(base_url="https://soar.example.test")
    client.prepare_bulk_payload.side_effect = lambda payload: payload

    def es_request(method, path, **kwargs):
        assert (method, path) == ("POST", "/rest/enterprise_security/findings/bulk_create")
        payload = kwargs["json"]
        assert len(payload["findings"][0]["email"]["attachments"]) == 3
        assert payload["findings"][0]["launch_automation"] is True
        cid = payload["container_ids"][0]
        assert next(r for r in c._ingest_records().values()
                    if r["container_id"] == cid)["publication_started"] is True
        c.events.append(("es_publish", cid))
        return {"status": "success", "created": 1, "failed": 0, "errors": [],
                "container_ids": [cid], "findings": [f"finding-{cid}"]}
    client.request.side_effect = es_request
    c._ingest_es_client_instance = client
    return c


def poll(c, **param):
    ar = t.patch_ar(c)
    status = c._handle_on_poll(param)
    return status, ar


@pytest.mark.parametrize("mode", ["release_requested", "needs_review"])
def test_ten_then_three_terminal_refill_without_callbacks(tmp_path, target, mode):
    c = setup(tmp_path, target, mode)
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["active_messages"] == 10
    assert len(c._saved_containers) == 10
    overviews = [a for a in c.artifacts.values() if "emailSubject" in a["cef"]]
    assert len(overviews) == 10
    assert all(a["name"] == "Synthetic quarantine" for a in overviews)
    assert all(a["name"] == "Original quarantined email" for a in c.artifacts.values() if a["cef"].get("isOriginalEmail"))
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 10
    assert all(a["run_automation"] is False for a in c.artifacts.values()) if target == "es" else True
    for index, row in enumerate(list(c._ingest_records().values())[:3]):
        c.observed[row["identity"]] = ["Released", "Denied", "Released"][index]
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["terminal_observed"] == 3
    assert ar.get_summary()["active_messages"] == 10
    assert len(c._saved_containers) == 13
    assert len([x for x in c.calls if x[0] == "reconcile"]) == 10
    assert not any(x[0] in {"release", "deny"} for x in c.calls)


@pytest.mark.parametrize("subject,expected", [
    ("Meeting notes", "Meeting notes"),
    ("RE: [EXTERNAL] Prüfung – FW: Plan?", "RE: [EXTERNAL] Prüfung – FW: Plan?"),
    ("x" * 260, "x" * 240),
    ("", "[No subject]"),
    ("   ", "[No subject]"),
    (None, "[No subject]"),
])
def test_container_subject_name_preserves_context_and_dedup(tmp_path, target, subject, expected):
    c = setup(tmp_path, target, limit=1)
    if subject is None:
        c.candidates[0].pop("Subject", None)
    else:
        c.candidates[0]["Subject"] = subject
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert len(c._saved_containers) == 1
    container = c._saved_containers[0]["container"]
    assert container["name"] == expected
    assert container["data"]["quarantine_identity"] == c.candidates[0]["Identity"]
    if target == "soar":
        assert container["artifacts"] == []
        assert len(c.artifacts) == 1
    else:
        request = container["artifacts"][0]
        assert request["name"] == "Quarantine release request"
        assert request["cef"]["emailSubject"] == (subject or "").strip()[:240]
        assert request["cef"]["quarantineIdentity"] == c.candidates[0]["Identity"]
        assert request["source_data_identifier"] == container["source_data_identifier"] + "-message"
        assert request["run_automation"] is False
    assert container["run_automation"] is False
    assert poll(c)[0] == t.APP_SUCCESS
    assert len(c._saved_containers) == 1


def test_full_window_has_no_extra_list_or_export(tmp_path, target):
    c = setup(tmp_path, target)
    assert poll(c)[0] == t.APP_SUCCESS
    c.calls.clear()
    assert poll(c)[0] == t.APP_SUCCESS
    assert [x[0] for x in c.calls] == ["reconcile"] * 10
    assert len(c._saved_containers) == 10


@pytest.mark.parametrize("status", ["Requested", "NotReleased", "ReleasedToSome",
                                     AutomationError("missing identity"), AutomationError("network")])
def test_nonterminal_and_errors_keep_slot(tmp_path, target, status):
    c = setup(tmp_path, target, limit=1)
    assert poll(c)[0] == t.APP_SUCCESS
    identity = next(iter(c._ingest_records().values()))["identity"]
    c.observed[identity] = status
    result, ar = poll(c)
    assert ar.get_summary()["active_messages"] == 1
    assert len(c._saved_containers) == 1
    assert result == (t.APP_ERROR if isinstance(status, Exception) else t.APP_SUCCESS)


@pytest.mark.parametrize("expires_days", [-1, 1, None])
def test_exact_missing_observation_needs_expiry_to_free_slot(tmp_path, target, expires_days):
    c = setup(tmp_path, target, limit=1)
    c.candidates[0]["Expires"] = "" if expires_days is None else (
        datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
    assert poll(c)[0] == t.APP_SUCCESS
    row, = c._ingest_records().values()
    c.observed[row["identity"]] = "NotFound"
    status, ar = poll(c)
    assert ar.get_summary()["active_messages"] == 1
    expired = expires_days == -1
    assert c._ingest_records()[row["key"]]["terminal"] is expired
    assert ar.get_summary()["messages_published"] == int(expired)
    assert status == (t.APP_SUCCESS if expired else t.APP_ERROR)
    if not expired:
        assert poll(c)[0] == t.APP_ERROR
        assert not c._ingest_records()[row["key"]]["terminal"]


@pytest.mark.parametrize("case_status", ["NotFound", "Error"])
def test_scheduled_poll_continues_after_case_problem(tmp_path, target, case_status):
    c = setup(tmp_path, target, limit=3)
    backlog = c.candidates
    c.candidates = backlog[:2]
    c.candidates[0]["Expires"] = (
        datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert poll(c)[0] == t.APP_SUCCESS
    c.candidates = backlog
    first, second = c._ingest_records().values()
    c.observed[first["identity"]] = case_status
    c.observed[second["identity"]] = "Released"
    status, ar = poll(c)
    assert status == t.APP_ERROR  # Report the case problem despite successful intake.
    assert ar.get_summary()["terminal_observed"] == 1
    assert ar.get_summary()["messages_published"] == 2
    first = c._ingest_records()[first["key"]]
    assert first["last_status_error"] and not first["terminal"]
    assert first["status"] == "completed"


@pytest.mark.parametrize("manual", [False, True])
def test_shared_auth_failure_stops_poll_with_free_capacity(tmp_path, target, manual):
    c = setup(tmp_path, target, limit=2)
    backlog = c.candidates
    c.candidates = backlog[:1]
    assert poll(c)[0] == t.APP_SUCCESS
    c.candidates = backlog
    row, = c._ingest_records().values()
    c.observed[row["identity"]] = TokenError("synthetic authentication failure")
    c.calls.clear()
    c._is_poll_now = manual
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert ar.get_summary()["messages_published"] == 0
    assert [action for action, *_ in c.calls] == ["reconcile"]
    assert "authentication failure" in c._ingest_records()[row["key"]]["last_status_error"]


def test_files_are_attached_to_their_own_container(tmp_path, target):
    t.VAULT_ADDS.clear()
    c = setup(tmp_path, target, limit=2)
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    ids = [item["id"] for item in c._saved_containers]
    assert set(x["container"] for x in t.VAULT_ADDS) == set(ids)
    for cid in ids:
        rows = [x for x in t.VAULT_ADDS if x["container"] == cid]
        assert [x["content"] for x in rows] == [c.eml, b"ATTACHMENT ONE", b"ATTACHMENT TWO"]
        assert all(".." not in x["file_name"] for x in rows)
    assert c.get_container_id() not in ids


def test_restart_respects_persisted_active_limit(tmp_path, target):
    c = setup(tmp_path, target, limit=2)
    assert poll(c)[0] == t.APP_SUCCESS
    again = setup(tmp_path, target, limit=2)
    assert poll(again)[0] == t.APP_SUCCESS
    assert not again._saved_containers
    assert len(again._ingest_records()) == 2


def test_case_duplicates_are_one_identity(tmp_path, target):
    c = setup(tmp_path, target)
    m = candidate(0xabcdef)
    c.candidates = [m, {**m, "Identity": m["Identity"].upper()}]
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert len(c._saved_containers) == 1


def test_import_failure_reserves_slot_and_only_poll_now_retries(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    original = c._store_in_vault
    c._store_in_vault = lambda *a, **k: (False, "failed")
    assert poll(c)[0] == t.APP_ERROR
    assert len(c._ingest_records()) == 1
    assert not [e for e in c.events if e[0] in {"publish", "es_publish"}]
    c._store_in_vault = original
    exports = sum(action == "export" for action, *_ in c.calls)
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["failed_imports"] == 1
    assert sum(action == "export" for action, *_ in c.calls) == exports
    c._is_poll_now = True
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["active_messages"] == 1
    assert len(c._saved_containers) == 1
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 1


def test_uncertain_publication_is_not_repeated(tmp_path, target):
    c = setup(tmp_path, target, limit=1)
    if target == "es":
        c._ingest_es_client_instance.request.side_effect = TimeoutError("lost receipt")
    else:
        original = c.save_artifact
        def fail(artifact):
            if artifact["run_automation"]:
                raise TimeoutError("lost receipt")
            return original(artifact)
        c.save_artifact = fail
    assert poll(c)[0] == t.APP_ERROR
    assert next(iter(c._ingest_records().values()))["status"] == "failed"
    calls = c._ingest_es_client_instance.request.call_count
    assert poll(c)[0] == t.APP_SUCCESS
    assert c._ingest_es_client_instance.request.call_count == calls
    assert len(c._saved_containers) == 1


def test_parallel_poll_is_refused(tmp_path, target):
    c = setup(tmp_path, target)
    with c._ingest_poll_lock():
        status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "running" in ar.get_message()
    assert not c.calls


@pytest.mark.parametrize("change", ["tenant", "target"])
def test_scope_drift_does_not_refill(tmp_path, change):
    c = setup(tmp_path, limit=1)
    assert poll(c)[0] == t.APP_SUCCESS
    if change == "tenant":
        c._config["azure_tenant_id"] = "other"
    else:
        c._config["ingest"] = dict(ES)
    assert poll(c)[0] == t.APP_ERROR
    assert len(c._saved_containers) == 1


def test_poll_now_cannot_exceed_active_asset_limit(tmp_path, target):
    c = setup(tmp_path, target, limit=3)
    c._is_poll_now = True
    assert poll(c, container_count=50)[0] == t.APP_SUCCESS
    assert len(c._saved_containers) == 3


def test_list_get_removed_from_public_manifest_and_dispatch(tmp_path):
    c = setup(tmp_path)
    manifest = json.loads((Path(__file__).resolve().parents[2] / "app" / "ms_quarantine_for_splunk_soar.json").read_text())
    identifiers = {a["identifier"] for a in manifest["actions"]}
    assert not identifiers & {"list_quarantine_requests", "get_quarantine_message"}
    assert {"on_poll", "on_es_poll", "release_quarantine_message", "deny_quarantine_release"} <= identifiers
    for identifier in ["list_quarantine_requests", "get_quarantine_message"]:
        c._action_id = identifier
        assert c.handle_action({}) == t.APP_ERROR
    assert not c.calls


def test_paired_runbook_version_and_fingerprint_are_current():
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[2]
    checked = subprocess.run([sys.executable, str(root / "tools/stamp_runbook.py"), "--check"],
                             cwd=root, capture_output=True, text=True)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    version = json.loads((root / "app/ms_quarantine_for_splunk_soar.json").read_text())["app_version"]
    assert f"runbook_version={version}" in checked.stdout


def test_nested_attached_email_not_extracted_twice():
    nested = EmailMessage()
    nested["Subject"] = "attached"
    nested.set_content("nested body")
    nested.add_attachment(b"INNER", maintype="application", subtype="octet-stream", filename="inner.bin")
    outer = EmailMessage()
    outer["Subject"] = "outer"
    outer.set_content("body")
    outer.add_attachment(nested)
    files = mail_files(outer.as_bytes())
    assert len(files) == 1
    assert files[0][0].endswith(".eml")
    assert b"inner.bin" in files[0][1]


def test_malformed_mail_and_attachment_limits_fail_closed():
    with pytest.raises(AutomationError):
        mail_files(b"not an email")
    message = EmailMessage()
    message["Subject"] = "too many"
    message.set_content("body")
    for n in range(101):
        message.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=str(n))
    with pytest.raises(AutomationError, match="attachment count"):
        mail_files(message.as_bytes())


@pytest.mark.parametrize("legacy", [
    {},
    {"export_mode": "inline", "create_email_artifacts": False},
    {"export_mode": "vault", "create_email_artifacts": True},
    {"export_mode": "", "create_email_artifacts": "maybe"},
    {"export_mode": None, "create_email_artifacts": None},
    {"export_mode": 123, "create_email_artifacts": []},
])
@pytest.mark.parametrize("select_subject", [True, False])
def test_ui_upgrade_preserves_config_and_imports_files_and_selected_headers(tmp_path, target, legacy, select_subject):
    t.VAULT_ADDS.clear()
    c = setup(tmp_path, target, limit=1)
    # Reinitialize like an asset saved with the current manifest, or an upgraded
    # asset retaining the old controls. Keep only the synthetic backend adapter.
    run = c._utils.run_action
    c._config.pop("export_mode", None)
    c._config.pop("create_email_artifacts", None)
    c._config.update(legacy)
    c._config["artifact_layout"] = "separate"
    for key in t.ARTIFACT_FIELD_CONFIG_KEYS.values():
        c._config[key] = False
    c._config["artifact_field_subject"] = select_subject
    before = json.loads(json.dumps(c._config))
    assert c.initialize() == t.APP_SUCCESS
    c._utils.run_action = run
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert c._config == before
    assert [row["content"] for row in t.VAULT_ADDS] == [
        c.eml, b"ATTACHMENT ONE", b"ATTACHMENT TWO",
    ]
    assert any(a["cef"].get("emailSubject") == "Synthetic quarantine"
               for a in c.artifacts.values()) is select_subject
    assert not any("fromEmail" in a["cef"] for a in c.artifacts.values())
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == 1
    assert not any(call[0] in {"release", "deny"} for call in c.calls)


@pytest.mark.parametrize("legacy_mode", ["inline", "vault"])
def test_hidden_asset_imports_large_chunked_mail(tmp_path, target, legacy_mode):
    t.VAULT_ADDS.clear()
    c = setup(tmp_path, target, limit=1)
    backend = c._utils.run_action
    c._config['export_mode'] = legacy_mode
    before = json.loads(json.dumps(c._config))
    assert c.initialize() == t.APP_SUCCESS
    # Real chunked decoder, not the synthetic small-mail export adapter.
    c.eml = sample_mail() + b'\r\n' + b' ' * (11 * 1024 * 1024)
    def run(action, identity=None, **kwargs):
        if action != 'export':
            return backend(action, identity=identity, **kwargs)
        c.calls.append((action, identity, kwargs))
        output = t.chunked_export_output(c.eml, identity=identity, chunk_size=262144)
        with t.req_mock.Mocker() as mock:
            mock.post(t.TOKEN_URL, json={'access_token': t.MOCK_TOKEN})
            mock.get(t.job_output_url(), text=output)
            result = c._utils.get_job_output(t.JOB_ID)
        assert 'eml' not in result
        assert result['_eml_bytes'] == c.eml
        return result
    c._utils.run_action = run
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert c._config == before
    assert [row['content'] for row in t.VAULT_ADDS] == [
        c.eml, b'ATTACHMENT ONE', b'ATTACHMENT TWO',
    ]
    assert len([e for e in c.events if e[0] in {'publish', 'es_publish'}]) == 1
    assert not any(call[0] in {'release', 'deny'} for call in c.calls)


@pytest.mark.parametrize("poll_now", [False, True])
@pytest.mark.parametrize("legacy", [{}, {"enable_on_poll_ingestion": False},
                                   {"enable_on_poll_ingestion": True},
                                   {"enable_on_poll_ingestion": "obsolete-value"}])
def test_platform_poll_runs_without_app_opt_in(tmp_path, target, poll_now, legacy):
    c = setup(tmp_path, target, limit=2, config_overrides=legacy)
    c._is_poll_now = poll_now
    c._action_id = "on_poll" if target == "soar" else "on_es_poll"
    ar = t.patch_ar(c)
    status = c.handle_action({"container_count": 1} if poll_now else {})
    expected = 1 if poll_now else 2
    assert status == t.APP_SUCCESS, ar.get_message()
    assert ar.get_summary()["ingestion_enabled"] is True
    assert ar.get_summary()["messages_published"] == expected
    assert ar.get_summary()["active_limit"] == 2
    assert len(c._saved_containers) == expected
    assert len([e for e in c.events if e[0] in {"publish", "es_publish"}]) == expected
    assert any(action == "list" for action, _, _ in c.calls)
    assert all(c.get_config()[key] == value for key, value in legacy.items())


@pytest.mark.parametrize("legacy_mode", ["release_requested", "needs_review"])
def test_legacy_scope_preserves_published_records_without_republishing(tmp_path, legacy_mode):
    c = setup(tmp_path, limit=1)
    assert poll(c)[0] == t.APP_SUCCESS
    before = c._ingest_records()
    state = c.load_state()
    state[INGEST_STATE_KEY]["scope"]["selection_mode"] = legacy_mode
    c.save_state(state)
    c.events.clear()
    assert c._ingest_records() == before
    assert poll(c)[0] == t.APP_SUCCESS
    assert set(c._ingest_records()) == set(before)
    assert len(c._saved_containers) == 1
    assert not c.events
    assert "selection_mode" not in c.load_state()[INGEST_STATE_KEY]["scope"]


def test_pending_legacy_never_automatically_replays(tmp_path, target):
    c = setup(tmp_path, target, mode="needs_review", limit=1)
    c._ingest_settings()
    identity = candidate(1)["Identity"].lower()
    key = c._worker_identity_key(identity, c.get_asset_id())
    c.save_state({INGEST_STATE_KEY: {"scope": {**c._ingest_scope(), "selection_mode": "needs_review"},
        "records": {key: {"key": key, "identity": identity, "phase": "reserved"}}}})
    for observed in ("NotReleased", "Requested"):
        c.observed[identity] = observed
        assert poll(c)[0] == t.APP_SUCCESS
        assert not c.events
        assert c._ingest_records()[key]["status"] == "failed"
        assert not any(action == "export" for action, *_ in c.calls)
    c._is_poll_now = True
    status, ar = poll(c)
    assert status == t.APP_SUCCESS, ar.get_message()
    assert c._ingest_records()[key]["status"] == "completed"
    assert len(c._saved_containers) == 1


def test_native_intake_does_not_import_notreleased_from_backend(tmp_path):
    c = setup(tmp_path, mode="needs_review", limit=1)
    c._utils.run_action = Mock(return_value={
        **t.build_metadata(), "action": "list", "count": 1,
        "messages": [candidate(1, status="NotReleased")],
    })
    status, ar = poll(c)
    assert status == t.APP_ERROR
    assert "not Requested" in ar.get_message()
    assert not c._saved_containers
    assert not c.events
