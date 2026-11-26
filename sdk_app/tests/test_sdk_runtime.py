# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

import json
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import httpx2
import pytest
from soar_sdk.app import platform_encryption_backend
from soar_sdk.asset_state import AssetState
from soar_sdk.params import OnPollParams

from src.actions import register_connectivity, register_quarantine_actions
from src.app import Asset, app
from src.ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY
from src.ms_quarantine_for_splunk_soar_utils import AutomationError
from src.polling import SDKIntake, _IntakeStateBackend, _PollResult, register_polling

IDENTITY = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
MAIL = b"From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nSubject: Fixture\r\n\r\nTest\r\n"


def register_actions(app, *, app_version, azure_factory):
    register_connectivity(app, app_version=app_version, azure_factory=azure_factory)
    register_quarantine_actions(app, azure_factory=azure_factory)


class State:
    def __init__(self):
        self.data = {}

    def get_all(self):
        return deepcopy(self.data)

    def put_all(self, data):
        self.data = deepcopy(data)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Unexpected outbound HTTP")

    monkeypatch.setattr("socket.create_connection", unexpected)
    monkeypatch.setattr("socket.socket.connect", unexpected)


@pytest.fixture
def setup():
    state = State()
    asset = SimpleNamespace(
        cache_state=state, model_dump=lambda: {"azure_tenant_id": "test-tenant"}
    )
    message = {
        "Identity": IDENTITY,
        "ReleaseStatus": "Requested",
        "SenderAddress": "sender@example.invalid",
        "RecipientAddress": "recipient@example.invalid",
    }
    azure = Mock(selection_release_status="Requested")
    azure.redact_sensitive_text.side_effect = lambda exc, **_: str(exc)

    def action(name, **kwargs):
        if name == "list":
            return {"messages": [message], "count": 1}
        assert (name, kwargs["identity"]) == ("export", IDENTITY)
        return {"_eml_bytes": MAIL}

    azure.run_action.side_effect = action
    soar = Mock()
    soar.get_asset_id.return_value = "938122"
    soar.container.create.return_value = 23
    soar.vault.create_attachment.return_value = "test-vault-id"
    soar.artifact.create.return_value = 99
    soar.get.return_value.json.return_value = {
        "name": "test asset",
        "configuration": {"ingest": {"container_label": "events"}},
    }

    def run(count=0, *, es=False, layout="combined"):
        asset.model_dump = lambda: {
            "azure_tenant_id": "test-tenant",
            "artifact_layout": layout,
        }
        params = OnPollParams(container_count=count)
        result = _PollResult(params.model_dump(), es=es)
        SDKIntake(
            soar,
            asset,
            params,
            state=state,
            poll_lock=nullcontext,
            result=result,
            azure_factory=lambda _: azure,
        )._run_native_poll(params.model_dump(), require_es=es)
        return result.result

    return SimpleNamespace(state=state, azure=azure, soar=soar, run=run)


def new_app():
    return type(app)(
        name="Test",
        app_type="generic",
        logo="light.svg",
        logo_dark="dark.svg",
        product_vendor="Test",
        product_name="Test",
        publisher="Test",
        appid="11111111-1111-4111-8111-111111111111",
        asset_cls=Asset,
    )


def test_manifest_and_sdk_dispatch():
    actions = app.actions_manager.get_actions()
    assert set(actions) == {
        "on_poll",
        "on_es_poll",
        "test_connectivity",
        "inspect_release_environment",
        "release_quarantine_message",
        "deny_quarantine_release",
    }
    azure = Mock()
    fixture_app = new_app()
    register_actions(fixture_app, app_version="1.1.0", azure_factory=lambda _: azure)
    fake_asset = object()
    for name in [
        "release_quarantine_message",
        "deny_quarantine_release",
        "inspect_release_environment",
    ]:
        handler = fixture_app.actions_manager.get_action(name)
        fixture_app.actions_manager.add_result = Mock()
        assert not handler(
            handler.meta.parameters(identity="invalid"), asset=fake_asset
        )
        result = fixture_app.actions_manager.add_result.call_args.args[0]  # pylint: disable=no-member
        assert "identity" in result.get_message().lower()
    azure.run_action.assert_not_called()


def test_classic_automation_waits_for_vault_and_checkpoint(setup):
    def create(artifact):
        assert artifact["run_automation"] is True
        assert artifact["cef"]["vaultId"] == "test-vault-id"
        setup.soar.vault.create_attachment.assert_called_once()
        (row,) = setup.state.data[INGEST_STATE_KEY]["records"].values()
        assert row["publication_started"] is True
        return 99

    setup.soar.artifact.create.side_effect = create
    assert setup.run().get_status()
    assert setup.run().get_status()
    setup.soar.artifact.create.assert_called_once()
    assert setup.soar.container.create.call_args.args[0]["run_automation"] is False


def test_vault_failure_is_not_published_or_retried_on_schedule(setup):
    setup.soar.vault.create_attachment.side_effect = RuntimeError("Vault failed")
    failed = setup.run()
    assert not failed.get_status()
    assert "Vault failed" in failed.get_message()
    assert setup.run().get_status()
    setup.soar.artifact.create.assert_not_called()
    assert setup.soar.vault.create_attachment.call_count == 1
    setup.soar.vault.create_attachment.side_effect = None
    assert setup.run(1).get_status()
    setup.soar.artifact.create.assert_called_once()
    setup.soar.container.create.assert_called_once()


def test_es_finding_ack_links_container_and_does_not_run_soar_automation(setup):
    def get(path):
        if path == "/rest/system_info":
            return Mock(
                **{"json.return_value": {"base_url": "https://soar.example.invalid"}}
            )
        return Mock(
            **{
                "json.return_value": {
                    "name": "test",
                    "configuration": {
                        "ingest": {
                            "use_es_ingest": True,
                            "container_label": "es-events",
                            "es_security_domain": "threat",
                            "es_run_threat_analysis": True,
                        }
                    },
                }
            }
        )

    def bulk(findings, containers):
        assert containers == [23]
        assert findings[0]["run_threat_analysis"] is True
        assert (
            findings[0]["email"]["raw_email_link"]
            == "https://soar.example.invalid/rest/download_attachment?vault_id=test-vault-id"
        )
        assert setup.soar.vault.create_attachment.called
        assert all(
            not c.args[0]["run_automation"]
            for c in setup.soar.artifact.create.call_args_list
        )
        return {
            "status": "success",
            "created": 1,
            "failed": 0,
            "findings": ["f-1"],
            "container_ids": containers,
            "errors": [],
        }

    setup.soar.get.side_effect = get
    setup.soar.create_findings_bulk.side_effect = bulk
    assert setup.run(es=True).get_status()
    setup.soar.create_findings_bulk.assert_called_once()


CONFIG = {
    "webhook_url": "https://fixture.invalid/hook?token=webhook-marker",
    "azure_subscription_id": "subscription-fixture",
    "azure_resource_group": "fixture",
    "azure_automation_account": "fixture",
    "azure_tenant_id": "tenant-fixture",
    "azure_client_id": "client-fixture",
    "azure_client_secret": "client-secret-marker",
}


@pytest.mark.parametrize(
    "identifier",
    [
        "on_poll",
        "test_connectivity",
        "inspect_release_environment",
        "release_quarantine_message",
        "deny_quarantine_release",
    ],
)
def test_bad_asset_validation_never_serializes_inputs(monkeypatch, capsys, identifier):
    fixture_app = new_app()
    azure = Mock()
    register_polling(fixture_app, azure_factory=azure)
    register_actions(fixture_app, app_version="1.1.0", azure_factory=azure)

    salts = []
    secrets = {
        "encrypted_webhook": CONFIG["webhook_url"],
        "encrypted_client_secret": CONFIG["azure_client_secret"],
    }

    # Exercise App.handle() through SDK decryption, asset validation and actual dispatch.
    def decrypt(value, salt):
        salts.append(salt)
        return secrets[value]

    monkeypatch.setattr(platform_encryption_backend, "decrypt", decrypt)
    monkeypatch.setattr(fixture_app.soar_client, "update_client", Mock())
    monkeypatch.setattr(
        fixture_app.soar_client,
        "get",
        Mock(return_value=Mock(**{"json.return_value": {}})),
    )
    response = fixture_app.handle(
        json.dumps(
            {
                "identifier": identifier,
                "parameters": [{"identity": IDENTITY}]
                if identifier not in {"on_poll", "test_connectivity"}
                else [{}],
                "asset_id": "938122",
                "config": {
                    **{k: v for k, v in CONFIG.items() if k != "azure_client_id"},
                    "webhook_url": "encrypted_webhook",
                    "azure_client_secret": "encrypted_client_secret",
                    "app_version": "1.1.0",
                    "directory": "app",
                    "main_module": "src.app",
                },
            }
        )
    )
    assert salts == ["938122", "938122"]
    manager = fixture_app.actions_manager
    (result,) = manager.get_results()
    assert not result.get_status()
    assert "asset configuration" in result.get_message()
    if identifier in {"release_quarantine_message", "deny_quarantine_release"}:
        assert result.get_summary()["outcome"] == "not_executed"
        assert result.get_data()[0]["error_code"] == "invalid_asset_configuration"
    out = (
        str(response)
        + result.get_message()
        + str(result.get_param())
        + str(capsys.readouterr())
    )
    assert "webhook-marker" not in out
    assert "client-secret-marker" not in out
    azure.assert_not_called()


def test_connectivity_registered_summary_and_manifest(monkeypatch):
    fixture_app = new_app()
    azure = Mock()
    build = "ms-quarantine-for-splunk-soar-runbook-1.0.1+sha256." + "a" * 64
    azure.run_action.return_value = {
        "runbook_version": "1.0.1",
        "runbook_build_id": build,
    }
    register_actions(fixture_app, app_version="1.1.0", azure_factory=lambda _: azure)
    monkeypatch.setattr(fixture_app, "_raw_asset_config", CONFIG, raising=False)
    manager = fixture_app.actions_manager
    manager.action_identifier = "test_connectivity"
    manager.handle_action({})
    (result,) = manager.get_results()
    assert result.get_status()
    assert result.get_summary()["app_version"] == "1.1.0"
    assert result.get_summary()["runbook_version"] == "1.0.1"
    assert result.get_summary()["runbook_build_id"] == build
    assert "differs" in result.get_summary()["version_warning"]
    assert "differs" in result.get_message()
    assert (
        sum(
            field["data_path"].startswith("action_result.summary.")
            for field in manager.get_action("test_connectivity").meta.model_dump()[
                "output"
            ]
        )
        == 4
    )


@pytest.mark.parametrize("es", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
def test_registered_poll_http_and_process_restart(
    setup, monkeypatch, tmp_path, es, interrupted
):
    calls = []

    def confirm_publication():
        assert_intent()
        if interrupted:
            # Model a worker terminating after submission, before acknowledging.
            raise KeyboardInterrupt

    def response(request):
        method, path = request.method, request.url.path
        payload = json.loads(request.content) if request.content else {}
        if method == "GET" and path == "/rest/asset/938122":
            return httpx2.Response(
                200,
                json={
                    "name": "test-asset",
                    "configuration": {
                        "ingest": {
                            "container_label": "quarantine",
                            "use_es_ingest": es,
                            "es_security_domain": "threat",
                        }
                    },
                },
            )
        if method == "GET" and path == "/rest/system_info":
            return httpx2.Response(
                200, json={"base_url": "https://soar.example.invalid"}
            )
        assert method == "POST"
        calls.append((path, payload))
        if path == "/rest/container":
            assert payload["label"] == "quarantine"
            assert payload["artifacts"] == []
            assert payload["run_automation"] is False
            return httpx2.Response(200, json={"id": 23})
        if path == "/rest/artifact":
            if payload["run_automation"]:
                assert not es
                assert calls[-2][0] == "vault"
                confirm_publication()
            return httpx2.Response(200, json={"id": 99})
        assert path == "/rest/enterprise_security/findings/bulk_create"
        assert es
        assert payload["container_ids"] == [23]
        confirm_publication()
        return httpx2.Response(
            200,
            json={
                "status": "success",
                "created": 1,
                "failed": 0,
                "findings": ["f-1"],
                "container_ids": [23],
                "errors": [],
            },
        )

    def assert_intent():
        (record,) = reader_state()[INGEST_STATE_KEY]["records"].values()
        assert record["publication_started"] is True

    def reader_state():
        reader = new_app().actions_manager
        monkeypatch.setattr(reader, "get_state_dir", lambda: str(tmp_path))
        return AssetState(
            _IntakeStateBackend(reader, "938122"), "ingest", "938122"
        ).get_all()

    def dispatch():
        fixture_app = new_app()
        register_polling(fixture_app, azure_factory=lambda _: setup.azure)
        manager = fixture_app.actions_manager
        monkeypatch.setattr(manager, "get_state_dir", lambda: str(tmp_path))
        monkeypatch.setattr(manager, "get_asset_id", lambda: "938122")
        monkeypatch.setattr(fixture_app, "_raw_asset_config", CONFIG, raising=False)
        soar = fixture_app.soar_client
        monkeypatch.setattr(soar, "get_asset_id", lambda: "938122")
        monkeypatch.setattr(soar.vault, "create_attachment", vault)
        manager.set_soar_client(soar)
        # This checks real SDK POST helpers with instrumented network responses.
        with httpx2.Client(
            base_url="https://soar.example.invalid",
            headers={"X-CSRFToken": "fixture"},
            cookies={"sessionid": "fixture"},
            transport=httpx2.MockTransport(response),
        ) as client:
            monkeypatch.setattr(soar, "_client", client)
            manager.action_identifier = "on_poll"
            manager.handle_action({})
        (result,) = manager.get_results()
        return result, manager.get_action("on_es_poll" if es else "on_poll").meta

    def vault(cid, content, _name):
        assert (cid, content) == (23, MAIL)
        if es:
            assert calls[-1][0] == "/rest/artifact"
            assert calls[-1][1]["name"] == "Quarantine release request"
            assert calls[-1][1]["run_automation"] is False
        calls.append(("vault", {}))
        return "test-vault-id"

    assert reader_state() == {}
    if interrupted:
        with pytest.raises(KeyboardInterrupt):
            dispatch()
    else:
        result, meta = dispatch()
        assert result.get_status(), result.get_message()
        assert result.get_summary()["messages_published"] == 1
        assert result.get_summary()["ingest_target"] == ("es" if es else "soar")
        if es:
            assert "Acknowledged 1 linked ES finding(s)" in result.get_message()
        assert (
            sum(
                field["data_path"].startswith("action_result.summary.")
                for field in meta.model_dump()["output"]
            )
            == 13
        )
    (row,) = reader_state()[INGEST_STATE_KEY]["records"].values()
    assert row["status"] == ("running" if interrupted else "completed")
    before = list(calls)
    result, _ = dispatch()
    assert result.get_status()
    assert result.get_summary()["messages_published"] == 0
    assert calls == before
    (row,) = reader_state()[INGEST_STATE_KEY]["records"].values()
    assert row["status"] == ("failed" if interrupted else "completed")
    if interrupted:
        assert row["publication_started"] is True


@pytest.mark.parametrize("explicit_es", [False, True])
def test_unauthenticated_or_broker_style_runs_fail_before_intake(
    monkeypatch, explicit_es
):
    fixture_app = new_app()
    azure_factory = Mock()
    register_polling(fixture_app, azure_factory=azure_factory)
    monkeypatch.setattr(fixture_app, "_raw_asset_config", CONFIG, raising=False)
    manager = fixture_app.actions_manager
    manager.action_identifier = "on_es_poll" if explicit_es else "on_poll"
    manager.handle_action({})
    (result,) = manager.get_results()
    assert not result.get_status()
    assert "Native SOAR session authentication" in result.get_message()
    azure_factory.assert_not_called()


def test_missing_persistent_checkpoint_is_not_acknowledged(
    tmp_path, setup, monkeypatch
):
    manager = new_app().actions_manager
    monkeypatch.setattr(manager, "get_state_dir", lambda: str(tmp_path))
    monkeypatch.setattr(manager, "save_state_to_file", lambda *_: None)
    params = OnPollParams()
    backend = _IntakeStateBackend(manager, "938122")
    intake = SDKIntake(
        setup.soar,
        SimpleNamespace(model_dump=lambda: CONFIG),
        params,
        state=AssetState(backend, "ingest", "938122"),
        poll_lock=backend.poll_lock,
        result=_PollResult({}, es=False),
        azure_factory=lambda _: setup.azure,
    )
    failed = intake._run_native_poll({})
    assert not failed
    assert "did not persist" in intake.result.result.get_message()
    setup.soar.container.create.assert_not_called()
    setup.soar.artifact.create.assert_not_called()


def test_separate_layout_confirms_request_on_container_reuse(setup):
    request_ids = []
    request_receipts = iter([0, True, 42])

    def create(artifact):
        if artifact["name"] == "Quarantine release request":
            assert artifact["container_id"] == 23
            assert artifact["run_automation"] is False
            request_ids.append(artifact["source_data_identifier"])
            return next(request_receipts)
        assert len(request_ids) == 3
        return 99

    setup.soar.artifact.create.side_effect = create
    for count in (0, 1):
        result = setup.run(count, layout="separate")
        assert not result.get_status()
        assert "did not confirm the Quarantine Request artifact" in result.get_message()
        setup.soar.vault.create_attachment.assert_not_called()
    assert setup.run(1, layout="separate").get_status()
    assert len(request_ids) == 3
    assert len(set(request_ids)) == 1
    setup.soar.container.create.assert_called_once()
    assert setup.soar.container.create.call_args.args[0]["artifacts"] == []
    assert setup.soar.artifact.create.call_args.args[0]["run_automation"] is True


def test_poll_rejects_missing_ingest_label_even_if_top_level_label_exists(setup):
    setup.soar.get.return_value.json.return_value = {
        "label": "unrelated",
        "configuration": {"ingest": {}},
    }
    result = setup.run()
    assert not result.get_status()
    assert "container label must be configured" in result.get_message()
    setup.azure.run_action.assert_not_called()
    setup.soar.container.create.assert_not_called()
    assert not setup.state.data


def test_poll_es_acknowledgement_survives_later_budget_error(setup, monkeypatch):
    other = IDENTITY.replace("aaaaaaaa", "cccccccc")
    second = {"Identity": other, "ReleaseStatus": "Requested"}
    dispatch = setup.azure.run_action.side_effect

    def azure(name, **params):
        if name == "list":
            original = dispatch(name)
            return {"messages": [*original["messages"], second], "count": 2}
        return dispatch(name, **params)

    setup.azure.run_action.side_effect = azure

    def get(path):
        data = {
            "/rest/system_info": {"base_url": "https://soar.example.invalid"},
            "/rest/asset/938122": {
                "configuration": {
                    "ingest": {
                        "container_label": "quarantine",
                        "use_es_ingest": True,
                        "es_security_domain": "threat",
                    }
                }
            },
        }
        return Mock(**{"json.return_value": data[path]})

    setup.soar.get.side_effect = get

    def publish(_findings, containers):
        def expire(self):
            raise AutomationError("Poll phase time budget exhausted.")

        monkeypatch.setattr(SDKIntake, "_ingest_budget_check", expire)
        return {
            "status": "success",
            "created": 1,
            "failed": 0,
            "findings": ["f-1"],
            "container_ids": containers,
            "errors": [],
        }

    setup.soar.create_findings_bulk.side_effect = publish
    result = setup.run(es=True)
    assert not result.get_status()
    assert result.get_summary()["messages_published"] == 1
    assert result.get_summary()["errors"] == 1
    assert "Acknowledged 1 linked ES finding(s)" in result.get_message()
    assert "time budget exhausted" in result.get_message()
    setup.soar.create_findings_bulk.assert_called_once()


@pytest.fixture
def es_setup(setup):
    setup.soar.get.side_effect = lambda path: Mock(
        **{
            "json.return_value": {
                "/rest/system_info": {"base_url": "https://soar.example.invalid"},
                "/rest/asset/938122": {
                    "configuration": {
                        "ingest": {
                            "container_label": "quarantine",
                            "use_es_ingest": True,
                            "es_security_domain": "threat",
                        }
                    },
                },
            }[path]
        }
    )
    setup.soar.create_findings_bulk.return_value = {
        "status": "success",
        "created": 1,
        "failed": 0,
        "findings": ["f-1"],
        "container_ids": [23],
        "errors": [],
    }
    return setup


@pytest.mark.parametrize("persisted", [False, True])
def test_poll_es_counts_receipt_even_when_completion_save_raises(
    es_setup, monkeypatch, persisted
):
    setup = es_setup
    save = setup.state.put_all

    def save_checkpoint(data):
        records = data.get(INGEST_STATE_KEY, {}).get("records", {})
        if any(row["status"] == "completed" for row in records.values()):
            if persisted:
                save(data)
            raise AutomationError("Synthetic completion checkpoint error.")
        save(data)

    monkeypatch.setattr(setup.state, "put_all", save_checkpoint)
    result = setup.run(es=True)

    assert not result.get_status()
    assert "Synthetic completion checkpoint error" in result.get_message()
    assert result.get_summary()["errors"] == 1
    assert result.get_summary()["messages_published"] == 1
    assert result.get_summary()["failed_imports"] == int(not persisted)
    assert "Acknowledged 1 linked ES finding(s)" in result.get_message()
    (row,) = setup.state.data[INGEST_STATE_KEY]["records"].values()
    assert row["status"] == ("completed" if persisted else "failed")
    assert row["publication_started"] is True
    if persisted:
        assert row["finding_id"] == "f-1"
    setup.soar.create_findings_bulk.assert_called_once()


@pytest.mark.parametrize("receipt_id", [True, 1.0, "1", 2])
def test_poll_es_rejects_unlinked_or_non_integer_receipts(es_setup, receipt_id):
    es_setup.soar.container.create.return_value = 1
    es_setup.soar.create_findings_bulk.return_value["container_ids"] = [receipt_id]

    result = es_setup.run(es=True)

    assert not result.get_status()
    assert result.get_summary()["messages_published"] == 0
    assert result.get_summary()["containers_created"] == 0
    assert result.get_summary()["errors"] == 1
    assert "Native ES did not confirm one linked finding." in result.get_message()
    (row,) = es_setup.state.data[INGEST_STATE_KEY]["records"].values()
    assert row["status"] == "failed"
    assert row["publication_started"] is True
    assert not row.get("finding_id")
    es_setup.soar.create_findings_bulk.assert_called_once()


def test_distinct_worker_temp_dirs_contend_on_same_ledger_lock(tmp_path, monkeypatch):
    shared = tmp_path / "state"
    workers = [new_app().actions_manager for _ in range(2)]
    for manager in workers:
        monkeypatch.setattr(manager, "get_state_dir", lambda: str(shared))
    first, second = (_IntakeStateBackend(m, "938122") for m in workers)
    monkeypatch.setattr("src.actions.gettempdir", lambda: str(tmp_path / "first"))
    with first.poll_lock():
        monkeypatch.setattr("src.actions.gettempdir", lambda: str(tmp_path / "second"))
        with pytest.raises(BlockingIOError), second.poll_lock():
            pytest.fail("Second worker should not acquire the same ledger lock")
        with _IntakeStateBackend(workers[1], "938123").poll_lock():
            pass
    with second.poll_lock():
        pass
    assert not (tmp_path / "first").exists()
    assert not (tmp_path / "second").exists()


@pytest.mark.parametrize("action, expected", [("release_quarantine_message", "released"), ("deny_quarantine_release", "denied")])
@pytest.mark.parametrize("scenario", ["preflight_failure", "confirmed", "unexpected_result_error"])
def test_sdk_disposition_keeps_submission_evidence(action, expected, scenario):
    azure = Mock()
    azure.redact_sensitive_text.side_effect = lambda value, **_: value
    azure.fire_webhook.return_value = "fixture-job"
    azure.wait_for_action_result.return_value = {"status": expected, "observed_release_status": expected}
    if scenario == "preflight_failure":
        azure.get_mgmt_token.side_effect = AutomationError("Reader unavailable")
    if scenario == "unexpected_result_error":
        azure.wait_for_action_result.side_effect = RuntimeError("Unexpected failure")

    fixture_app = new_app()
    register_actions(fixture_app, app_version="1.1.0", azure_factory=lambda _: azure)
    handler = fixture_app.actions_manager.get_action(action)
    sink = Mock()
    fixture_app.actions_manager.add_result = sink
    success = handler(handler.meta.parameters(identity=IDENTITY), asset=SimpleNamespace(azure_tenant_id=IDENTITY.split("\\", maxsplit=1)[0]))
    summary = sink.call_args.args[0].get_summary()
    if scenario == "preflight_failure":
        azure.fire_webhook.assert_not_called()
        assert not success
        assert summary["outcome"] == "not_executed"
    else:
        assert azure.method_calls[0][0] == "get_mgmt_token"
        azure.fire_webhook.assert_called_once()
        assert summary["azure_job_id"] == "fixture-job"
        assert summary["outcome"] == ("confirmed" if success else "unknown")
        assert bool(success) == (scenario == "confirmed")


def test_sdk_poll_refreshes_expiry_before_reconcile(setup):
    message = {"Identity": IDENTITY, "ReleaseStatus": "Requested", "Expires": "2020-01-01T00:00:00Z", "SenderAddress": "sender@example.invalid", "RecipientAddress": "recipient@example.invalid"}
    default = setup.azure.run_action.side_effect

    def action(name, **kwargs):
        if name == "list":
            return {"messages": [message], "count": 1}
        return default(name, **kwargs)

    setup.azure.run_action.side_effect = action
    assert setup.run().get_status()
    message["Expires"] = "2100-01-01T00:00:00Z"
    assert setup.run().get_status()
    (row,) = setup.state.data[INGEST_STATE_KEY]["records"].values()
    assert row["expires_at"].startswith("2100-01-01")


@pytest.mark.parametrize("observed_status", ["Requested", ""])
def test_sdk_inspect_requires_observed_status(observed_status):
    azure = Mock()
    azure.redact_sensitive_text.side_effect = lambda value, **_: value
    azure.run_action.return_value = {
        "status": "inspected",
        "observed_identity": IDENTITY,
        "observed_release_status": observed_status,
    }
    fixture_app = new_app()
    register_actions(fixture_app, app_version="1.1.0", azure_factory=lambda _: azure)
    handler = fixture_app.actions_manager.get_action("inspect_release_environment")
    fixture_app.actions_manager.add_result = Mock()
    assert bool(handler(handler.meta.parameters(identity=IDENTITY), asset=object())) == bool(observed_status)
