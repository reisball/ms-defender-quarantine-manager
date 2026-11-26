# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import httpx2
import pytest
from soar_sdk.app import platform_encryption_backend
from soar_sdk.params import OnPollParams

from src.actions import register_actions
from src.app import Asset, app
from src.ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY
from src.polling import SDKIntake, _intake_state, _PollResult, register_polling

IDENTITY = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
MAIL = b"From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nSubject: Fixture\r\n\r\nTest\r\n"


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

    def run(count=0, *, es=False):
        params = OnPollParams(container_count=count)
        result = _PollResult(params.model_dump(), es=es)
        SDKIntake(
            soar,
            asset,
            params,
            state=state,
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
    register_actions(fixture_app, app_version="1.0.0", azure_factory=lambda _: azure)
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
        result = fixture_app.actions_manager.add_result.call_args.args[0]
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


def test_bad_asset_validation_never_serializes_inputs(monkeypatch, capsys):
    fixture_app = new_app()
    azure = Mock()
    register_polling(fixture_app, azure_factory=azure)

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
    fixture_app.handle(
        json.dumps(
            {
                "identifier": "on_poll",
                "asset_id": "938122",
                "config": {
                    **{k: v for k, v in CONFIG.items() if k != "azure_client_id"},
                    "webhook_url": "encrypted_webhook",
                    "azure_client_secret": "encrypted_client_secret",
                    "app_version": "1.0.0",
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
    out = result.get_message() + str(result.get_param()) + str(capsys.readouterr())
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
    register_actions(fixture_app, app_version="1.0.0", azure_factory=lambda _: azure)
    monkeypatch.setattr(fixture_app, "_raw_asset_config", CONFIG, raising=False)
    manager = fixture_app.actions_manager
    manager.action_identifier = "test_connectivity"
    manager.handle_action({})
    (result,) = manager.get_results()
    assert result.get_status()
    assert result.get_summary()["app_version"] == "1.0.0"
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
        return _intake_state(reader, "938122").get_all()

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
    intake = SDKIntake(
        setup.soar,
        SimpleNamespace(model_dump=lambda: CONFIG),
        params,
        state=_intake_state(manager, "938122"),
        result=_PollResult({}, es=False),
        azure_factory=lambda _: setup.azure,
    )
    failed = intake._run_native_poll({})
    assert not failed
    assert "did not persist" in intake.result.result.get_message()
    setup.soar.container.create.assert_not_called()
    setup.soar.artifact.create.assert_not_called()
