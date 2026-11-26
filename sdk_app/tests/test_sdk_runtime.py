# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import OnPollParams

from src.actions import register_actions
from src.app import Asset, app
from src.ms_quarantine_for_splunk_soar_ingestion import INGEST_STATE_KEY
from src.polling import SDKIntake

IDENTITY = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
MAIL = b"From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nSubject: Fixture\r\n\r\nTest\r\n"


class State:
    def __init__(self):
        self.data = {}

    def get_all(self, *, force_reload):
        assert force_reload
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
        "label": "events",
        "configuration": {"ingest": {}},
    }

    def run(count=0, *, es=False):
        params = OnPollParams(container_count=count)
        return SDKIntake(
            soar, asset, params, azure_factory=lambda _: azure
        )._run_native_poll(params.model_dump(), require_es=es)

    return SimpleNamespace(state=state, azure=azure, soar=soar, run=run)


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
    fixture_app = type(app)(
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
    assert setup.run()
    assert setup.run()
    setup.soar.artifact.create.assert_called_once()
    assert setup.soar.container.create.call_args.args[0]["run_automation"] is False


def test_vault_failure_is_not_published_or_retried_on_schedule(setup):
    setup.soar.vault.create_attachment.side_effect = RuntimeError("Vault failed")
    with pytest.raises(ActionFailure, match="Vault failed"):
        setup.run()
    assert setup.run()
    setup.soar.artifact.create.assert_not_called()
    assert setup.soar.vault.create_attachment.call_count == 1
    setup.soar.vault.create_attachment.side_effect = None
    assert setup.run(1)
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
    assert setup.run(es=True)
    setup.soar.create_findings_bulk.assert_called_once()
