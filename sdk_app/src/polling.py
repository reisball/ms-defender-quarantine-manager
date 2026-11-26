# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

"""SDK binding for quarantine intake, retaining per-message durable checkpoints."""

import json
from collections.abc import Generator, Iterator
from contextlib import nullcontext

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.models.finding import Finding
from soar_sdk.params import OnESPollParams, OnPollParams

from .actions import _execution_lock, _map_error, build_azure
from .ms_quarantine_for_splunk_soar_es_ingestion import NativeESClient
from .ms_quarantine_for_splunk_soar_ingestion import (
    INGEST_STATE_KEY,
    NativeIngestionMixin,
)
from .ms_quarantine_for_splunk_soar_mail import (
    QuarantineMail,
    _parse_config_integer,
    parse_artifact_asset_config,
)
from .ms_quarantine_for_splunk_soar_utils import AutomationError

logger = getLogger()


class _PollResult:
    def update_summary(self, summary: dict) -> None:
        logger.progress(json.dumps(summary, sort_keys=True))

    def set_status(self, success: bool, message: str) -> bool:
        if not success:
            raise ActionFailure(message)
        logger.progress(message)
        return True


class _LinkedES:
    """Classic SDK proxy for findings linked to an already prepared SOAR event."""

    _public_download_origin = NativeESClient._public_download_origin

    def __init__(self, soar: SOARClient) -> None:
        self.soar = soar
        self._download_origin = None

    @property
    def base_url(self) -> str:
        return self._public_download_origin()

    def request(self, method: str, path: str, **kwargs) -> dict:
        if method == "GET":
            data = self.soar.get(path).json()
        elif (
            method == "POST"
            and path == "/rest/enterprise_security/findings/bulk_create"
        ):
            body = kwargs["json"]
            data = self.soar.create_findings_bulk(
                body["findings"], body["container_ids"]
            )
        else:
            raise AutomationError("Unexpected SDK ES operation.")
        if not isinstance(data, dict):
            raise AutomationError("SDK ES did not return an object.")
        return data

    @staticmethod
    def prepare_bulk_payload(payload: dict) -> dict:
        return payload


class SDKIntake(NativeIngestionMixin, QuarantineMail):
    def __init__(self, soar, asset, params, *, azure_factory=build_azure):
        self.soar = soar
        self.asset = asset
        self.params = params
        self.config = asset.model_dump()
        self._utils = azure_factory(asset)
        self._on_poll_max_containers = self._asset_integer(
            "on_poll_max_containers", 10, 50
        )
        self._worker_terminal_retention_days = self._asset_integer(
            "worker_terminal_retention_days", 30, 365
        )
        self._asset_artifact_options = parse_artifact_asset_config(self.config)
        self._ingest_runtime = {"asset_id": self.get_asset_id()}
        self._client = _LinkedES(soar)

    def _asset_integer(self, field, default, upper):
        value = self.config.get(field)
        parsed = _parse_config_integer(default if value is None else value, field)
        if not 1 <= parsed <= upper:
            raise AutomationError(f"{field} must be between 1 and {upper}.")
        return parsed

    def _ingest_settings(self):
        # The SDK routes on_poll from native ingest configuration. Re-read the
        # asset as the intake core must not silently fall back to SOAR on error.
        asset = self._client.request("GET", f"/rest/asset/{self.get_asset_id()}")
        self._ingest_runtime["asset_name"] = asset.get("name")
        self._asset_label = asset.get("label")
        self.config["ingest"] = asset.get("configuration", {}).get("ingest", {})
        self._ingest_runtime.pop("asset_id", None)
        return super()._ingest_settings()

    def _ingest_es_client(self):
        return self._client

    def _ingest_load(self, state):
        # This SDK namespace is for fresh assets. Never read a legacy ledger.
        if INGEST_STATE_KEY not in state:
            return {"scope": self._ingest_scope(), "records": {}, "version": 2}
        if (
            not isinstance(state[INGEST_STATE_KEY], dict)
            or state[INGEST_STATE_KEY].get("version") != 2
        ):
            raise AutomationError("Unexpected SDK intake state version.")
        return super()._ingest_load(state)

    def _ingest_poll_lock(self):
        return _execution_lock("ingest", self.get_asset_id())

    def _operation_state_lock(self):
        # The whole poll, including each read/write, is serialized.
        return nullcontext()

    def get_asset_id(self):
        asset_id = str(self.soar.get_asset_id())
        if not asset_id.isascii() or not asset_id.isdecimal() or int(asset_id) <= 0:
            raise AutomationError("SDK execution has no valid SOAR asset ID.")
        return asset_id

    def get_container_id(self):
        # The metadata projection includes a legacy context field; the publish
        # path uses the separately acknowledged intake container instead.
        return 0

    def get_config(self):
        return self.config

    def is_poll_now(self):
        return self.params.is_manual_poll()

    def load_state(self):
        # The polling decorators transact ingest_state and roll it back on
        # errors. Publication intent must survive a failed/terminated poll.
        return self.asset.cache_state.get_all(force_reload=True)

    def save_state(self, state):
        self.asset.cache_state.put_all(state)
        if self.asset.cache_state.get_all(force_reload=True) != state:
            raise AutomationError("SOAR did not persist the intake checkpoint.")
        return True

    def save_container(self, container):
        container["asset_id"] = int(self.get_asset_id())
        if self._asset_label:
            container["label"] = self._asset_label
        container_id = self.soar.container.create(container)
        return bool(container_id), "", container_id

    def save_artifact(self, artifact):
        artifact_id = self.soar.artifact.create(artifact)
        return bool(artifact_id), "", artifact_id

    def _store_in_vault(self, content, identity, *, container_id, file_name):
        vault_id = self.soar.vault.create_attachment(container_id, content, file_name)
        return bool(vault_id), {"vault_id": vault_id}

    def _map_error(self, exc, label):
        if isinstance(exc, ActionFailure):
            return exc.message
        if isinstance(exc, BlockingIOError):
            return "Another intake poll is still running."
        return _map_error(self._utils, exc, label)

    _ingest_failed = staticmethod(lambda status: not status)
    _ingest_status = staticmethod(bool)
    _ingest_action_result = staticmethod(lambda _param: _PollResult())
    save_progress = staticmethod(logger.progress)


def register_polling(app: App, *, azure_factory=build_azure) -> None:
    @app.on_poll()
    def on_poll(
        params: OnPollParams, soar: SOARClient, asset: BaseAsset
    ) -> Iterator[Container | Artifact]:
        """Import Requested messages into SOAR with acknowledged Vault uploads."""
        SDKIntake(soar, asset, params, azure_factory=azure_factory)._run_native_poll(
            params.model_dump()
        )
        return iter(())

    @app.on_es_poll()
    def on_es_poll(
        params: OnESPollParams, soar: SOARClient, asset: BaseAsset
    ) -> Generator[Finding, int | None, None]:
        """Import Requested messages as ES findings with a linked SOAR event."""
        if params.base_url is not None:
            raise ActionFailure(
                "Direct ES ingestion does not support linked SOAR containers; use SOAR-proxied ES ingestion."
            )
        SDKIntake(soar, asset, params, azure_factory=azure_factory)._run_native_poll(
            params.model_dump(), require_es=True
        )
        yield from ()
