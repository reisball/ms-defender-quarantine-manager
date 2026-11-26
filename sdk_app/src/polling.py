# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

"""SDK binding for quarantine intake, retaining per-message durable checkpoints."""

from contextlib import nullcontext
from functools import partial
from pathlib import Path

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset
from soar_sdk.asset_state import AssetState
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.meta.actions import ActionMeta
from soar_sdk.params import OnESPollParams, OnPollParams
from soar_sdk.shims.phantom.install_info import is_onprem_broker_install

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

from .special_actions import register_special

logger = getLogger()


class PollSummary(ActionOutput):
    candidates: int
    containers_created: int
    messages_published: int
    ingestion_enabled: bool
    active_messages: int
    active_limit: int
    ingest_target: str
    requested_containers: int
    terminal_observed: int
    failed_imports: int
    errors: int
    candidate_window: int
    results_may_be_truncated: bool


class _PollResult:
    def __init__(self, params: dict, *, es: bool):
        self.result = ActionResult(False, "", params)
        self.summary = {}
        self.es = es

    def update_summary(self, summary: dict) -> None:
        self.summary = summary
        self.result.set_summary(summary)

    def set_status(self, success: bool, message: str) -> bool:
        if self.es and self.summary:
            count = self.summary["messages_published"]
            message = f"Acknowledged {count} linked ES finding(s). {message}"
        return self.result.set_status(success, message)


class _IntakeStateBackend:
    """Use the SDK atomic file helpers, outside the SDK's deferred action state.

    The ledger has its own per-asset file so BaseConnector finalization cannot
    overwrite a publication checkpoint with an older in-memory snapshot.
    Run only with native SOAR execution; never use a broker-local file.
    """

    def __init__(self, actions_manager, asset_id: str):
        self.manager = actions_manager
        self.key = f"{asset_id}_msq_intake_v2"

    def load_state(self) -> dict:
        return self.manager.load_state_from_file(self.key)

    def save_state(self, state: dict) -> None:
        self.manager.save_state_to_file(self.key, state)

    def poll_lock(self):
        return _execution_lock(
            "ingest", self.key, parent=Path(self.manager.get_state_dir())
        )


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
    _ingest_separate_request = True

    def __init__(
        self,
        soar,
        asset,
        params,
        *,
        state,
        poll_lock,
        result,
        azure_factory=build_azure,
    ):
        self.soar = soar
        self.state = state
        self._poll_lock = poll_lock
        self.result = result
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
        self.config["ingest"] = asset.get("configuration", {}).get("ingest", {})
        self._ingest_runtime.pop("asset_id", None)
        settings = super()._ingest_settings()
        self._asset_label = settings.get("container_label")
        if not isinstance(self._asset_label, str) or not self._asset_label.strip():
            raise AutomationError(
                "A container label must be configured for native intake."
            )
        return settings

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
        return self._poll_lock()

    def _operation_state_lock(self):
        # The whole poll, including each read/write, is serialized.
        return nullcontext()

    def get_asset_id(self):
        return _asset_id(self.soar)

    def get_container_id(self):
        # The metadata projection includes a legacy context field; the publish
        # path uses the separately acknowledged intake container instead.
        return 0

    def get_config(self):
        return self.config

    def is_poll_now(self):
        return self.params.is_manual_poll()

    def load_state(self):
        return self.state.get_all()

    def save_state(self, state):
        self.state.put_all(state)
        if self.state.get_all() != state:
            raise AutomationError("SOAR did not persist the intake checkpoint.")
        return True

    def save_container(self, container):
        container["asset_id"] = int(self.get_asset_id())
        container["label"] = self._asset_label
        container_id = self.soar.container.create(container)
        return bool(container_id), "", container_id

    def save_artifact(self, artifact):
        artifact_id = self.soar.artifact.create(artifact)
        return type(artifact_id) is int and artifact_id > 0, "", artifact_id

    def _store_in_vault(self, content, identity, *, container_id, file_name):
        vault_id = self.soar.vault.create_attachment(container_id, content, file_name)
        return bool(vault_id), {"vault_id": vault_id}

    def _map_error(self, exc, label):
        if isinstance(exc, ActionFailure):
            return self._utils.redact_sensitive_text(exc.message)
        if isinstance(exc, BlockingIOError):
            return "Another intake poll is still running."
        return _map_error(self._utils, exc, label)

    _ingest_failed = staticmethod(lambda status: not status)
    _ingest_status = staticmethod(bool)

    def _ingest_action_result(self, _param):
        return self.result

    save_progress = staticmethod(logger.progress)


def _asset_id(soar: SOARClient) -> str:
    asset_id = str(soar.get_asset_id())
    if not asset_id.isascii() or not asset_id.isdecimal() or int(asset_id) <= 0:
        raise ActionFailure("SDK execution has no valid SOAR asset ID.")
    return asset_id


def register_polling(app: App, *, azure_factory=build_azure) -> None:
    def run(params, soar: SOARClient, asset: BaseAsset, *, es: bool) -> ActionResult:
        params_dict = params.model_dump()
        if (
            is_onprem_broker_install()
            or not soar.client.headers.get("X-CSRFToken")
            or not soar.client.cookies.get("sessionid")
        ):
            raise ActionFailure(
                "Native SOAR session authentication is required for intake; Automation Broker is not supported."
            )
        if soar._get_es_finding_context() is not None:
            raise ActionFailure(
                "Direct ES ingestion does not support linked SOAR containers; use SOAR-proxied ES ingestion."
            )
        asset_id = _asset_id(soar)
        result = _PollResult(params_dict, es=es)
        backend = _IntakeStateBackend(app.actions_manager, asset_id)
        intake = SDKIntake(
            soar,
            asset,
            params,
            state=AssetState(backend, "ingest", asset_id),
            poll_lock=backend.poll_lock,
            result=result,
            azure_factory=azure_factory,
        )
        intake._run_native_poll(params_dict, require_es=es)
        return result.result

    for es, params_class, name, description in (
        (
            False,
            OnPollParams,
            "on poll",
            "Import Requested messages into SOAR with acknowledged Vault uploads.",
        ),
        (
            True,
            OnESPollParams,
            "on es poll",
            "Import Requested messages as ES findings with a linked SOAR event.",
        ),
    ):
        register_special(
            app,
            ActionMeta(
                action=name,
                identifier=name.replace(" ", "_"),
                type="ingest",
                read_only=True,
                parameters=params_class,
                description=description,
            ),
            PollSummary,
            partial(run, es=es),
        )
    app.actions_manager.supports_es_polling = True
