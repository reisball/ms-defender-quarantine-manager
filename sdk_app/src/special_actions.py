# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

"""Bind reserved SDK actions that need a structured ActionResult."""

from collections.abc import Callable

from pydantic import ValidationError
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, ActionResult
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure
from soar_sdk.meta.actions import ActionMeta
from soar_sdk.params import Params
from soar_sdk.types import action_protocol


def register_special(
    app: App, meta: ActionMeta, summary_type: type[ActionOutput], execute: Callable
) -> None:
    """Keep SDK dispatcher metadata without the fixed-result decorators.

    Intake must acknowledge the Vault and persist intent *before* an immediate
    linked publication; a buffered yield cannot preserve that ordering. Both
    ingestion and connectivity also need to return their published summaries.
    """
    meta.summary_type = summary_type

    @action_protocol
    def handler(
        params: Params | None = None, soar: SOARClient | None = None, *, asset=None
    ) -> bool:
        safe_params = {}
        try:
            validated = meta.parameters.model_validate({} if params is None else params)
            safe_params = validated.model_dump()
            config = app.asset if asset is None else asset
            result = execute(
                validated, app.soar_client if soar is None else soar, config
            )
        except ValidationError:
            result = ActionResult(
                False, "Invalid action parameters or asset configuration.", safe_params
            )
        except ActionFailure as exc:
            result = ActionResult(False, exc.message, safe_params)
        except Exception:
            # Do not let unexpected backend errors echo credentials or message data.
            result = ActionResult(
                False,
                "Action could not complete. Check the asset and native SOAR execution configuration.",
                safe_params,
            )
        app.actions_manager.add_result(result)
        return result.get_status()

    handler.params_class = meta.parameters
    handler.meta = meta
    app.actions_manager.set_action(meta.identifier, handler)
