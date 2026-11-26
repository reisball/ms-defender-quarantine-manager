# Copyright 2026 Kai Seidenschnur
# Licensed under the Apache License, Version 2.0.

from pydantic import ConfigDict
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset

from .actions import register_actions
from .polling import register_polling
from .version import APP_VERSION


class Asset(BaseAsset):
    model_config = ConfigDict(hide_input_in_errors=True)

    webhook_url: str = AssetField(
        description="Connection: HTTPS webhook URL with token; no redirects",
        sensitive=True,
    )
    azure_subscription_id: str = AssetField(description="Connection: Azure subscription ID")
    azure_resource_group: str = AssetField(description="Connection: Azure resource group")
    azure_automation_account: str = AssetField(description="Connection: Azure Automation Account")
    azure_tenant_id: str = AssetField(description="Connection: Azure API tenant ID (not Exchange)")
    azure_client_id: str = AssetField(description="Connection: Azure API client ID (not Exchange)")
    azure_client_secret: str = AssetField(description="Connection: Azure API secret VALUE (not Exchange)", sensitive=True)
    exchange_organization: str | None = AssetField(
        description="Connection: Exchange domain (blank = variable)",
        default=None,
        required=False,
    )
    on_poll_max_containers: float | None = AssetField(
        description="Email import: Maximum active messages (1-50; default 10)",
        default=10.0,
    )
    worker_terminal_retention_days: float | None = AssetField(
        description="Email import: Completed-entry retention (whole days, 1-365)",
        default=30.0,
    )
    artifact_layout: str | None = AssetField(
        description="Mail fields: Group selected fields: combined or separate",
        default="combined",
        value_list=["combined", "separate"],
    )
    artifact_field_from: bool | None = AssetField(description="Mail fields: From", default=True)
    artifact_field_to: bool | None = AssetField(description="Mail fields: To", default=True)
    artifact_field_cc: bool | None = AssetField(description="Mail fields: Cc", default=False)
    artifact_field_reply_to: bool | None = AssetField(description="Mail fields: Reply-To", default=False)
    artifact_field_subject: bool | None = AssetField(description="Mail fields: Subject", default=True)
    artifact_field_email_date: bool | None = AssetField(description="Mail fields: email date", default=True)
    artifact_field_received_date: bool | None = AssetField(description="Mail fields: received date", default=False)
    artifact_field_message_id: bool | None = AssetField(description="Mail fields: Message-ID", default=True)
    artifact_field_quarantine_identity: bool | None = AssetField(description="Mail fields: quarantine identity", default=False)
    poll_interval_seconds: float | None = AssetField(
        description="Advanced: Job status check (whole seconds, 1-60; default 5)",
        default=5.0,
    )
    poll_timeout_seconds: float | None = AssetField(
        description="Advanced: Job timeout (whole seconds, 600-3600; default 600)",
        default=600.0,
    )


app = App(
    name="MS Defender Quarantine Manager",
    app_type="generic",
    logo="ms_quarantine_for_splunk_soar.svg",
    logo_dark="ms_quarantine_for_splunk_soar_dark.svg",
    product_vendor="Microsoft",
    product_name="Exchange Online Quarantine",
    publisher="Kai Seidenschnur",
    appid="2e21b2c5-a6a6-4fb4-8df7-9dd1135ab08e",
    fips_compliant=False,
    python_version="3.13",
    min_phantom_version="8.7.0",
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


register_actions(app, app_version=APP_VERSION)
register_polling(app)


if __name__ == "__main__":
    app.cli()
