# MS Defender Quarantine Manager

When a recipient requests release of a quarantined email, this app imports the message into Splunk SOAR for investigation. The original email and its attachments are available in the Vault. Importing a message does not release it.

## Configure the asset

Use Splunk SOAR 8.7 or later with Python 3.13. Publish the matching [Azure Automation runbook](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/installation.md#1-configure-azure-automation) before configuring the asset.

The Automation Account’s **managed identity** connects to Exchange Online and needs [quarantine permissions](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/installation.md#2-grant-exchange-permissions). The separate **Entra app registration** configured below only [reads Azure job status and output](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/installation.md#3-configure-azure-job-access). The webhook starts the runbook.

| Asset field | What to enter |
|---|---|
| `webhook_url` | Full HTTPS webhook URL for the published runbook, including its token. |
| `azure_subscription_id` | Subscription ID of the Automation Account. |
| `azure_resource_group` | Name of the resource group containing the Automation Account. |
| `azure_automation_account` | Name of the Automation Account. |
| `azure_tenant_id` | Entra directory (tenant) ID as a UUID, not a domain. |
| `azure_client_id` | Application (client) ID of the Entra app registration. |
| `azure_client_secret` | Client secret **value**, not its ID. |

Leave **Exchange organization** blank to use the runbook’s `ExchangeOrganization` variable, or enter the Exchange tenant domain. The active-message limit controls how many unresolved messages the asset can track; it is not a per-poll limit. Artifact layout and mail-field options control how metadata appears in the SOAR event. Azure job interval and timeout control the wait for the runbook, not the import schedule. See [all optional settings and defaults](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/installation.md#optional-asset-fields).

## Verify the first import

1. Save the asset and run **Test Connectivity**. It checks Azure job access and reads the quarantine list; it does not release mail.
2. In **Ingest Settings**, choose a SOAR container label and leave the schedule off. Use one ingesting asset per tenant.
3. With a known release request in Microsoft Defender, click **Poll Now**. Check that the SOAR event contains the original EML, its attachments in the Vault, and the selected email fields. If there are no pending release requests, no event is expected.
4. Set the schedule once the manual import works. For findings instead of SOAR events, see the separate [Enterprise Security setup](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/ingestion.md#enterprise-security).

## Act on a request

Use `container:data.quarantine_identity` as the identity for these actions:

- **Deny quarantine release** rejects the recipient’s release request.
- **Release quarantine message** releases the email to **all original recipients**.
- **Inspect release environment** checks the message and runbook without changing the message. Additional tenant RBAC diagnostics are opt-in.

A timeout does not cancel the Azure job. Inspect a pending or unknown result before retrying a disposition. For a failed import or other errors, see [Troubleshooting](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/troubleshooting.md).
