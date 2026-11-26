# MS Defender Quarantine Manager

When a recipient requests release of a quarantined email, this app imports the message into Splunk SOAR for investigation. The original email and its attachments are available in the Vault. Importing a message does not release it.

## Configure the asset

Use Splunk SOAR 8.7 or later with Python 3.13. Publish the matching [Azure Automation runbook](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/installation.md#5-publish-the-runbook-and-configure-the-start-method) before configuring the asset.

The Automation Account’s **managed identity** connects to Exchange Online and needs [quarantine permissions](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/installation.md#2-grant-exchange-permissions). The separate **Entra app registration** configured below only [reads Azure job status and output](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/installation.md#3-create-an-azure-job-reader-role). For REST start, the registration also needs job write permission.

### Runbook start method

- **Webhook (`webhook`, default):** Enter the full HTTPS webhook URL.
- **Azure REST API (`rest`):** Enter the published runbook name; no webhook URL is required.

### Required Fields

| Asset field | What to enter |
|---|---|
| HTTPS Webhook URL (with token) — webhook only | Paste the complete HTTPS URL for the webhook attached to the published runbook. Copy it when you create the webhook; Azure displays it only once. [Create a webhook](https://learn.microsoft.com/en-us/azure/automation/automation-webhooks). |
| Subscription ID (Azure Automation Account) | Find the subscription listed on the Automation Account’s Overview page. Open that subscription and copy its ID (a GUID), not its display name. |
| Resource Group Name (Azure Automation Account) | Copy the resource group name shown on the Automation Account’s Overview page. Use the name, not the full resource ID. |
| Automation Account Name | Copy the name of the Automation Account resource, not the name of the runbook inside it. |
| Directory (tenant) ID — Microsoft Entra app registration | Open the job-reader app in Microsoft Entra **App registrations** and copy **Directory (tenant) ID** from **Overview**. Use the GUID, not a domain name. [Register an app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app). |
| Application (client) ID — Microsoft Entra app registration | From the same app’s **Overview**, copy **Application (client) ID**, not **Object ID**. |
| Client Secret Value — Microsoft Entra app registration | In that same app registration, open **Certificates & secrets** and copy the new secret’s **Value**, not its **Secret ID**. [Add a client secret](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials?tabs=client-secret). |

### Configuration Settings

| Asset field | What it controls |
|---|---|
| Connection: Exchange domain (blank = variable) | Enter the Exchange tenant domain (for example, `contoso.onmicrosoft.com`), or leave it blank if the Automation Account has an `ExchangeOrganization` variable. One is required. |
| Email import: Maximum active messages (1-50; default 10) | Maximum unresolved messages tracked at once, not a limit on messages per poll. |
| Email import: Completed-entry retention (whole days, 1-365) | Keeps completed tracking entries for 30 days by default. A message can be imported again if it reappears after its entry expires. |
| Mail fields: Group selected fields: combined or separate | Use `combined` (default) for one email artifact per event, or `separate` for individual artifacts. |
| Mail fields: From, To, Subject, email date, Message-ID | Included by default. Turn off any fields your workflow does not need. |
| Mail fields: Cc, Reply-To, received date, quarantine identity | Off by default. Enable them if a playbook or analyst needs those fields in the email artifacts. |
| Advanced: Job status check (whole seconds, 1-60; default 5) | Time between status checks for an Azure job. This does not change the SOAR import schedule. |
| Advanced: Job timeout (whole seconds, 600-3600; default 600) | How long the app waits for an Azure job; reaching this limit does not cancel the job. |

## Verify the first import

1. Save the asset and run **Test Connectivity**. It checks Azure job access and reads the quarantine list; it does not release mail.
2. In **Ingest Settings**, choose a SOAR container label and leave the schedule off. Use one ingesting asset per tenant.
3. With a known release request in Microsoft Defender, click **Poll Now**. Check that the SOAR event contains the original EML, its attachments in the Vault, and the selected email fields. If there are no pending release requests, no event is expected.
4. Set the schedule once the manual import works. For findings instead of SOAR events, see the separate [Enterprise Security setup](https://github.com/reisball/ms-defender-quarantine-manager/blob/main/docs/ingestion.md#enterprise-security).
