# Installation and configuration

[Back to README](../README.md)

## Requirements

- Splunk SOAR 8.7.0 or later with Python 3.13 and native execution.
- An Azure Automation Account with a PowerShell 7.4 runtime environment and the `ExchangeOnlineManagement` module installed in that environment.
- The Automation Account’s **system-assigned managed identity** runs the quarantine commands in Exchange Online. See [Grant Exchange permissions](#2-grant-exchange-permissions).
- A separate **Microsoft Entra app registration** lets SOAR read Azure Automation job status and output. See [Configure Azure job access](#3-configure-azure-job-access).

## Install order

Publish the runbook first, then install the SOAR app from the same release. See the [compatibility matrix](compatibility.md) before enabling intake.

## 1. Configure Azure Automation

1. Enable the Automation Account’s system-assigned managed identity.
2. Import `ms-defender-quarantine-manager-runbook-<version>.ps1`, select the PowerShell 7.4 runtime with `ExchangeOnlineManagement`, and publish the runbook.
3. Create a webhook for the runbook and save its HTTPS URL securely. Azure displays it only once.

## 2. Grant Exchange permissions

Grant the Automation Account’s managed identity the `Exchange.ManageAsApp` application role for app-only sign-in. Then add its Exchange service principal to a role group that allows it to list and export quarantined messages and to release messages or deny release requests. Sign-in permission alone does not grant quarantine access.

See Microsoft’s [managed identity setup](https://learn.microsoft.com/en-us/powershell/exchange/connect-exo-powershell-managed-identity), [role group assignment](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2#option-2-assign-custom-role-groups-to-the-application-using-service-principals), and [quarantine permissions](https://learn.microsoft.com/en-us/defender-office-365/scc-permissions).

## 3. Configure Azure job access

Create a Microsoft Entra app registration with a client secret. Assign its service principal a [custom Azure RBAC role](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles) scoped to the **Automation Account**, with exactly these Actions and no DataActions:

- `Microsoft.Automation/automationAccounts/jobs/read` — read job status.
- `Microsoft.Automation/automationAccounts/jobs/output/read` — read job output.

The webhook starts jobs. The app registration only reads them; it does not need Automation Job Operator. See [Security](security.md) for inherited access and shared-account risks.

## 4. Install the app and create an asset

Install `ms-defender-quarantine-manager-<version>.tgz` in SOAR and create a new asset. Fill in the fields below, then run **Test Connectivity**. It verifies Azure job access and reads messages with release requests; it does not release mail.

### Required asset fields

| Field | What to enter |
|---|---|
| `webhook_url` | Full HTTPS webhook URL for the published runbook, including its token. HTTP and redirects are rejected. |
| `azure_subscription_id` | Subscription ID of the Automation Account. |
| `azure_resource_group` | Name of the resource group containing the Automation Account. |
| `azure_automation_account` | Name of the Automation Account. |
| `azure_tenant_id` | Entra directory (tenant) ID as a UUID, not a domain name. |
| `azure_client_id` | Application (client) ID of the Entra app registration from step 3. |
| `azure_client_secret` | Client secret **value**, not the secret ID. |

### Optional asset fields

| Field | What it controls |
|---|---|
| `exchange_organization` | Exchange tenant domain, such as `contoso.onmicrosoft.com`. If blank, the runbook uses the `ExchangeOrganization` Automation Variable. |
| `on_poll_max_containers` | Maximum tracked messages still awaiting a Microsoft outcome: 1–50, default 10. This is not a per-poll limit. |
| `worker_terminal_retention_days` | How long resolved messages remain tracked: 1–365 days, default 30. A message that reappears after expiry can be imported again. |
| `artifact_layout` | `combined` (default) creates one email artifact per SOAR event. `separate` uses separate artifacts. See [artifact layouts and playbook input](ingestion.md#playbook-input-combined-layout). |
| `artifact_field_*` | Choose which email fields to include. From, To, Subject, email date, and Message-ID are enabled by default; Cc, Reply-To, received date, and quarantine identity are off by default. |
| `poll_timeout_seconds` | Maximum wait for an Azure job: 600–3600 seconds, default 600. |
| `poll_interval_seconds` | Time between Azure job status checks: 1–60 seconds, default 5. This is separate from the SOAR import schedule. |

## 5. Configure ingestion

### SOAR ingest

In the asset’s **Ingest Settings**, select a container label and set the schedule. Leave the schedule off for manual imports with **Poll Now**. Use only one ingesting asset per tenant. See [Email import](ingestion.md) for polling behavior and playbook inputs.

### ES ingest (optional)

For ES findings instead of SOAR events, follow the separate [ES ingestion setup](ingestion.md#enterprise-security).
