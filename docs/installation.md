# Installation and configuration

[Back to README](../README.md)

## Requirements

- Splunk SOAR 8.7.0 or later with Python 3.13 and native execution.
- An Azure Automation Account with a PowerShell 7.4 runtime environment and the `ExchangeOnlineManagement` module installed in that environment.
- The Automation Account’s **system-assigned managed identity** runs the quarantine commands in Exchange Online.

  See also: [Grant Exchange permissions](#2-grant-exchange-permissions).
- A separate **Microsoft Entra app registration** lets SOAR read Azure Automation job status and output.

  See also: [Register the Microsoft Entra app](#4-register-the-microsoft-entra-app).

## Install order

### 1. Configure Azure Automation

Create or select an Automation Account and enable its system-assigned managed identity. Azure creates the identity for the account.

See also: [Enable a managed identity for Azure Automation](https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation).

### 2. Grant Exchange permissions

Grant the Automation Account’s managed identity the `Exchange.ManageAsApp` application role for app-only sign-in. Then add its service principal to an Exchange role group that grants access to these quarantine cmdlets:

- `Get-QuarantineMessage` — list quarantined messages.
- `Export-QuarantineMessage` — export quarantined messages.
- `Release-QuarantineMessage` — release messages or deny release requests with `-ActionType Deny`.

See also: [Managed identity setup](https://learn.microsoft.com/en-us/powershell/exchange/connect-exo-powershell-managed-identity), [role group assignment](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2#option-2-assign-custom-role-groups-to-the-application-using-service-principals), and [quarantine permissions](https://learn.microsoft.com/en-us/defender-office-365/scc-permissions).

### 3. Create an Azure job-reader role

Create a custom Azure RBAC role with exactly these Actions and no DataActions:

- `Microsoft.Automation/automationAccounts/jobs/read` — read job status.
- `Microsoft.Automation/automationAccounts/jobs/output/read` — read job output.

See also: [Create a custom Azure RBAC role](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles).

### 4. Register the Microsoft Entra app

Create an app registration and a client secret. Assign the job-reader role to the app’s service principal **at the Automation Account scope**. The app registration reads jobs; the webhook starts them.

See also: [Register an application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app), [add a client secret](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials?tabs=client-secret), and [Security](security.md).

### 5. Publish the runbook and create the webhook

Import and publish `ms-defender-quarantine-manager-runbook-<version>.ps1` using PowerShell 7.4 with `ExchangeOnlineManagement`. Create a webhook for the published runbook and save its full HTTPS URL securely. Azure displays it only once.

Set the Exchange tenant domain either in the SOAR asset’s `exchange_organization` field or in the Automation Account’s `ExchangeOrganization` variable. If both are unset, the runbook cannot connect to Exchange.

### 6. Install the app in Splunk SOAR

Install `ms-defender-quarantine-manager-<version>.tgz` from the same release as the runbook.

See also: [App and runbook version pairs](compatibility.md).

### 7. Create and test the SOAR asset

Fill in the fields below, then run **Test Connectivity**. It verifies Azure job access and reads messages with release requests; it does not release mail.

#### Required asset fields

| Field | What to enter |
|---|---|
| HTTPS Webhook URL (with token) | Full HTTPS webhook URL for the published runbook, including its token. HTTP and redirects are rejected. |
| Subscription ID (Azure Automation Account) | Subscription ID of the Automation Account. |
| Resource Group Name (Azure Automation Account) | Name of the resource group containing the Automation Account. |
| Automation Account Name | Name of the Automation Account. |
| Directory (tenant) ID — Microsoft Entra app registration | Entra directory (tenant) ID as a UUID, not a domain name. |
| Application (client) ID — Microsoft Entra app registration | Application (client) ID of the Entra app registration from step 4. |
| Client Secret Value — Microsoft Entra app registration | Client secret **value**, not the secret ID. |

#### Optional asset fields

| Field | What it controls |
|---|---|
| `exchange_organization` | Exchange tenant domain, such as `contoso.onmicrosoft.com`. If blank, the runbook uses the `ExchangeOrganization` Automation Variable. |
| `on_poll_max_containers` | Maximum tracked messages still awaiting a Microsoft outcome: 1–50, default 10. This is not a per-poll limit. |
| `worker_terminal_retention_days` | How long resolved messages remain tracked: 1–365 days, default 30. A message that reappears after expiry can be imported again. |
| `artifact_layout` | `combined` (default) creates one email artifact per SOAR event. `separate` uses separate artifacts. See [artifact layouts and playbook input](ingestion.md#playbook-input-combined-layout). |
| `artifact_field_*` | Choose which email fields to include. From, To, Subject, email date, and Message-ID are enabled by default; Cc, Reply-To, received date, and quarantine identity are off by default. |
| `poll_timeout_seconds` | Maximum wait for an Azure job: 600–3600 seconds, default 600. |
| `poll_interval_seconds` | Time between Azure job status checks: 1–60 seconds, default 5. This is separate from the SOAR import schedule. |

## Configure ingestion

### SOAR ingest

In the asset’s **Ingest Settings**, select a container label and set the schedule. Leave the schedule off for manual imports with **Poll Now**. Use only one ingesting asset per tenant.

See also: [Email import](ingestion.md) for polling behavior and playbook inputs.

### ES ingest (optional)

For ES findings instead of SOAR events, configure ES ingestion separately.

See also: [ES ingestion setup](ingestion.md#enterprise-security).
