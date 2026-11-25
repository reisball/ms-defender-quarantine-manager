# Installation and configuration

[Back to README](../README.md)

## Requirements

- Splunk SOAR 8.5.0 or later with **native** execution and authenticated access to its local REST API. Automation Broker is not supported. The app runs on Python 3.9 or 3.13 (SOAR 8.7 and later use 3.13).
- An Azure Automation Account with a system-assigned Managed Identity and a PowerShell 7 runtime with .NET AES-GCM and RSA-OAEP-SHA-256 support (use a supported Azure PowerShell 7.4 runtime), including the ExchangeOnlineManagement module. Windows PowerShell 5.1 cannot process protected list/export.
- An Entra App Registration that can read Azure Automation job status and output.
- Exchange/Defender quarantine permissions for the Managed Identity.
- For ES ingestion: a connected ES environment; see [ES-only setup](ingestion.md#enterprise-security).

Two identities are involved, and neither substitutes for the other:

| Identity | Used for |
|---|---|
| App Registration (configured in the SOAR asset) | Reading Azure Automation job status and output |
| Automation Account Managed Identity | Connecting to Exchange Online and running quarantine commands |

## Install order

For a new installation or an upgrade, follow this order:

Pause intake and avoid manual list/export while updating the pair. Plaintext list/export is not supported by the new runbook.

1. Publish the matching runbook in Azure and confirm it is published.
2. Install the matching SOAR app.
3. Activate the compatible playbook.

Check the [compatibility matrix](compatibility.md) before upgrading.

## 1. Configure Azure Automation

1. Create an Automation Account and enable its system-assigned Managed Identity.
2. Add ExchangeOnlineManagement to the account's PowerShell runtime.
3. Import and publish `ms-quarantine-for-splunk-soar-runbook-<version>.ps1`.
4. Create a webhook for the runbook and copy its URL. Azure shows it only once.
5. Optionally, set the `ExchangeOrganization` Automation Variable to your tenant domain, such as `contoso.onmicrosoft.com`. A value in the SOAR asset takes precedence.

## 2. Grant Exchange permissions

The runbook connects with `Connect-ExchangeOnline -ManagedIdentity -Organization <tenant-domain>`. Grant the Managed Identity the `Exchange.ManageAsApp` app role, for example:

```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"
$MI = Get-MgServicePrincipal -Filter "DisplayName eq '<automation-account-name>'"
$ExoSP = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'"
$Role = $ExoSP.AppRoles | Where-Object { $_.Value -eq "Exchange.ManageAsApp" }
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id `
  -PrincipalId $MI.Id -ResourceId $ExoSP.Id -AppRoleId $Role.Id
```

`Exchange.ManageAsApp` only allows app-only sign-in. The quarantine rights themselves come from an Exchange / Email & collaboration role group that contains the Managed Identity's Exchange service principal. Azure resource roles do not grant Exchange quarantine rights.

Microsoft references: [Managed Identity authentication](https://learn.microsoft.com/en-us/powershell/exchange/connect-exo-powershell-managed-identity), [role groups for service principals](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2#option-2-assign-custom-role-groups-to-the-application-using-service-principals), [quarantine permissions](https://learn.microsoft.com/en-us/defender-office-365/scc-permissions).

## 3. Configure Azure job access

Create an Entra App Registration with a client secret. Create a custom Azure RBAC role with exactly these **Actions** and no **DataActions**:

| Action | Used for |
|---|---|
| `Microsoft.Automation/automationAccounts/jobs/read` | Read the status of the known job: `GET .../jobs/{jobName}`. |
| `Microsoft.Automation/automationAccounts/jobs/output/read` | Read its result: `GET .../jobs/{jobName}/output`. |

Make the custom role available in the resource group containing the Automation Account, then assign it to the service principal **on that Automation Account**, not at the resource group or subscription. The account is the narrowest practical assignment scope because the webhook creates new job IDs dynamically. Record the tenant ID, the client ID and the secret **value** (not the secret ID).

The HTTPS webhook URL starts jobs; these ARM permissions do not grant job creation, control or writes. Do not grant **Automation Job Operator** to the job-reader identity: it includes job creation. When replacing an existing assignment, check the principal's effective access on the account, including inherited and group assignments. A custom read role does not cancel a write permission granted elsewhere. In a shared account, the reader can read output for other runbooks too; use a dedicated account for quarantine and review who inherits job-output access.

Microsoft references: [Automation RBAC operations](https://learn.microsoft.com/en-us/azure/automation/automation-role-based-access-control), [Jobs – Get](https://learn.microsoft.com/en-us/rest/api/automation/job/get), [Jobs – Get Output](https://learn.microsoft.com/en-us/rest/api/automation/job/get-output), [custom roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles).

## 4. Install the app and create an asset

Install `ms-quarantine-for-splunk-soar-<version>.tgz` in SOAR app management and create an asset. The Linux x86-64 package includes the app-local cryptography dependencies for both declared Python runtimes; do not install anything into the SOAR host interpreter.

This app has its own app UUID (`2e21b2c5-a6a6-4fb4-8df7-9dd1135ab08e`). Assets and state of an earlier, differently identified app (such as MS Quarantine Manager) are not migrated. When moving a tenant to this app, pause the old intake first and never run two ingesting assets for the same tenant.

| Asset field | Notes |
|---|---|
| `webhook_url` | Direct **HTTPS** webhook URL including its token. HTTP and redirects are rejected. |
| `azure_subscription_id`, `azure_resource_group`, `azure_automation_account` | Location of the Automation Account |
| `azure_tenant_id`, `azure_client_id`, `azure_client_secret` | App Registration from step 3 (not an Exchange login) |
| `exchange_organization` | Optional; falls back to the `ExchangeOrganization` Automation Variable |
| `on_poll_max_containers` | Active-message limit, 1–50, default 10. See [email import](ingestion.md#active-message-limit). |
| `worker_terminal_retention_days` | 1–365, default 30 |
| `artifact_layout` and `artifact_field_*` | Email artifact layout and optional header fields. Use `combined` for playbooks. |
| `poll_timeout_seconds`, `poll_interval_seconds` | Azure job wait (600–3600 s, default 600) and status interval (1–60 s, default 5) |
| `es_soar_base_url` | Optional external HTTPS SOAR URL used for SOAR and ES import |

Azure TLS certificates are always verified. If you use a private CA, add it to the platform trust store.

Run **test connectivity**. It checks Azure job access and reads `Requested` messages. It does not release mail or test other integrations.

## 5. Configure ingestion

- In the asset's **Ingest Settings**, select the intake target and configure the polling schedule. Disable the schedule to pause automatic imports; **Poll Now** runs a manual import.
- **SOAR events:** Set the container label and leave native ES intake off. No ES fields or drilldowns are needed.
- **ES findings (optional):** Enable native ES intake, set the security domain and complete the [ES-only setup](ingestion.md#enterprise-security).
- Keep the asset's tenant, organization and ingest target unchanged while it has tracked messages.
- For playbooks, use the combined layout and the [playbook input data](ingestion.md#playbook-input-combined-layout). The app does not configure or activate playbooks.
- For ES, complete the [ES setup](ingestion.md#enterprise-security).
