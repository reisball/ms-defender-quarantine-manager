# Installation and configuration

[Back to README](../README.md)

## Requirements

- Splunk SOAR 8.5.0 or later with **native** execution and authenticated access to its local REST API. Automation Broker is not supported. SOAR Cloud has not been verified. The app runs on Python 3.9 or 3.13 (SOAR 8.7 and later use 3.13).
- An Azure Automation Account with a system-assigned Managed Identity and a PowerShell runtime that includes the ExchangeOnlineManagement module.
- An Entra App Registration that can read Azure Automation job status and output.
- Exchange/Defender quarantine permissions for the Managed Identity.
- For ES ingestion: a connected ES environment with the [additional fields](ingestion.md#enterprise-security) registered.

Two identities are involved, and neither substitutes for the other:

| Identity | Used for |
|---|---|
| App Registration (configured in the SOAR asset) | Reading Azure Automation job status and output |
| Automation Account Managed Identity | Connecting to Exchange Online and running quarantine commands |

## Install order

For a new installation or an upgrade, follow this order:

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

Create an Entra App Registration with a client secret. Assign its service principal **Automation Job Operator** on the Automation Account. Record the tenant ID, the client ID and the secret **value** (not the secret ID).

## 4. Install the app and create an asset

Install `ms-quarantine-for-splunk-soar-<version>.tgz` in SOAR app management and create an asset.

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

- In the asset's **Ingest Settings**, set the container label and polling schedule. Disable the schedule to pause imports. **Poll Now** runs a manual import.
- Keep the asset's tenant, organization and ingest target unchanged while it has tracked messages.
- For playbooks, use the combined layout and the [playbook input data](ingestion.md#playbook-input-combined-layout). The app does not configure or activate playbooks.
- For ES, complete the [ES setup](ingestion.md#enterprise-security).
