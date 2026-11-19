# Installation and configuration

App **3.7.4** / companion Runbook **3.7.4**. [Documentation index](README.md).

## Requirements

- Native Splunk SOAR execution with authenticated access to its local REST API. Automation Broker is not supported; SOAR Cloud compatibility has not been verified.
- An Azure Automation Account with a system-assigned Managed Identity, a PowerShell runtime with ExchangeOnlineManagement, and the companion runbook.
- An App Registration for reading Azure Automation job status and output.
- Exchange/Defender permissions for the quarantine operations you intend to perform.
- For ES ingestion, a connected ES environment with the [required additional fields](ingestion.md#enterprise-security-setup).

The app manifest declares SOAR 8.5.0 as its minimum and Python 3.9/3.13 runtimes. Use the Python runtime supported by your SOAR version; SOAR 8.7 and later use Python 3.13.

## Setup

### 1. Configure Azure Automation

1. Create an Automation Account and enable its system-assigned Managed Identity.
2. Add ExchangeOnlineManagement to the account's PowerShell runtime. Verify the runtime can connect to Exchange Online with Managed Identity.
3. Import and publish `ms-quarantine-for-splunk-soar-runbook-3.7.4.ps1`.
4. Create a webhook for the runbook and copy its URL when Azure displays it.
5. Set the `ExchangeOrganization` Automation Variable to your tenant domain, such as `contoso.onmicrosoft.com`, or provide that value in the SOAR asset. The asset value takes precedence.

Installing the SOAR app does not deploy the runbook to Azure.

### 2. Grant Exchange permissions

The runbook connects with:

```powershell
Connect-ExchangeOnline -ManagedIdentity -Organization <tenant-domain>
```

Grant the Automation Account's Managed Identity `Exchange.ManageAsApp`. For example, using an administrator authorized to assign app roles:

```powershell
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"
$MI = Get-MgServicePrincipal -Filter "DisplayName eq '<automation-account-name>'"
$ExoSP = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'"
$Role = $ExoSP.AppRoles | Where-Object { $_.Value -eq "Exchange.ManageAsApp" }
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id `
  -PrincipalId $MI.Id -ResourceId $ExoSP.Id -AppRoleId $Role.Id
```

`Exchange.ManageAsApp` enables app-only connectivity; operational permissions are a separate requirement. Use a dedicated Exchange/Email & collaboration role group with the required quarantine permissions and the registered Exchange service principal. Azure resource roles do not grant Exchange quarantine rights. Tenant-wide RBAC enumeration is optional diagnosis, not a prerequisite for every action.

References:

- [Managed Identity authentication](https://learn.microsoft.com/en-us/powershell/exchange/connect-exo-powershell-managed-identity)
- [Custom role groups for app-only service principals](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2#option-2-assign-custom-role-groups-to-the-application-using-service-principals)
- [Quarantine permissions](https://learn.microsoft.com/en-us/defender-office-365/scc-permissions)

### 3. Configure Azure job access

Create an Entra App Registration and client secret. Assign its service principal **Automation Job Operator** on the Automation Account. Record the tenant ID, client ID and secret **value**, not the secret ID.

| Identity | Purpose |
|---|---|
| App Registration configured in the SOAR asset | Read Azure Automation job status and output |
| Automation Account Managed Identity | Connect to Exchange Online and perform quarantine operations |

The asset's client secret is not an Exchange login.

### 4. Install the app and configure an asset

Install `ms-quarantine-for-splunk-soar-3.7.4.tgz` through SOAR's app management UI, then create an asset.

This package has its own app UUID and package name. Existing assets for a differently identified app are not converted or inherited. Before changing a tenant's ingesting asset, pause the previous intake and follow the [migration and retention rules](ingestion.md); do not run two ingesting assets for the same tenant.

Enter the connection fields in the order shown by the form:

1. Azure Automation webhook, subscription, resource group and account.
2. Azure API tenant ID, client ID and client secret.
3. Exchange organization, if not supplied by the Automation Variable.

Use the direct **HTTPS** webhook URL, including its token. HTTP URLs and webhook redirects are rejected. Azure TLS certificate verification is enforced; add a private CA to the platform trust store if required.

Intake imports only Microsoft `Requested` messages. Configure the active-message limit and mail fields; there is no source-mode selector. The complete field and action reference is available in the app's installed **Documentation** page ([HTML help](../app/readme.html)).

Run **test connectivity** to check the Azure connection and read Microsoft `Requested` messages. It does not release mail or verify every downstream integration.

### 5. Configure ingestion and analysis

Use **one ingesting asset per tenant**. Keep its tenant, organization and ingest target fixed while tracked work exists. Separate ingesting assets have independent state and can process the same message.

In **Ingest Settings**, configure the container label and polling schedule. Disable the schedule there to pause automatic imports. Use **Poll Now** for a manual import. There is no additional app-level enable checkbox.

For combined-layout SOAR analysis, configure a playbook to consume the single email artifact after the mail is fully prepared. Set the required analyzer assets, analyst/approver, notification recipient, portal URLs and routing label before activating it. Use that artifact's original-email `vaultId`, the event's `data.quarantine_identity` and the [documented input mappings](ingestion.md#data-available-to-soar-playbooks-combined-layout). Update consumers of the old Ready/Request artifacts before activating the changed producer. The app does not configure or activate playbooks for you.

For ES ingestion, configure the native ES target, security domain, threat analysis and automation options. See [Email import](ingestion.md) for the ES field contract and artifact details.
