**Bring Microsoft Defender quarantine mail into Splunk SOAR for investigation and controlled disposition.**

MS Quarantine for Splunk SOAR imports quarantined email through an Azure Automation runbook, preserves the original EML and attachments in the SOAR Vault, and prepares one container per message before handing it to analysis. Native Enterprise Security ingestion is also available.

[Documentation](docs/README.md) · [Installation](docs/installation.md) · [Operation](docs/operations.md) · [Changelog](CHANGELOG.md)

## Why MS Quarantine for Splunk SOAR?

- **Analyze the original message.** Keep the EML, bounded MIME attachments, hashes and selected metadata together.
- **Control the work in progress.** A persistent window limits unresolved messages across polls and restarts.
- **Keep import separate from disposition.** Import does not release or deny mail. Explicit actions check the selected source status and confirm the resulting Microsoft status.
- **Recover without blind retries.** Inspect blocked imports and reconcile uncertain operations before another write.
- **Use platform scheduling.** Configure native Ingest Settings or use Poll Now; no extra app-level polling checkbox is needed.

## Is it for you?

This project is for teams operating Microsoft Defender quarantine, Azure Automation and native Splunk SOAR, with optional native ES ingestion. It is a community-maintained connector, not a Splunk or Microsoft support offering.

Native SOAR execution is required. Automation Broker is unsupported. The connector has been piloted successfully on Splunk SOAR Cloud. Azure job access and Exchange permissions are separate prerequisites. See [installation and compatibility](docs/installation.md).

Intake examines the first 50 matching source candidates; it is not a complete paginated mailbox export. Analysis completion alone does not free an intake slot: Microsoft must report `Released` or `Denied`. See [limits and recovery](docs/operations.md).

## Get started

The current source version is **App 3.7.4**, paired with **Runbook 3.4.5**. The runbook is deployed separately; installing the SOAR app does not update Azure.

1. Follow [installation](docs/installation.md) to configure Azure identity, the runbook and the SOAR asset.
1. Select `release_requested` or `needs_review`, configure one ingesting asset per tenant, and start with a small active-message limit.
1. Run the [deployment checklist](docs/validation.md) with controlled test messages before enabling regular intake.
1. Connect an analysis workflow only after mapping and validating its assets, approver, notification routing and portal URL.

Building from source? See [development and CI](docs/ci.md). Release archives and source checkouts have different contents; the [publication guide](docs/publication.md) explains the packaging contract.

## Analysis workflows

This repository contains the SOAR app and its Azure Automation runbook, **not playbooks**. Configure your analysis and approval workflows separately in SOAR. The [ingestion guide](docs/ingestion.md) describes how a fully prepared message is handed to automation; importing a message does not itself establish successful analysis or disposition.

## Documentation

| Task | Guide |
|---|---|
| Install and configure | [Installation](docs/installation.md) |
| Operate, reconcile and recover | [Operations](docs/operations.md) |
| Understand native SOAR and ES intake | [Email ingestion](docs/ingestion.md) |
| Diagnose Azure and Exchange failures | [Troubleshooting](docs/troubleshooting.md) |
| Validate a deployment | [Deployment checklist](docs/validation.md) |
| Develop and package changes | [CI and build checks](docs/ci.md) |
| Review security and data handling | [Security guide](docs/security.md) |

The installed app includes a self-contained [HTML help page](readme.html).

## Contributing and support

Use the repository's issue tracker for bugs, questions and feature proposals. Include versions, expected behavior, a minimal reproduction and sanitized errors. Do not attach credentials or original quarantined mail.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code and [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

[Apache License 2.0](LICENSE). Third-party platforms and connectors retain their own licenses and service terms.

## Requirements

- Native Splunk SOAR execution with authenticated access to its local REST API. Automation Broker is not supported. The connector has been piloted successfully on Splunk SOAR Cloud.
- An Azure Automation Account with a system-assigned Managed Identity, a PowerShell runtime with ExchangeOnlineManagement, and the companion runbook.
- An App Registration for reading Azure Automation job status and output.
- Exchange/Defender permissions for the quarantine operations you intend to perform.
- For ES ingestion, a connected ES environment with the [required additional fields](docs/ingestion.md#enterprise-security-setup).

The app manifest declares SOAR 8.5.0 as its minimum and Python 3.9/3.13 runtimes. Use the Python runtime supported by your SOAR version; SOAR 8.7 and later use Python 3.13.

## Setup

### 1. Configure Azure Automation

1. Create an Automation Account and enable its system-assigned Managed Identity.
1. Add ExchangeOnlineManagement to the account's PowerShell runtime. Verify the runtime can connect to Exchange Online with Managed Identity.
1. Import and publish `ms-quarantine-for-splunk-soar-runbook-3.4.5.ps1`.
1. Create a webhook for the runbook and copy its URL when Azure displays it.
1. Set the `ExchangeOrganization` Automation Variable to your tenant domain, such as `contoso.onmicrosoft.com`, or provide that value in the SOAR asset. The asset value takes precedence.

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

This package has its own app UUID and package name. Existing assets for a differently identified app are not converted or inherited. Before changing a tenant's ingesting asset, pause the previous intake and follow the [migration and retention rules](docs/ingestion.md); do not run two ingesting assets for the same tenant.

Enter the connection fields in the order shown by the form:

1. Azure Automation webhook, subscription, resource group and account.
1. Azure API tenant ID, client ID and client secret.
1. Exchange organization, if not supplied by the Automation Variable.

Use the direct **HTTPS** webhook URL, including its token. HTTP URLs and webhook redirects are rejected. Azure TLS certificate verification is enforced; add a private CA to the platform trust store if required.

Choose the email selection mode, active-message limit and mail fields. The complete field and action reference is available in the app's installed **Documentation** page ([HTML help](readme.html)).

Run **test connectivity** to check the Azure connection and selected quarantine read path. It does not release mail or verify every downstream integration.

### 5. Configure ingestion and analysis

Use **one ingesting asset per tenant**. Keep its tenant, organization, selection mode and ingest target fixed while tracked work exists. Separate ingesting assets have independent state and can process the same message.

In **Ingest Settings**, configure the container label and polling schedule. Disable the schedule there to pause automatic imports. Use **Poll Now** for a manual import. There is no additional app-level enable checkbox.

For SOAR analysis, configure a playbook to consume the ready artifact after the mail is fully prepared. Set the required analyzer assets, analyst/approver, notification recipient, portal URLs and routing label before activating it. Use the ready artifact's original-email Vault ID, not an arbitrary attachment Vault ID. The app does not configure or activate playbooks for you.

For ES ingestion, configure the native ES target, security domain, threat analysis and automation options. See [Email import](docs/ingestion.md) for the ES field contract and artifact details.

## Recovery and support

Use the documented reconciliation and recovery actions before retrying uncertain operations. This is a community-supported app; report issues through this repository. See [operations](docs/operations.md) and [security](SECURITY.md).
