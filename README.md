# MS Quarantine for Splunk SOAR

Publisher: Kai Seidenschnur <br>
Connector Version: 3.7.4 <br>
Product Vendor: Microsoft <br>
Product Name: Exchange Online Quarantine <br>
Minimum Product Version: 8.5.0

Ingest Microsoft Defender quarantine emails through Azure Automation into native SOAR or ES workflows. Inspect, release, deny and reconcile quarantine messages.

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

Native SOAR execution is required. Automation Broker is unsupported. The connector has been piloted successfully on Splunk SOAR Cloud. This native pilot is not certification for every SOAR version or tenant. Azure job access and Exchange permissions are separate prerequisites. See [installation and compatibility](docs/installation.md).

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

- Native Splunk SOAR execution with authenticated access to its local REST API. Automation Broker is not supported. The connector has been piloted successfully on Splunk SOAR Cloud. This native pilot is not certification for every SOAR version or tenant.
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

### Configuration variables

This table lists the configuration variables required to operate MS Quarantine for Splunk SOAR. These variables are specified when configuring a Exchange Online Quarantine asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**webhook_url** | required | password | Connection: HTTPS webhook URL with token; no redirects |
**azure_subscription_id** | required | string | Connection: Azure subscription ID |
**azure_resource_group** | required | string | Connection: Azure resource group |
**azure_automation_account** | required | string | Connection: Azure Automation Account |
**azure_tenant_id** | required | string | Connection: Azure API tenant ID (not Exchange) |
**azure_client_id** | required | string | Connection: Azure API client ID (not Exchange) |
**azure_client_secret** | required | password | Connection: Azure API secret VALUE (not Exchange) |
**exchange_organization** | optional | string | Connection: Exchange domain (blank = variable) |
**quarantine_selection_mode** | optional | string | Email import: Selection: release_requested or needs_review |
**on_poll_max_containers** | optional | numeric | Email import: Maximum active messages (1-50; default 10) |
**worker_terminal_retention_days** | optional | numeric | Email import: Completed-entry retention (whole days, 1-365) |
**artifact_layout** | optional | string | Mail fields: Group selected fields: combined or separate |
**artifact_field_from** | optional | boolean | Mail fields: From |
**artifact_field_to** | optional | boolean | Mail fields: To |
**artifact_field_cc** | optional | boolean | Mail fields: Cc |
**artifact_field_reply_to** | optional | boolean | Mail fields: Reply-To |
**artifact_field_sender_address** | optional | boolean | Mail fields: Sender |
**artifact_field_recipient_address** | optional | boolean | Mail fields: original recipient |
**artifact_field_subject** | optional | boolean | Mail fields: Subject |
**artifact_field_email_date** | optional | boolean | Mail fields: email date |
**artifact_field_received_date** | optional | boolean | Mail fields: received date |
**artifact_field_message_id** | optional | boolean | Mail fields: Message-ID |
**artifact_field_quarantine_identity** | optional | boolean | Mail fields: quarantine identity |
**artifact_field_vault_id** | optional | boolean | Mail fields: Vault ID |
**poll_interval_seconds** | optional | numeric | Advanced: Job status check (whole seconds, 1-60; default 5) |
**poll_timeout_seconds** | optional | numeric | Advanced: Job timeout (whole seconds, 600-3600; default 600) |
**es_soar_base_url** | optional | string | Advanced: SOAR URL override (optional; SOAR and ES) |
**include_verbose_action_diagnostics** | optional | boolean | Advanced: Verbose diagnostics for successful actions |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validates webhook reachability and Azure AD token acquisition <br>
[on poll](#action-on-poll) - Email import: save complete quarantine emails and attachments in SOAR containers. Check Microsoft status and refill the active-message window <br>
[recover quarantine ingestion](#action-recover-quarantine-ingestion) - Import recovery: retry blocked preparation or confirm an uncertain publication <br>
[inspect release environment](#action-inspect-release-environment) - Read-only inspection of the deployed runbook, loaded Exchange cmdlet contract, and one exact quarantine identity; optional tenant RBAC inspection requires explicit opt-in <br>
[release quarantine message](#action-release-quarantine-message) - Release a quarantined message to all original recipients <br>
[deny quarantine release](#action-deny-quarantine-release) - Deny a user's request to release a quarantined message <br>
[reconcile quarantine operation](#action-reconcile-quarantine-operation) - Read an existing Azure job and optionally refresh the exact Exchange status without a disposition call <br>
[on es poll](#action-on-es-poll) - Email import: publish to ES with app-managed Microsoft status checks and active-message limits

## action: 'test connectivity'

Validates webhook reachability and Azure AD token acquisition

Type: **test** <br>
Read only: **True**

Fires the webhook with action=list and waits for job completion. Confirms that the webhook URL, Azure AD credentials, and job polling all work end-to-end.

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Email import: save complete quarantine emails and attachments in SOAR containers. Check Microsoft status and refill the active-message window

Type: **ingest** <br>
Read only: **True**

Import complete EML, attachments and metadata before automation. Keep at most the configured active-message count. Exact Microsoft Released/Denied observations release slots; first50 source-status candidate window, no paging.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Ignored. | numeric | |
**end_time** | optional | Ignored. | numeric | |
**container_count** | optional | Maximum containers for Poll Now (1-50). | numeric | |
**artifact_count** | optional | Ignored. | numeric | |
**container_id** | optional | Ignored. | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.summary.candidates | numeric | | |
action_result.summary.containers_created | numeric | | |
action_result.summary.messages_published | numeric | | |
action_result.summary.ingestion_enabled | boolean | | |
action_result.summary.active_messages | numeric | | |
action_result.summary.active_limit | numeric | | |
action_result.summary.ingest_target | string | | |
action_result.summary.requested_containers | numeric | | |
action_result.summary.terminal_observed | numeric | | |
action_result.summary.errors | numeric | | |
action_result.summary.candidate_window | numeric | | |
action_result.summary.results_may_be_truncated | boolean | | |

## action: 'recover quarantine ingestion'

Import recovery: retry blocked preparation or confirm an uncertain publication

Type: **generic** <br>
Read only: **False**

Operator recovery for one exact quarantine identity. retry_preparation retries only blocked, preparing, ready, or reserved ingestion. confirm_published acknowledges only uncertain publishing after external verification. The required operator note is persisted. Recovery never retires an identity or frees an active window slot; only Microsoft Released or Denied does.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**identity** | required | Quarantine message Identity. | string | |
**resolution** | required | Explicit ingestion recovery resolution. | string | |
**operator_note** | required | Operator recovery rationale and publication verification evidence. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.summary.identity | string | | |
action_result.summary.phase | string | | |
action_result.summary.slot_retained | boolean | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.identity | string | | |
action_result.parameter.resolution | string | | |
action_result.parameter.operator_note | string | | |

## action: 'inspect release environment'

Read-only inspection of the deployed runbook, loaded Exchange cmdlet contract, and one exact quarantine identity; optional tenant RBAC inspection requires explicit opt-in

Type: **investigate** <br>
Read only: **True**

Fires the Azure Automation webhook with action=diagnose. The runbook binds the exact Get-QuarantineMessage identity before any optional tenant-wide RBAC query. By default it reads only the identity and local runtime/cmdlet metadata. When include_rbac=true, it additionally reads management-role contracts, the Quarantine role and assignments, managed-identity app/object GUIDs, the matching Exchange service principal, and relevant role-group membership. Only GUID-confirmed matching group names cross into the result; unrelated assignment names and members remain private. Permission-query totals count every real failure while retained records are capped at 20 and 32 KiB of compact UTF-8 JSON. It never returns an access token or xms_mirid resource path and never invokes Release-QuarantineMessage.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**identity** | required | Exact quarantine Identity in GUID1\\GUID2 form. The diagnose action reads this identity but never releases or denies it. | string | |
**include_rbac** | optional | Explicitly opt in to tenant-wide read-only RBAC and role-group diagnostics after the exact quarantine identity has been bound. Defaults to false. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.identity | string | | |
action_result.parameter.include_rbac | boolean | | |
action_result.data.\*.action | string | | |
action_result.data.\*.identity | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.inspected_at_utc | string | | |
action_result.data.\*.result_count | numeric | | |
action_result.data.\*.observed_identity | string | | |
action_result.data.\*.observed_release_status | string | | |
action_result.data.\*.inspection_error | string | | |
action_result.data.\*.handling | string | | |
action_result.data.\*.error_code | string | | |
action_result.data.\*.runbook_version | string | | |
action_result.data.\*.runbook_source_revision | string | | |
action_result.data.\*.runbook_build_id | string | | |
action_result.data.\*.powershell_version | string | | |
action_result.data.\*.powershell_edition | string | | |
action_result.data.\*.powershell_platform | string | | |
action_result.data.\*.powershell_os | string | | |
action_result.data.\*.exchange_auth_method | string | | |
action_result.data.\*.exchange_online_management_version | string | | |
action_result.data.\*.exchange_online_management_path | string | | |
action_result.data.\*.cmdlet_name | string | | |
action_result.data.\*.cmdlet_command_type | string | | |
action_result.data.\*.cmdlet_module_name | string | | |
action_result.data.\*.cmdlet_module_version | string | | |
action_result.data.\*.cmdlet_default_parameter_set | string | | |
action_result.data.\*.cmdlet_parameter_sets | string | | |
action_result.data.\*.cmdlet_metadata_error | string | | |
action_result.data.\*.exchange_auth_method_source | string | | |
action_result.data.\*.exchange_organization | string | | |
action_result.data.\*.exchange_organization_source | string | | |
action_result.data.\*.exchange_connection_metadata | string | | |
action_result.data.\*.exchange_connection_metadata_error | string | | |
action_result.data.\*.cmdlet_contract_id | string | | |
action_result.data.\*.cmdlet_expected_argument_names | string | | |
action_result.data.\*.cmdlet_parameter_names | string | | |
action_result.data.\*.permission_queries_read_only | boolean | | |
action_result.data.\*.include_rbac | boolean | | |
action_result.data.\*.rbac_included | boolean | | |
action_result.data.\*.rbac_diagnostics_status | string | | |
action_result.data.\*.rbac_diagnostics_reason | string | | |
action_result.data.\*.rbac_empty_contracts.\* | string | | |
action_result.data.\*.rbac_required_cmdlets.\* | string | | |
action_result.data.\*.rbac_available_cmdlets.\* | string | | |
action_result.data.\*.missing_cmdlets.\* | string | | |
action_result.data.\*.missing_cmdlet_count | numeric | | |
action_result.data.\*.read_roles | string | | |
action_result.data.\*.export_roles | string | | |
action_result.data.\*.release_to_all_roles | string | | |
action_result.data.\*.release_deny_roles | string | | |
action_result.data.\*.quarantine_role_present | boolean | | |
action_result.data.\*.quarantine_role_groups | string | | |
action_result.data.\*.matched_quarantine_role_groups | string | | |
action_result.data.\*.managed_identity_claims_status | string | | |
action_result.data.\*.managed_identity_app_id | string | | |
action_result.data.\*.managed_identity_object_id | string | | |
action_result.data.\*.service_principal_registered | boolean | | |
action_result.data.\*.registered_service_principal_identity | string | | |
action_result.data.\*.registered_service_principal_app_id | string | | |
action_result.data.\*.registered_service_principal_object_id | string | | |
action_result.data.\*.role_group_membership_evaluated | boolean | | |
action_result.data.\*.quarantine_group_membership_confirmed | boolean | | |
action_result.data.\*.quarantine_administrator_membership_confirmed | boolean | | |
action_result.data.\*.role_assignment_matches_identity | boolean | | |
action_result.data.\*.quarantine_role_group_total_count | numeric | | |
action_result.data.\*.quarantine_role_group_inspected_count | numeric | | |
action_result.data.\*.quarantine_role_group_inspection_truncated | boolean | | |
action_result.data.\*.permission_query_error_count | numeric | | |
action_result.data.\*.permission_query_error_retained_count | numeric | | |
action_result.data.\*.permission_query_error_dropped_count | numeric | | |
action_result.data.\*.permission_query_errors_truncated | boolean | | |
action_result.data.\*.permission_query_errors.\*.query | string | | |
action_result.data.\*.permission_query_errors.\*.cmdlet | string | | |
action_result.data.\*.permission_query_errors.\*.error | string | | |
action_result.data.\*.permission_query_errors.\*.exception_type | string | | |
action_result.summary.status | string | | |
action_result.summary.handling | string | | |
action_result.summary.runbook_version | string | | |
action_result.summary.runbook_build_id | string | | |
action_result.summary.rbac_diagnostics_status | string | | |
action_result.summary.rbac_diagnostics_reason | string | | |
action_result.summary.missing_cmdlets.\* | string | | |
action_result.summary.missing_cmdlet_count | numeric | | |
action_result.summary.quarantine_role_present | boolean | | |
action_result.summary.service_principal_registered | boolean | | |
action_result.summary.role_assignment_matches_identity | boolean | | |
action_result.summary.quarantine_role_present_evaluation | string | | |
action_result.summary.service_principal_registered_evaluation | string | | |
action_result.summary.role_assignment_matches_identity_evaluation | string | | |
action_result.summary.quarantine_role_group_total_count | numeric | | |
action_result.summary.quarantine_role_group_inspected_count | numeric | | |
action_result.summary.quarantine_role_group_inspection_truncated | boolean | | |
action_result.summary.permission_query_error_count | numeric | | |
action_result.summary.permission_query_error_retained_count | numeric | | |
action_result.summary.permission_query_error_dropped_count | numeric | | |
action_result.summary.permission_query_errors_truncated | boolean | | |
action_result.summary.observed_release_status | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'release quarantine message'

Release a quarantined message to all original recipients

Type: **correct** <br>
Read only: **False**

Fires the Azure Automation webhook with action=release. The runbook confirms the exact Identity matches the asset-selected source status (Requested by default, NotReleased for needs_review) and then invokes Release-QuarantineMessage -Identity <id> -ReleaseToAll -Confirm:$false -ErrorAction Stop exactly once, with no synthetic binder or capability gate and no automatic retry. Native cmdlet/binder errors, the exact-identity postcondition and the effective Exchange sign-in (always the Automation Account Managed Identity, plus organization and its source; never secrets) are reported separately; cleanup never overrides them. Before every write a read-only config_check proves that the protocol minimum Runbook 3.4.2+ applies the Managed Identity-only connection and the configured organization. It then performs a bounded postcondition window (default seven exact reads at ten-second intervals). Only Released is success. A deterministic rejection with an unchanged source state is confirmed_failed; ambiguous outcomes remain outcome_unknown and block blind retry. Successful diagnostics are compact unless enabled on the asset. IRREVERSIBLE. Reference: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/release-quarantinemessage Needs review uses the quarantine_selection_v1 pairing check and requires protocol minimum Runbook 3.4.3 or newer. The recommended pair is App 3.7.4 / Runbook 3.4.5 for bounded/redacted disposition diagnostics. Deny of a message without a release request is tenant-unverified; only confirmed Denied is success.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**identity** | required | Quarantine message Identity in the exact format GUID1\\GUID2 (e.g. c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7). Use cef.quarantineIdentity from the ingested SOAR ready artifact or quarantine_identity from the ES finding. The format is validated before the webhook fires - malformed values fail immediately without starting a runbook job. | string | |
**operation_id** | optional | Stable idempotency key for this logical release. Reusing the same value suppresses another webhook while its operation record is retained. Terminal records may be evicted at the 50-record registry limit; this is not permanent idempotency protection. If omitted, the connector derives a stable key from the SOAR container, action, and identity. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.parameter.operation_id | string | | deny-case-2026-00042 |
action_result.data.\*.status | string | | released already_released |
action_result.data.\*.message | string | | Release request approval confirmed by Exchange quarantine status. |
action_result.data.\*.identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.data.\*.action | string | | release |
action_result.data.\*.runbook_version | string | | 3.4.2 |
action_result.data.\*.operation_id | string | | deny-case-2026-00042 |
action_result.data.\*.state | string | | pending outcome_unknown confirmed_success confirmed_failed |
action_result.data.\*.handling | string | | reconcile_before_retry manual_review |
action_result.data.\*.azure_job_id | string | | aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee |
action_result.data.\*.last_job_status | string | | Running unknown |
action_result.data.\*.verification_method | string | | Get-QuarantineMessage |
action_result.data.\*.expected_release_status | string | | Requested Released |
action_result.data.\*.observed_release_status | string | | Requested Released |
action_result.data.\*.verification_attempts | numeric | | 1 3 7 |
action_result.data.\*.observed_identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.data.\*.observed_release_status_history | string | | Requested -> Approved -> PreparingToRelease -> Released |
action_result.data.\*.last_verification_error | string | | Get-QuarantineMessage returned a different identity. |
action_result.data.\*.exchange_online_management_version | string | | 3.5.0 |
action_result.data.\*.cmdlet_warning | string | | |
action_result.data.\*.cmdlet_information | string | | |
action_result.data.\*.cmdlet_verbose | string | | |
action_result.data.\*.cmdlet_error | string | | |
action_result.data.\*.runbook_source_revision | string | | |
action_result.data.\*.runbook_build_id | string | | |
action_result.data.\*.powershell_version | string | | |
action_result.data.\*.cmdlet_contract_id | string | | |
action_result.data.\*.cmdlet_invocation_attempted | boolean | | |
action_result.data.\*.cmdlet_invocation_form | string | | |
action_result.data.\*.cmdlet_error_position | string | | |
action_result.data.\*.exchange_auth_method | string | | |
action_result.data.\*.exchange_auth_method_source | string | | |
action_result.data.\*.exchange_organization | string | | |
action_result.data.\*.exchange_organization_source | string | | |
action_result.data.\*.exchange_disconnect_status | string | | |
action_result.data.\*.exchange_disconnect_error | string | | |
action_result.data.\*.cmdlet_executed | boolean | | |
action_result.data.\*.idempotent | boolean | | |
action_result.data.\*.cmdlet_duration_ms | numeric | | |
action_result.data.\*.cmdlet_fully_qualified_error_id | string | | |
action_result.data.\*.cmdlet_error_category | string | | |
action_result.data.\*.cmdlet_http_status_code | string | | |
action_result.data.\*.cmdlet_request_id | string | | |
action_result.data.\*.cmdlet_correlation_id | string | | |
action_result.data.\*.diagnostic_bundle | string | | |
action_result.summary.operation_id | string | | deny-case-2026-00042 |
action_result.summary.action | string | | deny |
action_result.summary.state | string | | pending outcome_unknown confirmed_success confirmed_failed |
action_result.summary.status | string | | outcome_unknown |
action_result.summary.handling | string | | reconcile_before_retry manual_review |
action_result.summary.identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.summary.azure_job_id | string | | aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee |
action_result.summary.last_job_status | string | | Running unknown |
action_result.summary.runbook_version | string | | 3.4.2 |
action_result.summary.verification_method | string | | Get-QuarantineMessage |
action_result.summary.expected_release_status | string | | Requested Released |
action_result.summary.observed_release_status | string | | Requested Released |
action_result.summary.verification_attempts | numeric | | 1 3 |
action_result.status | string | | success failed |
action_result.message | string | | Message released successfully |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'deny quarantine release'

Deny a user's request to release a quarantined message

Type: **correct** <br>
Read only: **False**

Fires the Azure Automation webhook with action=deny. The runbook confirms the exact Identity matches the asset-selected source status (Requested by default, NotReleased for needs_review) and then invokes Release-QuarantineMessage -Identities @(<id>) -ActionType Deny -Confirm:$false -ErrorAction Stop exactly once, with no synthetic binder or capability gate and no automatic retry. Native cmdlet/binder errors, the exact-identity postcondition and the effective Exchange sign-in (always the Automation Account Managed Identity, plus organization and its source; never secrets) are reported separately; cleanup never overrides them. Before every write a read-only config_check proves that the protocol minimum Runbook 3.4.2+ applies the Managed Identity-only connection and the configured organization. It then performs a bounded postcondition window (default seven exact reads at ten-second intervals). Only Denied is success. A deterministic rejection with an unchanged source state is confirmed_failed; ambiguous outcomes remain outcome_unknown and block blind retry. Successful diagnostics are compact unless enabled on the asset. Reference: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/release-quarantinemessage#-actiontype Needs review uses the quarantine_selection_v1 pairing check and requires protocol minimum Runbook 3.4.3 or newer. The recommended pair is App 3.7.4 / Runbook 3.4.5 for bounded/redacted disposition diagnostics. Deny of a message without a release request is tenant-unverified; only confirmed Denied is success.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**identity** | required | Quarantine message Identity in the exact format GUID1\\GUID2 (e.g. c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7). Use cef.quarantineIdentity from the ingested SOAR ready artifact or quarantine_identity from the ES finding. The format is validated before the webhook fires - malformed values fail immediately without starting a runbook job. | string | |
**operation_id** | optional | Stable idempotency key for this logical deny. Reusing the same value suppresses another webhook while its operation record is retained. Terminal records may be evicted at the 50-record registry limit; this is not permanent idempotency protection. If omitted, the connector derives a stable key from the SOAR container, action, and identity. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.parameter.operation_id | string | | deny-case-2026-00042 |
action_result.data.\*.status | string | | denied already_denied |
action_result.data.\*.message | string | | Release request denied. Message remains in quarantine. |
action_result.data.\*.identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.data.\*.action | string | | deny |
action_result.data.\*.runbook_version | string | | 3.4.2 |
action_result.data.\*.operation_id | string | | deny-case-2026-00042 |
action_result.data.\*.state | string | | pending outcome_unknown confirmed_success confirmed_failed |
action_result.data.\*.handling | string | | reconcile_before_retry |
action_result.data.\*.azure_job_id | string | | aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee |
action_result.data.\*.last_job_status | string | | Running unknown |
action_result.data.\*.verification_method | string | | Get-QuarantineMessage |
action_result.data.\*.expected_release_status | string | | Denied |
action_result.data.\*.observed_release_status | string | | Requested Denied |
action_result.data.\*.verification_attempts | numeric | | 1 3 |
action_result.data.\*.observed_identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.data.\*.observed_release_status_history | string | | Requested -> Denied |
action_result.data.\*.last_verification_error | string | | Get-QuarantineMessage returned a different identity. |
action_result.data.\*.exchange_online_management_version | string | | 3.5.0 |
action_result.data.\*.cmdlet_warning | string | | |
action_result.data.\*.cmdlet_information | string | | |
action_result.data.\*.cmdlet_verbose | string | | |
action_result.data.\*.cmdlet_error | string | | |
action_result.data.\*.runbook_source_revision | string | | |
action_result.data.\*.runbook_build_id | string | | |
action_result.data.\*.powershell_version | string | | |
action_result.data.\*.cmdlet_contract_id | string | | |
action_result.data.\*.cmdlet_invocation_attempted | boolean | | |
action_result.data.\*.cmdlet_invocation_form | string | | |
action_result.data.\*.cmdlet_error_position | string | | |
action_result.data.\*.exchange_auth_method | string | | |
action_result.data.\*.exchange_auth_method_source | string | | |
action_result.data.\*.exchange_organization | string | | |
action_result.data.\*.exchange_organization_source | string | | |
action_result.data.\*.exchange_disconnect_status | string | | |
action_result.data.\*.exchange_disconnect_error | string | | |
action_result.data.\*.cmdlet_executed | boolean | | |
action_result.data.\*.idempotent | boolean | | |
action_result.data.\*.cmdlet_duration_ms | numeric | | |
action_result.data.\*.cmdlet_fully_qualified_error_id | string | | |
action_result.data.\*.cmdlet_error_category | string | | |
action_result.data.\*.cmdlet_http_status_code | string | | |
action_result.data.\*.cmdlet_request_id | string | | |
action_result.data.\*.cmdlet_correlation_id | string | | |
action_result.data.\*.diagnostic_bundle | string | | |
action_result.summary.operation_id | string | | deny-case-2026-00042 |
action_result.summary.action | string | | deny |
action_result.summary.state | string | | pending outcome_unknown confirmed_success confirmed_failed |
action_result.summary.status | string | | outcome_unknown |
action_result.summary.handling | string | | reconcile_before_retry |
action_result.summary.identity | string | | c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7 |
action_result.summary.azure_job_id | string | | aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee |
action_result.summary.last_job_status | string | | Running unknown |
action_result.summary.runbook_version | string | | 3.4.2 |
action_result.summary.verification_method | string | | Get-QuarantineMessage |
action_result.summary.expected_release_status | string | | Denied |
action_result.summary.observed_release_status | string | | Requested Denied |
action_result.summary.verification_attempts | numeric | | 1 3 |
action_result.status | string | | success failed |
action_result.message | string | | Release request denied |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'reconcile quarantine operation'

Read an existing Azure job and optionally refresh the exact Exchange status without a disposition call

Type: **investigate** <br>
Read only: **True**

READ-ONLY. By default, queries only the supplied Azure Automation job/output and never invokes the webhook. If refresh_exchange_status is explicitly enabled for a completed outcome_unknown job, it starts the paired runbook's action=reconcile path, which performs exactly one Get-QuarantineMessage read and cannot invoke Release-QuarantineMessage. The durable operation is updated only after action, identity, version, and postcondition evidence validate.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**azure_job_id** | required | Existing Azure Automation job UUID recorded by the original release or deny action. | string | |
**expected_action** | required | Irreversible action the existing job was expected to execute. | string | |
**expected_identity** | required | Exact quarantine identity expected in the validated runbook result. | string | |
**operation_id** | optional | Optional stable operation ID from the original action. When omitted, the connector resolves it from the Azure job ID or creates a durable read-only observation. | string | |
**refresh_exchange_status** | optional | Explicitly start one read-only runbook reconciliation to obtain a fresh exact Exchange ReleaseStatus. No release or deny cmdlet is permitted. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.azure_job_id | string | | |
action_result.parameter.expected_action | string | | |
action_result.parameter.expected_identity | string | | |
action_result.parameter.operation_id | string | | |
action_result.parameter.refresh_exchange_status | boolean | | |
action_result.data.\*.operation_id | string | | |
action_result.data.\*.action | string | | |
action_result.data.\*.identity | string | | |
action_result.data.\*.state | string | | pending outcome_unknown confirmed_success confirmed_failed |
action_result.data.\*.status | string | | pending outcome_unknown released denied confirmed_failed |
action_result.data.\*.handling | string | | wait manual_review no_retry_needed retry_requires_new_operation |
action_result.data.\*.azure_job_id | string | | |
action_result.data.\*.last_job_status | string | | |
action_result.data.\*.runbook_version | string | | |
action_result.data.\*.verification_method | string | | |
action_result.data.\*.expected_release_status | string | | |
action_result.data.\*.observed_release_status | string | | |
action_result.data.\*.verification_attempts | numeric | | |
action_result.data.\*.observed_identity | string | | |
action_result.data.\*.observed_release_status_history | string | | |
action_result.data.\*.last_verification_error | string | | |
action_result.data.\*.exchange_online_management_version | string | | |
action_result.data.\*.cmdlet_warning | string | | |
action_result.data.\*.cmdlet_information | string | | |
action_result.data.\*.cmdlet_verbose | string | | |
action_result.data.\*.cmdlet_error | string | | |
action_result.data.\*.runbook_source_revision | string | | |
action_result.data.\*.runbook_build_id | string | | |
action_result.data.\*.powershell_version | string | | |
action_result.data.\*.cmdlet_contract_id | string | | |
action_result.data.\*.cmdlet_invocation_attempted | boolean | | |
action_result.data.\*.cmdlet_invocation_form | string | | |
action_result.data.\*.cmdlet_error_position | string | | |
action_result.data.\*.exchange_auth_method | string | | |
action_result.data.\*.exchange_auth_method_source | string | | |
action_result.data.\*.exchange_organization | string | | |
action_result.data.\*.exchange_organization_source | string | | |
action_result.data.\*.exchange_disconnect_status | string | | |
action_result.data.\*.exchange_disconnect_error | string | | |
action_result.data.\*.cmdlet_executed | boolean | | |
action_result.data.\*.idempotent | boolean | | |
action_result.data.\*.cmdlet_duration_ms | numeric | | |
action_result.data.\*.cmdlet_fully_qualified_error_id | string | | |
action_result.data.\*.cmdlet_error_category | string | | |
action_result.data.\*.cmdlet_http_status_code | string | | |
action_result.data.\*.cmdlet_request_id | string | | |
action_result.data.\*.cmdlet_correlation_id | string | | |
action_result.data.\*.diagnostic_bundle | string | | |
action_result.summary.operation_id | string | | |
action_result.summary.action | string | | |
action_result.summary.identity | string | | |
action_result.summary.state | string | | |
action_result.summary.status | string | | |
action_result.summary.handling | string | | |
action_result.summary.azure_job_id | string | | |
action_result.summary.last_job_status | string | | |
action_result.summary.runbook_version | string | | |
action_result.summary.verification_method | string | | |
action_result.summary.expected_release_status | string | | |
action_result.summary.observed_release_status | string | | |
action_result.summary.verification_attempts | numeric | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'on es poll'

Email import: publish to ES with app-managed Microsoft status checks and active-message limits

Type: **ingest** <br>
Read only: **True**

Uses the same persistent active-message window and unchanged Runbook as native SOAR intake. ES owns threat analysis and automation launch settings.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Ignored. | numeric | |
**end_time** | optional | Ignored. | numeric | |
**container_count** | optional | Maximum containers for Poll Now (1-50). | numeric | |
**artifact_count** | optional | Ignored. | numeric | |
**container_id** | optional | Ignored. | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.summary.candidates | numeric | | |
action_result.summary.containers_created | numeric | | |
action_result.summary.messages_published | numeric | | |
action_result.summary.ingestion_enabled | boolean | | |
action_result.summary.active_messages | numeric | | |
action_result.summary.active_limit | numeric | | |
action_result.summary.ingest_target | string | | |
action_result.summary.requested_containers | numeric | | |
action_result.summary.terminal_observed | numeric | | |
action_result.summary.errors | numeric | | |
action_result.summary.candidate_window | numeric | | |
action_result.summary.results_may_be_truncated | boolean | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.status | string | | |
action_result.message | string | | |
action_result.parameter.start_time | numeric | | |
action_result.parameter.end_time | numeric | | |
action_result.parameter.container_count | numeric | | |
action_result.parameter.artifact_count | numeric | | |
action_result.parameter.container_id | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Kai Seidenschnur.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
