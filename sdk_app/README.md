# MS Defender Quarantine Manager

Imports Microsoft Defender for Office 365 quarantine messages with a release request into Splunk SOAR. The original EML and attachments are saved in the Vault before investigation automation starts. An analyst or playbook can then inspect the message, release it to all original recipients, or deny the request.

## Setup

This SDK build targets Splunk SOAR 8.7 or later with Python 3.13. Deploy the companion Azure Automation runbook separately, then configure its webhook and Azure job-reader credentials in a new SOAR asset. Set a SOAR container label and run **test connectivity** before enabling polling. Intake requires native SOAR session authentication; Automation Broker is unsupported.

For Enterprise Security, configure native ES ingestion on the SOAR asset. This app supports the SOAR-proxied path that links findings to a SOAR container. Direct ES ingestion is not supported: it cannot link an existing SOAR container, which is needed for Vault evidence and downstream actions.

## Operation

- **Poll Now** or scheduled polling considers the first 50 Requested quarantine messages. Failed imports are not automatically replayed. Inspect any existing SOAR event, Vault files or ES finding before using Poll Now to retry.
- **Inspect release environment** is read-only; optional tenant-wide RBAC diagnostics require opt-in.
- **Release quarantine message** and **deny quarantine release** use the exact `container:data.quarantine_identity`. A timeout does not cancel an Azure job. Inspect pending or unknown outcomes before retrying.

The runbook lists with `Get-QuarantineMessage -ReleaseStatus Requested`, exports with `Export-QuarantineMessage` and writes dispositions using `Release-QuarantineMessage -ReleaseToAll` (add `-ActionType Deny` for denial).

See the [project documentation](https://github.com/reisball/ms-defender-quarantine-manager#documentation) for the Azure runbook, Exchange permissions and troubleshooting. Do not include webhook URLs, credentials or quarantined email in support reports.
