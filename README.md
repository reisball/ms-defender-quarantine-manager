# MS Defender Quarantine Manager

A community connector for Splunk SOAR to investigate Microsoft Defender for Office 365 quarantined email and release or deny requested messages.

The app imports quarantined messages that have a recipient release request (Microsoft status `Requested`) through an Azure Automation runbook. Each message becomes one SOAR event with the original EML and attachments in the Vault. Playbooks or analysts can then release or deny the message. Native Splunk Enterprise Security (ES) ingestion is optional.

This is a community-maintained connector, not a Splunk or Microsoft support offering.

## Components

| Component | Where it runs |
|---|---|
| SOAR app (`ms-defender-quarantine-manager-<version>.tgz`) | Splunk SOAR (native execution, 8.5.0 or later) |
| Runbook (`ms-defender-quarantine-manager-runbook-<version>.ps1`) | Azure Automation, deployed separately; installing the app does not update Azure |
| [Native SAA example playbook](examples/MS_Quarantine_SAA_Example/README.md) (optional) | Splunk SOAR, imported separately |

App and runbook share one version. Deploy them as a matching pair; see the [compatibility matrix](docs/compatibility.md).

## Exchange Online PowerShell cmdlets

The Azure Automation runbook uses the `ExchangeOnlineManagement` module (not
Microsoft Graph) for the quarantine operations:

| Operation | Cmdlet and key arguments |
|---|---|
| List messages with a release request | `Get-QuarantineMessage -ReleaseStatus Requested` |
| Export the original EML | `Export-QuarantineMessage -Identity <identity>` |
| Release to all original recipients | `Release-QuarantineMessage -Identity <identity> -ReleaseToAll` |
| Deny the release request | `Release-QuarantineMessage -Identity <identity> -ReleaseToAll -ActionType Deny` |

The runbook reads the status by identity with `Get-QuarantineMessage` before and
after a release or denial. See [Installation](docs/installation.md) for
permissions and [Operation](docs/operations.md) for how outcomes are confirmed.

## Quick start

1. [Install](docs/installation.md): set up the Azure Automation Account and Exchange permissions, publish the runbook, then install the app and create one asset per tenant.
2. Start with a small active-message limit and run **test connectivity**.
3. Work through the [deployment checklist](docs/validation.md) with controlled test messages.
4. Optionally connect an analysis playbook such as the [SAA example](examples/MS_Quarantine_SAA_Example/README.md).

## Documentation

| Topic | Guide |
|---|---|
| Prerequisites, permissions and asset setup | [Installation](docs/installation.md) |
| App/runbook pairing and upgrade order | [Compatibility](docs/compatibility.md) |
| Intake, playbook input data, ES, limits and retries | [Email import](docs/ingestion.md) |
| Release, Deny and timeouts | [Operation](docs/operations.md) |
| Errors and diagnostics | [Troubleshooting](docs/troubleshooting.md) |
| Acceptance testing | [Deployment checklist](docs/validation.md) |
| Identities, TLS and quarantined content | [Security](docs/security.md) |
| Building, testing and releasing | [Development and release](docs/development.md) |

The installed app also includes a quick start and troubleshooting guidance on its **Documentation** page ([HTML help](app/readme.html)). Release notes are published in [GitHub Releases](https://github.com/reisball/ms-defender-quarantine-manager/releases).

## Support and contributing

Use the issue tracker for bugs and questions. Include app/runbook and SOAR versions, sanitized errors and known Azure job IDs. Never attach credentials, webhook URLs or original quarantined mail. See [CONTRIBUTING.md](CONTRIBUTING.md) and, for vulnerabilities, [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Third-party platforms and connectors retain their own licenses and service terms.
