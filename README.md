# MS Quarantine for Splunk SOAR

Bring Microsoft Defender quarantine mail into Splunk SOAR for investigation, then release or deny it.

The app imports quarantined messages that have a recipient release request (Microsoft status `Requested`) through an Azure Automation runbook. Each message becomes one SOAR event with the original EML and attachments in the Vault. Playbooks or analysts can then release or deny the message. Native Splunk Enterprise Security (ES) ingestion is optional.

This is a community-maintained connector, not a Splunk or Microsoft support offering.

## Components

| Component | Where it runs |
|---|---|
| SOAR app (`ms-quarantine-for-splunk-soar-<version>.tgz`) | Splunk SOAR (native execution, 8.5.0 or later) |
| Runbook (`ms-quarantine-for-splunk-soar-runbook-<version>.ps1`) | Azure Automation, deployed separately; installing the app does not update Azure |
| [Native SAA example playbook](examples/MS_Quarantine_SAA_Example/README.md) (optional) | Splunk SOAR, imported separately |

App and runbook share one version. Deploy them as a matching pair; see the [compatibility matrix](docs/compatibility.md).

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

The installed app also includes a quick start and troubleshooting guidance on its **Documentation** page ([HTML help](app/readme.html)). Release notes are published in [GitHub Releases](https://github.com/reisball/ms-quarantine-for-splunk-soar/releases).

## Support and contributing

Use the issue tracker for bugs and questions. Include app/runbook and SOAR versions, sanitized errors and known Azure job IDs. Never attach credentials, webhook URLs or original quarantined mail. See [CONTRIBUTING.md](CONTRIBUTING.md) and, for vulnerabilities, [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Third-party platforms and connectors retain their own licenses and service terms.
