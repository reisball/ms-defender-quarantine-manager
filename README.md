# MS Quarantine for Splunk SOAR

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

Native SOAR execution is required. Automation Broker is unsupported; SOAR Cloud compatibility has not been verified. Azure job access and Exchange permissions are separate prerequisites. See [installation and compatibility](docs/installation.md).

Intake examines the first 50 matching source candidates; it is not a complete paginated mailbox export. Analysis completion alone does not free an intake slot: Microsoft must report `Released` or `Denied`. See [limits and recovery](docs/operations.md).

## Get started

App and runbook share the current source version **3.7.4**. The runbook is deployed separately; installing the SOAR app does not update Azure.

1. Follow [installation](docs/installation.md) to configure Azure identity, the runbook and the SOAR asset.
2. Select `release_requested` or `needs_review`, configure one ingesting asset per tenant, and start with a small active-message limit.
3. Run the [deployment checklist](docs/validation.md) with controlled test messages before enabling regular intake.
4. Connect an analysis workflow only after mapping and validating its assets, approver, notification routing and portal URL.

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

The installed app includes a self-contained [HTML help page](app/readme.html).

## Contributing and support

Use the repository's issue tracker for bugs, questions and feature proposals. Include versions, expected behavior, a minimal reproduction and sanitized errors. Do not attach credentials or original quarantined mail.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code and [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

[Apache License 2.0](LICENSE). Third-party platforms and connectors retain their own licenses and service terms.
