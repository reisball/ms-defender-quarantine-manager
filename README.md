# MS Quarantine for Splunk SOAR

**Bring Microsoft Defender quarantine mail into Splunk SOAR for investigation and controlled disposition.**

MS Quarantine for Splunk SOAR imports quarantined email through an Azure Automation runbook, preserves the original EML and attachments in the SOAR Vault, and prepares one container per message.

[Documentation](docs/README.md) · [Installation](docs/installation.md) · [Operation](docs/operations.md) · [Releases](https://github.com/reisball/ms-quarantine-for-splunk-soar/releases)

## Why MS Quarantine for Splunk SOAR?

Automate your Microsoft Defender quarantine workflow in Splunk SOAR—from collecting quarantined messages to investigation, approval and release or denial. Bring email evidence and response actions together so your team can focus on decisions instead of manual handoffs.

Use Splunk SOAR for additional analysis—for example, with Splunk Attack Analyzer or Automated Threat Analysis (a feature of Splunk Enterprise Security). A workflow could analyze suspicious URLs and attachments, enrich sender domains with threat intelligence, and present the results to an analyst before a release or denial decision.

## Is it for you?

This project is for teams operating Microsoft Defender quarantine, Azure Automation and native Splunk SOAR, with optional native ES ingestion.

Azure job access and Exchange permissions are separate prerequisites. See [installation and configuration](docs/installation.md).

## Get started

The runbook is deployed separately; installing the SOAR app does not update Azure.

1. Follow [installation](docs/installation.md) to configure Azure identity, the runbook and the SOAR asset.
2. Select `release_requested` or `needs_review`, configure one ingesting asset per tenant, and start with a small active-message limit.
3. Run the [deployment checklist](docs/validation.md) with controlled test messages before enabling regular intake.
4. Connect an analysis workflow only after mapping and validating its assets, approver, notification routing and portal URL.

Building from source? See [development and CI](docs/ci.md). Release archives and source checkouts have different contents; the [publication guide](docs/publication.md) explains the packaging contract.

## Analysis workflows

Import quarantined emails with status `Requested` (the app's `release_requested` mode) or `NotReleased` (`needs_review` mode), then hand them over to Splunk SOAR automation.

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

This is a community-maintained connector, not a Splunk or Microsoft support offering.

Use the repository's issue tracker for bugs, questions and feature proposals. Include versions, expected behavior, a minimal reproduction and sanitized errors. Do not attach credentials or original quarantined mail.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code and [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

[Apache License 2.0](LICENSE). Third-party platforms and connectors retain their own licenses and service terms.
