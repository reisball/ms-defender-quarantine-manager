# Security and data handling

[Documentation index](README.md).

## Separate the identities

The asset's App Registration reads Azure Automation job status/output. The Automation Account's Managed Identity connects to Exchange Online and needs the applicable quarantine permissions. A successful job lookup does not prove Exchange authorization. Do not use an Exchange password or client secret as a substitute for the Managed Identity.

Store credentials and token-bearing webhook URLs in the appropriate protected asset/automation settings, not in playbook examples, logs, issues or Git.

## Transport

Azure webhook requests require HTTPS and do not follow redirects. Use trusted certificate chains. Native SOAR transport follows the platform TLS policy and its fixed native loopback exception; no asset option disables validation for an arbitrary host. See [ingestion](ingestion.md) for the exact endpoint contract.

## Quarantined content

Original mail and attachments may contain malware or private data. Restrict access to SOAR containers, Vault, app state and Azure job output. Apply retention and backup policies to each location. Use synthetic messages in public test reports.

Parsing is bounded but not an antivirus boundary. Review [MIME limits](mime-limits.md) and your sandbox's submission/privacy policy before handing a message to an analyzer.

## Irreversible actions and recovery

Import is separate from Release/Deny. Disposition requires the selected source status and a confirming Microsoft postcondition. If a write's outcome is uncertain, reconcile the original operation before another write. Do not clear app state to force a retry.

Use one ingesting asset per tenant. Its ledger is scoped to that asset and retained history, not a global or permanent exactly-once guarantee. Follow [operations](operations.md) for blocked preparation and uncertain publication.

## Vulnerabilities

Follow [SECURITY.md](../SECURITY.md) for private reporting. Tests use synthetic data and reserved example domains. They do not provision assets or establish acceptance for a real environment.
