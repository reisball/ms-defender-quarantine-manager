# Security and data handling

[Back to README](../README.md)

## Identities and credentials

The asset's App Registration is a [read-only Azure job reader](installation.md#3-configure-azure-job-access). The separate bearer webhook starts jobs; keep it separate from the App Registration's permissions. The Automation Account's Managed Identity connects to Exchange and needs the quarantine permissions. A successful job read does not prove Exchange authorization. Exchange sign-in is Managed Identity only; passwords and client secrets are not accepted for Exchange.

Keep credentials and the token-bearing webhook URL in the protected asset and Automation settings. Never put them in playbooks, logs, issues or Git.

## Transport

Azure webhook calls require HTTPS, verify certificates and do not follow redirects. No asset option disables certificate validation. Native SOAR calls follow the platform TLS policy.

## Quarantined content

Original mail and attachments can contain malware or personal data. Restrict access to SOAR containers, the Vault, app state and Azure job output, and apply retention and backup policies to each. The MIME parser is bounded ([limits](ingestion.md#limits)) but is not an antivirus boundary. Check your sandbox's submission and privacy policy before sending mail to an analyzer.

Azure job output can include original EML and message metadata. Output-read permission can expose data from other runbooks in the same Automation Account, and principals with inherited access may have it even if they were not assigned directly on the account. Prefer a dedicated account and review effective access from the account, resource group and subscription. A dedicated account does not itself remove inherited grants. See [#36](https://github.com/reisball/ms-quarantine-for-splunk-soar/issues/36) for reducing readable job-output content.

## Disposition safety

Release and Deny run only for `Requested` messages and succeed only when the matching status is confirmed. Writes are never retried automatically. Follow [uncertain outcomes](operations.md#timeouts-and-uncertain-outcomes) before starting another action, and never clear app state to force processing.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
