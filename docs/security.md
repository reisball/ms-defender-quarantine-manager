# Security and data handling

[Back to README](../README.md)

## Identities and credentials

The asset's App Registration is a [read-only Azure job reader](installation.md#3-configure-azure-job-access). The separate bearer webhook starts jobs; keep it separate from the App Registration's permissions. The Automation Account's Managed Identity connects to Exchange and needs the quarantine permissions. A successful job read does not prove Exchange authorization. Exchange sign-in is Managed Identity only; passwords and client secrets are not accepted for Exchange.

Keep credentials and the token-bearing webhook URL in the protected asset and Automation settings. Never put them in playbooks, logs, issues or Git.

## Transport

Azure webhook calls require HTTPS, verify certificates and do not follow redirects. No asset option disables certificate validation. Native SOAR calls follow the platform TLS policy.

## Quarantined content

Original mail and attachments can contain malware or personal data. Restrict access to SOAR containers, the Vault, app state and Azure job output, and apply retention and backup policies to each. The MIME parser is bounded ([limits](ingestion.md#limits)) but is not an antivirus boundary. Check your sandbox's submission and privacy policy before sending mail to an analyzer.

List and export encrypt mail-bearing job records before writing them. SOAR creates a fresh RSA key pair per job; the webhook carries only the public key. The runbook wraps a new AES-256 key with RSA-OAEP-SHA-256 and uses AES-GCM for each record. Missing, altered, or reordered records are rejected; there is no plaintext fallback. The app verifies the original EML digest after reassembling a chunked export.

This protects against readers of stored job output, not operators who can change the runbook or compromise either endpoint. Azure still sees job timing, sizes/count of encrypted records, and request metadata (action, organization, and the quarantine identity for an export). Reconcile and disposition can still report identities, statuses and bounded errors. Existing plaintext output from older jobs is not retroactively protected.

Check effective Azure access at the account, resource-group and subscription scopes, including inherited and group assignments. A principal with job output or stream read access can read the records, and other runbooks in the same account may emit unprotected output. Prefer a dedicated account with the [scoped reader role](installation.md#3-configure-azure-job-access). Azure Automation documents up to 30 days of native job-log retention; forwarded diagnostic logs follow the destination's separate retention and access policy. See [Azure limits](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#automation-limits) and [diagnostic log forwarding](https://learn.microsoft.com/en-us/azure/automation/automation-manage-send-joblogs-log-analytics).

## Disposition safety

Release and Deny run only for `Requested` messages and succeed only when the matching status is confirmed. Writes are never retried automatically. Follow [uncertain outcomes](operations.md#timeouts-and-uncertain-outcomes) before starting another action, and never clear app state to force processing.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
