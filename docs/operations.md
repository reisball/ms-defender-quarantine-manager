# Operation

[Documentation index](README.md).

## How email import works

The app exports each message, prepares its container and Vault files, then publishes the completed message for analysis. Preparation does not trigger automation. A small identity/result record retains the outcome and native references; there is no background recovery workflow.

| Setting or behavior | Meaning |
|---|---|
| Intake | Import only Microsoft `Requested` messages; no source-mode selector |
| Active-message limit | Default 10, configurable 1–50; a total ceiling, not an increment per poll |
| Slot release | A confirmed Microsoft `Released` or `Denied` status frees a slot |
| Analysis completed or import failed | Does not free a slot while the Microsoft status remains unresolved |
| Discovery | Uses the first 50 matching source candidates; no pagination or chronological ordering guarantee |
| Poll Now count | Bounds attempts in that poll and cannot exceed the asset's active-message ceiling |

A missing or expired source message can retain a slot until investigated. An empty import does not prove the entire source backlog is empty. Obsolete source-mode settings are ignored; existing scope and published references are preserved. Older unconfirmed attempts are not automatically replayed after upgrade. See [intake compatibility](ingestion.md#configure-intake).

## Actions

| Action | Purpose |
|---|---|
| **test connectivity** | Check Azure job access and read Microsoft `Requested` messages |
| **on poll** | Import mail to the configured native target |
| **on es poll** | Import using native ES ingestion settings; requires an ES target |
| **inspect release environment** | Read one identity and Exchange runtime details; optionally collect RBAC diagnostics |
| **release quarantine message** | Request release to all recipients and confirm the resulting Microsoft status |
| **deny quarantine release** | Deny the release request and confirm the resulting Microsoft status |

Use `container:data.quarantine_identity` from the imported event for disposition actions. Release/Deny require Microsoft `Requested` or an already matching terminal status. The normal action submits one Azure job, waits for its output and returns a native SOAR ActionResult. No diagnostic action or extra configuration-check job is required first.

The runbook reads the exact identity, invokes the selected command once if needed, then checks for `Released` or `Denied`. After a successful command it allows up to seven status reads, ten seconds apart, for Exchange to reflect the change. A command error remains an error; a later status observation does not turn it into success.

### Waiting and uncertain outcomes

The default Azure job/output wait is **600 seconds**, with job status polling every **5 seconds**. `poll_timeout_seconds` accepts 600–3600 and `poll_interval_seconds` accepts 1–60, both whole seconds. These monitor individual jobs, not the ingestion schedule. Transient read failures are retried within the same deadline, honoring Retry-After where available. The writing webhook is never automatically retried.

A timeout means the result is unknown, not that Azure was cancelled. Inspect the reported job ID and output in Azure Automation and, if needed, use **inspect release environment** to read the current Microsoft status. Do not infer a permission or cmdlet failure from a timeout alone. A lost webhook response may leave no known job ID; check Azure job history before deciding to start another action.

There is no persistent disposition registry or manual operation ID. A consciously started new action is allowed after an old failure or uncertainty; it performs fresh input/status validation. The app does not resume or replay the old action automatically.

## Import failures and deliberate retries

Scheduled polls skip failed imports, including interrupted or uncertain attempts. A failed identity is not successfully imported and continues to occupy its existing active-window slot.

1. Read the action error and inspect any existing container, Vault files, final artifact or ES finding.
2. Correct the reported problem. If publication acceptance is unknown, inspect the native target before retrying.
3. Use native **Poll Now** to start a fresh attempt for failed identities that still appear as `Requested` in the first 50 candidates. It can also admit new messages within the usual limit; there is no new retry parameter.
4. Verify the completed files, publication and downstream workflow separately.

Previously successful identities remain deduplicated. Retrying a failed identity does not consume an additional slot. A failure in this poll is not retried again within the same poll. Native API calls are not one exactly-once transaction: a fresh ES attempt after a lost receipt can create a duplicate finding.

| Symptom | Next step |
|---|---|
| Azure job cannot be read | Check the asset's App Registration credentials, account coordinates and Automation Job Operator assignment |
| Exchange connection or authorization failure | Read the returned Microsoft error; check the Managed Identity, organization and applicable permissions |
| EML/MIME/size failure | Correct the reported input issue before Poll Now; incomplete mail must not start analysis |
| Import window is full | Inspect tracked Microsoft statuses; analysis completion and import failure do not free slots |
| ES mail/file links fail | Verify the external HTTPS SOAR URL and analyst access from the analyst interface |

See [Email import](ingestion.md) and [Runbook troubleshooting](troubleshooting.md) for details.

## Limits and data handling

- Original EML: up to 24 MiB, with chunked Azure output transport retained.
- MIME: up to 200 parts, 30 nesting levels, 100 attachments and 48 MiB combined decoded attachments.
- Tracked ingestion records: up to 1,000. Active records are not evicted.
- Terminal-entry retention: 1–365 days, default 30. A reappearing source record can be admitted again after retention expires.
- Scheduled polls have a 600-second between-call work budget. Poll Now always refreshes tracked statuses, then gives listing/import its own 600-second budget, even with a paused schedule. This is not a ten-minute total Poll Now timeout; an in-flight operation can run longer than its phase budget. Unattempted candidates can be considered on later polls; failed attempts need Poll Now.
- ES headers/body are a bounded projection; the original Vault EML remains the complete source.

Quarantined mail and attachments may contain sensitive data or malware. Apply platform access controls and retention policies to Azure jobs, containers, Vault files and app state. Back up configuration and state before maintenance; do not clear state to force processing to restart.

## Operational checks and support

Use the [deployment checklist](validation.md) with controlled messages. For support, provide app/runbook and SOAR/ES versions, sanitized action errors and known Azure job IDs. Report unknown outcomes as unknown; do not invent a root cause. Do not include client secrets, webhook tokens or raw message contents.

Developer instructions are in [CONTRIBUTING.md](../CONTRIBUTING.md); release changes are in [GitHub Releases](https://github.com/reisball/ms-quarantine-for-splunk-soar/releases).
