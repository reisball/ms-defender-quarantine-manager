# Operation and recovery

[Documentation index](README.md).

## How email import works

The app prepares one container per message, saves the original EML and attachments in the Vault, adds selected metadata, then publishes the completed message for analysis. Preparation does not trigger automation.

| Setting or behavior | Meaning |
|---|---|
| `release_requested` (default) | Import Microsoft messages with status `Requested` |
| `needs_review` | Import messages with status `NotReleased`, including mail without a recipient release request |
| Active-message limit | Default 10, configurable 1–50; a total ceiling, not an increment per poll |
| Slot release | A confirmed Microsoft `Released` or `Denied` status frees a slot |
| Analysis completed | Does not free a slot while the Microsoft status remains unresolved |
| Discovery | Uses the first 50 matching source candidates; no pagination or chronological ordering guarantee |
| Poll Now count | Can restrict new admissions but cannot exceed the asset's active-message ceiling |

A missing or expired source message can retain a slot until investigated. Check your tenant's Deny eligibility before using it with `NotReleased` messages. An empty import does not prove the entire source backlog is empty.

The advanced `poll_interval_seconds` and `poll_timeout_seconds` settings monitor individual Azure jobs. They do not set the ingestion schedule.

## Actions

| Action | Purpose |
|---|---|
| **test connectivity** | Check Azure job access and read the selected quarantine source |
| **on poll** | Import prepared mail to the configured native target |
| **on es poll** | Import using native ES ingestion settings; requires an ES target |
| **recover quarantine ingestion** | Resume eligible preparation or acknowledge an independently verified publication |
| **inspect release environment** | Inspect one identity and Exchange runtime details; optionally collect RBAC diagnostics |
| **release quarantine message** | Request release to all recipients and confirm the resulting Microsoft status |
| **deny quarantine release** | Deny the release request and confirm the resulting Microsoft status |
| **reconcile quarantine operation** | Read an existing operation's job/output; optionally refresh Microsoft status |

Use the imported message's `quarantineIdentity` for disposition actions. Release/Deny require the selected source status or an already matching terminal status. A successful command return alone is not sufficient: the app checks the resulting `Released` or `Denied` status.

If a disposition has an unknown outcome, use **reconcile quarantine operation** before considering another write. Keep the original operation/job identifiers. Reusing a retained operation ID does not automatically resubmit the write; terminal operation records are bounded to 50 entries.

## Errors and recovery

| Symptom | Next step |
|---|---|
| Azure job cannot be read | Check the asset's App Registration credentials, account coordinates and Automation Job Operator assignment |
| Exchange connection or authorization failure | Check the Automation Account Managed Identity, organization and Exchange permissions |
| Import is `blocked` | Correct the reported EML/MIME/size problem; use `retry_preparation` only for an eligible item |
| Import remains `publishing` | Establish whether the exact final email artifact (Ready artifact in separate layout) or ES finding exists; do not blindly resubmit |
| Import window is full | Inspect tracked Microsoft statuses; completing analysis alone does not free a slot |
| ES mail/file links fail | Verify the external HTTPS SOAR URL and analyst access from the analyst interface |
| Release/Deny outcome is uncertain | Reconcile the original operation and read the current Microsoft status |

**recover quarantine ingestion** requires the exact identity, resolution and an operator note. `retry_preparation` resumes eligible blocked or incomplete preparation on a later poll. `confirm_published` records your independent verification of an existing publication; it does not verify the evidence itself or send another submission. Neither resolution releases a Microsoft-status-controlled slot.

See [Email import and recovery](ingestion.md) and the [runbook troubleshooting guide](troubleshooting.md) for details.

## Limits and data handling

- Original EML: up to 24 MiB.
- MIME: up to 200 parts, 30 nesting levels, 100 attachments and 48 MiB combined decoded attachments.
- Tracked ingestion records: up to 1,000. Active records are not evicted.
- Completed-entry retention: 1–365 days, default 30. A reappearing source record can be admitted again after retention expires.
- Each poll has a 600-second between-call work budget; an in-flight operation can run longer. Deferred work resumes on subsequent polls.
- ES headers/body are a bounded projection; the original Vault EML remains the complete source.

Quarantined mail and attachments may contain sensitive data or malware. Apply platform access controls and retention policies to Azure jobs, containers, Vault files and app state. Back up configuration and state before maintenance; do not clear state to force processing to restart.

## Operational checks and support

Use the [deployment checklist](validation.md) to verify your own connection, ingestion, analysis and disposition paths with controlled messages.

For support, provide app/runbook and SOAR/ES versions, the selection mode, sanitized action errors and Azure job IDs. Do not include client secrets, webhook tokens or raw message contents.

Developer instructions are in [CONTRIBUTING.md](../CONTRIBUTING.md); release changes are in [GitHub Releases](https://github.com/reisball/ms-quarantine-for-splunk-soar/releases).
