# Operation

[Back to README](../README.md)

## Actions

| Action | Purpose |
|---|---|
| **test connectivity** | Check Azure job access and read `Requested` messages |
| **on poll** | Import mail to the configured target ([email import](ingestion.md)) |
| **on es poll** | Import to ES; requires an ES target |
| **release quarantine message** | Release to all recipients and confirm Microsoft status `Released` |
| **deny quarantine release** | Deny the release request and confirm Microsoft status `Denied` |
| **inspect release environment** | Optional diagnostics; see [troubleshooting](troubleshooting.md#inspect-release-environment) |

Pass `container:data.quarantine_identity` from the event as the `identity` parameter for Release and Deny. No diagnostic action is needed first.

## How Release and Deny work

Each action submits one Azure job and waits for its output. The runbook then:

1. reads the message with `Get-QuarantineMessage`. It continues only if the status is `Requested`. If the status already matches the requested result, the action succeeds without a write; any other status stops the action.
2. runs the command once, without retry:
   - Release: `Release-QuarantineMessage -Identity <id> -ReleaseToAll -Confirm:$false -ErrorAction Stop`
   - Deny: `Release-QuarantineMessage -Identity <id> -ReleaseToAll -ActionType Deny -Confirm:$false -ErrorAction Stop`
3. after the command succeeds, reads the status up to seven times, ten seconds apart, until it shows `Released` or `Denied`. A failed command is reported as an error, even if a later read shows the expected status.

A confirmed `Released` or `Denied` status also frees the message's slot in the [active-message limit](ingestion.md#active-message-limit).

## Timeouts and uncertain outcomes

The app waits up to `poll_timeout_seconds` (default 600) for the Azure job and checks its status every `poll_interval_seconds` (default 5). Transient read errors are retried within that deadline, honouring Retry-After. The webhook that starts the job is **never** retried automatically.

A timeout means the outcome is unknown. Azure is not cancelled. Before starting another action:

1. open the reported Azure job ID in Azure Automation and read its output (if no job ID was returned, check the job history);
2. if needed, run **inspect release environment** to read the current Microsoft status.

A new Release or Deny that you start deliberately is a fresh attempt with fresh validation. Nothing is resumed or replayed automatically. Never clear app state to force a retry.
