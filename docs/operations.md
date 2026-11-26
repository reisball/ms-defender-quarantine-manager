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

The app acquires a non-blocking lock for the configured Entra tenant UUID and
quarantine identity before submitting one Azure job. It holds the lock through
result validation. A competing action gets `operation_in_progress` and submits no job.

The lock covers assets and worker processes on the same Linux execution host
when they share the same service UID and temporary directory. Configure the same
Entra tenant UUID for all assets serving that tenant. Use one execution location
per tenant for Release/Deny; different hosts, isolated filesystems, runbook
calls made outside this app and other Exchange writers are not covered. Do not
remove the lock directory while dispositions are running. This is not a durable
write registry: after a timeout or a worker exit an Azure job can still run.

The runbook then:

1. reads the message with `Get-QuarantineMessage`. It continues only if the status is `Requested`. If the status already matches the requested result, the action succeeds without a write; any other status stops the action.
2. runs the command once, without retry:
   - Release: `Release-QuarantineMessage -Identity <id> -ReleaseToAll -Confirm:$false -ErrorAction Stop`
   - Deny: `Release-QuarantineMessage -Identity <id> -ReleaseToAll -ActionType Deny -Confirm:$false -ErrorAction Stop`
3. after the command succeeds, reads the status up to seven times, ten seconds apart, until it shows `Released` or `Denied`. A failed command is reported as an error, even if a later read shows the expected status.

A confirmed `Released` or `Denied` status also frees the message's slot in the [active-message limit](ingestion.md#active-message-limit).

## Timeouts and uncertain outcomes

The app waits up to `poll_timeout_seconds` (default 600) for the Azure job and checks its status every `poll_interval_seconds` (default 5). Transient read errors are retried within that deadline, honouring Retry-After. The webhook that starts the job is **never** retried automatically. If the output body is still downloading when the deadline expires, SOAR stops waiting; an in-flight network read may finish in the background and Azure keeps running.

Use `action_result.summary.outcome` in playbooks. All outcomes except
`confirmed` return a SOAR action error and include `action_result.data.*.error_code`.

| Outcome | Meaning |
|---|---|
| `confirmed` | Exchange confirmed the requested terminal status for the exact identity. |
| `not_executed` | The app did not submit a job (for example, a lock conflict or invalid input), or a runbook precondition prevented a write. |
| `failed` | The disposition cmdlet reported an error. This is not proof that no remote effect occurred. |
| `pending` | Exchange reported `PreparingToRelease`; wait for and inspect the current status, do not issue a new disposition. |
| `unknown` | No reliable confirmation, for example a lost webhook response, timeout, ended Azure job without a validated result, or unconfirmed Exchange status. Azure is not cancelled. |

Before starting another action after an ambiguous result:

1. open the reported Azure job ID in Azure Automation and read its output (if no job ID was returned, check the job history);
2. if needed, run **inspect release environment** to read the current Microsoft status.

A new Release or Deny that you start deliberately is a fresh attempt with fresh validation. Nothing is resumed or replayed automatically. Never clear app state to force a retry.
