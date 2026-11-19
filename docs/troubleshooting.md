# Runbook troubleshooting

Deploy the matching companion runbook separately to Azure Automation. The source still carries App/Runbook **3.7.4** labels; the simplification documented here is a source change, not evidence of a new shipped release or customer deployment. Compare the actual source revision and available runbook version/fingerprint when investigating an unexpected response.

## Start with the native result

Read the SOAR ActionResult status and message, including the actual Azure/Exchange error and known `azure_job_id`. Open that job in Azure Automation to inspect its status and output. Preserve the original error text in a sanitized support report; a missing result does not establish a particular root cause.

| Observation | Next step |
|---|---|
| Azure authorization or job-read failure | Check the App Registration's credentials, Automation Account coordinates and job-read role |
| Exchange connection or permission error | Check the Automation Account Managed Identity, organization and the permission named by the actual error |
| Missing organization | Set the asset organization or the `ExchangeOrganization` Automation Variable |
| Cmdlet failure | Inspect the returned native error and job output; do not report success based on a later status read |
| Command succeeded but target status was not confirmed | Inspect job output and current Microsoft status before deciding on a new action |
| Azure timeout or unavailable output | Treat the outcome as unknown; inspect the known job and current status |
| Webhook response lost without a job ID | Inspect Azure job history; absence of an ID is not proof that no job started |
| Import/publication failed | Inspect native container/artifact/finding evidence, fix the cause, then deliberately use Poll Now if appropriate |

A job/output timeout does **not** cancel Azure. The app never automatically retries the writing webhook or resumes the action later. A new user/playbook invocation is a new attempt, not an automatic continuation.

## Normal Release/Deny path

The app submits one webhook job, waits for its output and returns one native ActionResult. It does not require an extra configuration-check job, RBAC inspection or a diagnostic proof matrix.

The runbook performs these steps:

1. Read the exact identity using `Get-QuarantineMessage`. Microsoft must report `Requested`; an already matching terminal status succeeds without a write. Any other state stops.
2. Invoke the selected command once, without retry:

   **Release**

   ```powershell
   Release-QuarantineMessage -Identity <id> -ReleaseToAll -Confirm:$false -ErrorAction Stop
   ```

   **Deny**

   ```powershell
   Release-QuarantineMessage -Identity <id> -ReleaseToAll -ActionType Deny -Confirm:$false -ErrorAction Stop
   ```

   Both retain the original all-recipient semantics. The actual identity uses singular `Identity`.
3. Only after command success, read Exchange up to seven times, ten seconds apart, for the matching `Released` or `Denied` status. The first unchanged status is not an immediate failure. If the command itself fails, return that error; do not reconstruct success from another status read.
4. Disconnect the Exchange session. Diagnostic cleanup information does not replace the action outcome.

The Azure wait defaults to **600 seconds** and status polling to **5 seconds**. The existing whole-second limits remain 600–3600 and 1–60 respectively. Transient status/output **reads** can retry within one deadline, respecting Retry-After. These settings are independent of the native ingestion schedule.

Only exact Microsoft `Released`/`Denied` observations free intake slots, not playbook completion or a failed import. Offline tests verify invocation and waiting behavior, not live Exchange acceptance.

## Separate Azure and Exchange identities

Exchange authentication uses the Automation Account's **Managed Identity**, with the organization from the asset or, if absent, the `ExchangeOrganization` Automation Variable. The asset's App Registration/client secret is only for Azure job reads. It is not an Exchange login.

Normal input validation remains in place, including rejection of unsupported legacy authentication. A module import or Exchange connection failure is a real error. Optional module/connection metadata is diagnostic context, not a mandatory proof gate for business actions.

## Optional manual diagnostics

Use **inspect release environment** with the exact quarantine identity to read its current Microsoft state and inspect the loaded Exchange runtime. It does not call Release/Deny. Leave `include_rbac` false unless tenant permission diagnosis is needed. A partial optional RBAC report is not a prerequisite failure for every normal action.

The action can return `cmdlet_proxy_diagnostics` and `cmdlet_proxy_diagnostics_status`. This includes the loaded ActionType type/enum/ValidateSet and available proxy/helper source excerpts. Source is redacted and bounded: up to 32,768 characters per command, 16,384 excerpt characters and 512 excerpt lines. Missing helpers, compiled commands and truncation are explicit. These are static definitions, not capture of the outgoing HTTP request; a partial report is not proof of a complete transport trace.

Keep diagnostic collection separate from normal operations. Do not execute captured source or add diagnostics as a required playbook step. For a new installation or coordinated update, publish and confirm the matching runbook, install the matching app, then activate its compatible playbook.

## Import diagnosis

A small identity/result record retains successful and failed imports and their native references. Scheduled polling does not retry a failed or interrupted identity. Native **Poll Now** is the deliberate fresh retry path for failed identities still visible in the first 50 `Requested` candidates; successful imports remain deduplicated.

Inspect existing files and final publication before retrying an uncertain attempt. SOAR and ES APIs do not form one exactly-once transaction, and a lost ES receipt does not guarantee that a finding was not created. Never clear app state or change ingesting assets just to force a retry.

See [Email import](ingestion.md) for layout, scope, active-window and retry details, and [Deployment checklist](validation.md) for environment checks.
