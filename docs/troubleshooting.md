# Troubleshooting

[Back to README](../README.md)

Start with the SOAR action result: its status, the Azure/Exchange error text and any `azure_job_id`. Open that job in Azure Automation to see its status and output.

| Symptom | Next step |
|---|---|
| Azure authorization or job-read failure | Check the App Registration credentials, the Automation Account fields and the two [job-reader permissions](installation.md#3-configure-azure-job-access) and their effective assignment at the account |
| Exchange connection or permission error | Check the Managed Identity, the organization and the permission named in the error ([installation](installation.md#2-grant-exchange-permissions)) |
| Missing organization | Set `exchange_organization` in the asset or the `ExchangeOrganization` Automation Variable |
| Cmdlet failure | Read the returned error and job output |
| Command succeeded but status not confirmed | Read the job output and current Microsoft status before starting another action |
| Timeout or no output | The outcome is unknown, so follow [uncertain outcomes](operations.md#timeouts-and-uncertain-outcomes) |
| Webhook response lost, no job ID | Check Azure job history; a job may still have started |
| Import or publication failed | Inspect the container, artifacts or ES finding, fix the cause, then use [Poll Now](ingestion.md#failed-imports-and-poll-now) |
| EML, MIME or size failure | The message exceeds a [limit](ingestion.md#limits) or is malformed; it is not published |
| Active-message limit is full | Check the Microsoft status of tracked messages; only `Released`/`Denied` frees a slot |
| ES mail or file links fail | Check that the external SOAR URL is HTTPS and reachable, and that analysts have access |

The asset's client secret is used only for Azure job reads. Exchange always uses the Automation Account's Managed Identity.

## Inspect release environment

**inspect release environment** reads one quarantine identity's current Microsoft status and the loaded Exchange module details. It never releases or denies.

- Leave `include_rbac` false unless you need to diagnose tenant permissions.
- The result can include `cmdlet_proxy_diagnostics`: static, redacted excerpts of the loaded `Release-QuarantineMessage` definition (max 32,768 characters per command; excerpts max 16,384 characters and 512 lines). This is not a capture of the HTTP request.

Do not add this action as a required playbook step.

## Asking for support

Include app/runbook and SOAR/ES versions, the sanitized error text and known Azure job IDs. If the outcome is unknown, report it as unknown. Never include client secrets, webhook URLs or message content.
