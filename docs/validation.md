# Deployment checklist

Use controlled test messages to verify the configuration before enabling regular intake. Release and Deny change real quarantine state; use only messages approved for those actions. These are deployment checks, not extra runtime prerequisites for each business action.

The current source retains App/Runbook 3.7.4 labels. Local tests do not establish a newly shipped release, a customer installation or production acceptance. Select a unique release version before package handover, and record which source revision was actually tested.

## Before the first import

- Publish and confirm the matching runbook in Azure first, install the matching app second, then activate the compatible playbook. Verify package checksums.
- Use native SOAR execution. Automation Broker is unsupported; SOAR Cloud compatibility has not been verified.
- Verify Azure job access for the App Registration and Exchange permissions for the Automation Account Managed Identity separately.
- Configure one ingesting asset per tenant and set a small active-message limit. Intake is Requested-only; no source-mode setting is needed.
- For ES, register the five [additional fields](ingestion.md#enterprise-security-setup), set a security domain and verify the external HTTPS SOAR URL.
- Configure the intended analysis playbook's analyzer assets, approver, notification recipient, portal links and routing label. Enable only the intended automation. The existing [native consumer mappings](ingestion.md#updating-an-existing-playbook-consumer) are unchanged; this source implementation does not modify customer playbooks.

## Check import and publication

| Check | Expected result |
|---|---|
| Test connectivity | Azure job/output access and the Microsoft `Requested` read succeed |
| Poll Now with one `Requested` message | Original EML, attachments and selected metadata are complete before publication |
| Combined SOAR layout | Exactly one app email artifact is saved last; its native automation flag starts the configured workflow |
| Separate layout or ES | Existing layout, links and native analysis/automation settings remain effective |
| `NotReleased` source message | No new import or publication |
| Legacy intake state | Scope and published references survive; older unconfirmed attempts do not automatically replay |
| Original and attachment downloads | Content matches the test message and is accessible to the analyst; large EML still uses chunked transport |
| Scheduled ingestion | The native schedule admits new eligible messages but skips failed identities |
| Repeated/concurrent intake | The same retained successful identity is not imported again; incomplete input does not start automation |
| Active-message limit | Failed and successfully published unresolved messages share the ceiling; retrying a counted failure uses no additional slot |
| Analysis without disposition | Analysis completion alone does not release a Microsoft-status-controlled slot |
| Interrupted import or restart | Successful outcomes remain deduplicated; incomplete attempts are retained without automatic replay |
| Deliberate Poll Now retry | A previously failed identity still in the first 50 `Requested` candidates gets a fresh attempt; failures arising in that poll are not immediately retried |

For a failed import, inspect existing native data and fix the cause before Poll Now. For an uncertain ES response, inspect the target first: the finding may exist, and a fresh attempt can duplicate it. Do not describe these native API calls as an exactly-once transaction or an ES deduplication guarantee.

A successful artifact/finding receipt alone does not prove that downstream analysis completed. Verify the expected workflow separately.

## Check disposition and waiting

| Check | Expected result |
|---|---|
| Approved Release/Deny | One Azure job, the original command semantics and a native result confirming the expected terminal status |
| Slow Azure job | The default 600-second job/output wait and 5-second status interval remain usable; no premature short timeout |
| Delayed Exchange status after command success | Up to seven reads, ten seconds apart, allow status propagation |
| Transient Azure read throttling | Bounded read retries respect Retry-After and the same deadline; no second writing POST |
| Genuine Azure/Exchange failure | Actual error and known job ID are returned; no invented root cause or error-to-success reconstruction |
| Timeout | Unknown outcome is reported; Azure is not cancelled and the write is not automatically replayed |
| Consciously started action after old uncertainty | Fresh validation and execution are allowed without a retained-operation gate |
| Optional manual diagnosis | Identity/runtime inspection and optional RBAC work independently of normal actions |

After a timeout or unclear result, inspect the known Azure job and current Microsoft status before deciding on another action. Never clear app state to force a retry.

Record expected versus observed results, relevant action/job/container/finding IDs and unresolved issues. Clearly distinguish mocked/local checks from native environment execution and untested customer behavior. Keep raw mail and credentials out of shared reports. See [Email import](ingestion.md) and [Runbook troubleshooting](troubleshooting.md).
