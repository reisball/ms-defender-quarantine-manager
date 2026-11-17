# Deployment checklist

Use controlled test messages to verify the configuration before enabling regular intake. Release and Deny change real quarantine state; use only messages approved for those actions.

## Before the first import

- Install App 3.7.4 and deploy companion Runbook 3.4.5 separately. Record the versions and use the release checksums to verify the files.
- Use native SOAR execution. Automation Broker is unsupported. The connector has been piloted successfully on Splunk SOAR Cloud.
- Verify Azure job access for the App Registration and Exchange permissions for the Automation Account Managed Identity separately.
- Configure one ingesting asset per tenant, select the source mode and set a small active-message limit.
- For ES, register the five [additional fields](ingestion.md#enterprise-security-setup), set a security domain and verify the external HTTPS SOAR URL.
- Configure the intended analysis playbook's analyzer assets, approver, notification recipient, portal links and routing label. Enable only the intended automation.

## Check the workflow

| Check | Expected result |
|---|---|
| Test connectivity | Azure job/output access and the selected source read succeed |
| Poll Now with one message | One container contains the original EML, attachments and selected metadata before automation starts |
| Original and attachment downloads | Downloaded content matches the test message and is accessible to the analyst |
| Scheduled ingestion | The native schedule invokes intake without an additional app checkbox |
| Repeated poll | The retained identity is not imported or analyzed a second time |
| Active-message limit | Pending and published unresolved messages share the configured ceiling; Poll Now cannot exceed it |
| Analysis without disposition | Analysis can complete while the Microsoft-status-controlled slot remains occupied |
| Approved Release/Deny | The action confirms the expected Microsoft terminal state; the next poll can refill the freed slot |
| Restart | Tracked identities and partial preparation remain available without duplicate publication |
| ES target, if used | One finding is linked to the correct container; original/attachment links and configured native analysis/automation work |

Test each source mode you intend to use. Do not assume Deny is eligible for a `NotReleased` message in your tenant. A successful import or finding receipt alone does not prove that the analysis workflow completed.

## Recovery checks

In a controlled environment, verify that incomplete preparation does not start analysis. For a blocked message, correct the cause before using `retry_preparation`. For an uncertain publication, verify the existing artifact/finding and workflow before using `confirm_published`.

For a Release/Deny timeout or unclear result, reconcile the original operation before considering another write. Never clear app state to force a retry.

Record the expected and observed result, relevant action/job/container/finding identifiers and any unresolved issue. Keep raw mail and credentials out of shared reports. See [Email import and recovery](ingestion.md) and [Runbook troubleshooting](troubleshooting.md) for the operational details.
